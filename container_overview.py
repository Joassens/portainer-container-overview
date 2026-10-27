#!/usr/bin/env python3
"""container-overview: one page with ALL containers of ALL Portainer environments (Portainer CE cannot show that in one view),
with the update status of every image and (optionally) a button that updates a container.

Portainer is only used as a proxy to the Docker API of each environment (GET /api/endpoints, .../docker/...).
  /                 the page (search + host filter, update status, refreshes itself)
  /api/containers   JSON list
  /api/summary      JSON counts per host (used by the Homepage tiles)
  /api/updates      update status per container (digest of the image in the registry against the local one)
  /api/job          the running or last update job
  POST /api/check   check all images now          (needs the header X-Requested-With: container-overview)
  POST /api/update  {"targets":[{"host","name"}]}  (same header; only with --enable-updates)
The Portainer access token is read from a file (never served).

Update status: the digest of <repo>:<tag> in the registry (anonymous pull token) is compared with the RepoDigests of the local image.
That is what Watchtower and diun do: it finds a rebuilt tag (latest, 1.2) but not a newer version number, so for Docker Hub images with a version tag
the newest version tag is shown as a hint.

Update: pull the image, stop the container, create a new one from its inspect data (image defaults are not copied, anonymous volumes and extra networks
are kept), start it, wait until it runs (and is healthy), remove the old one. On any failure the old container is renamed back and started again."""
import argparse
import concurrent.futures
import hmac
import json
import os
import re
import signal
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE            # Portainer uses a self-signed certificate on the LAN
CACHE_S = 10
CHECK_EVERY_S = 6 * 3600
HEADER = ("X-Requested-With", "container-overview")
DEFAULT_PROTECT = r"^(portainer|portainer[_-]agent|agent)$"       # stopping these would cut the connection this page works through
DATABASE = re.compile(r"(^|/)(postgres|postgresql|pgvecto|mariadb|mysql|mongo|redis|valkey|influxdb|timescaledb)([:/@_-]|$)", re.I)   # never part of "update all"


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------------------------------------------- image references

def parse_image(ref):
    """'ghcr.io/a/b:1.2@sha256:..' -> {registry, repo, tag, digest}; None for 'sha256:..' ids and empty references."""
    if not ref or ref.startswith("sha256:"):
        return None
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    first, _, rest = ref.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = "docker.io", ref
    tag = "latest"
    name, sep, t = path.rpartition(":")
    if sep and "/" not in t:
        path, tag = name, t
    if registry in ("docker.io", "index.docker.io") and "/" not in path:
        path = "library/" + path
    if registry == "index.docker.io":
        registry = "docker.io"
    return {"registry": registry, "repo": path, "tag": tag, "digest": digest}


def repo_key(ref):
    p = parse_image(ref)
    return (p["registry"], p["repo"]) if p else None


def local_digests(image_ref, repo_digests):
    """The digests of repo_digests ('name@sha256:..') that belong to the repository of image_ref."""
    key = repo_key(image_ref)
    return {d.split("@", 1)[1] for d in repo_digests or [] if "@" in d and repo_key(d.split("@", 1)[0]) == key}


VERSION = re.compile(r"^(v?)(\d+(?:\.\d+){1,3})(-[A-Za-z0-9.]+)?$")


def _vt(tag):
    """'v1.2.3-alpine' -> (1, 2, 3)"""
    return tuple(int(x) for x in VERSION.match(tag).group(2).split("."))


def newer_tag(current, tags):
    """The highest version tag of the same shape (same 'v' prefix and suffix) that is above the current one, or None."""
    m = VERSION.match(current or "")
    if not m:
        return None
    prefix, suffix = m.group(1), m.group(3) or ""
    cur = tuple(int(x) for x in m.group(2).split("."))
    best = None
    for t in tags:
        mt = VERSION.match(t)
        if not mt or mt.group(1) != prefix or (mt.group(3) or "") != suffix:
            continue
        v = tuple(int(x) for x in mt.group(2).split("."))
        n = max(len(v), len(cur))
        if v + (0,) * (n - len(v)) > cur + (0,) * (n - len(cur)) and (best is None or v > best[0]):
            best = (v, t)
    return best[1] if best else None


# ---------------------------------------------------------------------------------------------------------------------- registries

class Registry:
    ACCEPT = ("application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, "
              "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")

    def __init__(self, opener=None):
        self.opener = opener or (lambda req, timeout: urllib.request.urlopen(req, timeout=timeout))
        self.tokens = {}
        self.lock = threading.Lock()

    def _token(self, challenge, repo):
        m = re.match(r'\s*Bearer\s+(.*)', challenge or "", re.I)
        if not m:
            return None
        params = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
        if "realm" not in params:
            return None
        q = {"service": params.get("service", ""), "scope": params.get("scope") or f"repository:{repo}:pull"}
        url = params["realm"] + "?" + urllib.parse.urlencode(q)
        with self.opener(urllib.request.Request(url), 20) as r:
            j = json.load(r)
        return j.get("token") or j.get("access_token")

    def head_digest(self, registry, repo, tag):
        """(digest, None) or (None, reason)."""
        host = "registry-1.docker.io" if registry == "docker.io" else registry
        url = f"https://{host}/v2/{repo}/manifests/{urllib.parse.quote(tag)}"
        for attempt in range(3):
            headers = {"Accept": self.ACCEPT}
            with self.lock:
                tok = self.tokens.get((host, repo))
            if tok:
                headers["Authorization"] = "Bearer " + tok
            try:
                with self.opener(urllib.request.Request(url, headers=headers, method="HEAD"), 20) as r:
                    d = r.headers.get("Docker-Content-Digest")
                    return (d, None) if d else (None, "het register geeft geen digest")
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt < 2:
                    try:
                        tok = self._token(e.headers.get("WWW-Authenticate"), repo)
                    except Exception:                                        # noqa: BLE001
                        tok = None
                    if tok:
                        with self.lock:
                            self.tokens[(host, repo)] = tok
                        continue
                    return None, "niet openbaar bij het register (lokaal gebouwd of privé)"
                if e.code in (401, 403):
                    return None, "niet openbaar bij het register (lokaal gebouwd of privé)"
                if e.code == 404:
                    return None, "tag niet gevonden in een openbaar register (lokaal gebouwd of privé)"
                if e.code == 429:
                    return None, "rate limit van het register"
                return None, f"register antwoordde {e.code}"
            except Exception as exc:                                         # noqa: BLE001
                return None, "register niet bereikbaar: " + str(exc)[:60]
        return None, "geen toegang"

    def hub_tags(self, repo):
        """Most recently pushed tags of a Docker Hub repository (for the 'newer version' hint)."""
        url = f"https://hub.docker.com/v2/repositories/{repo}/tags?page_size=100&ordering=last_updated"
        try:
            with self.opener(urllib.request.Request(url), 20) as r:
                return [t["name"] for t in json.load(r).get("results", [])]
        except Exception:                                                    # noqa: BLE001
            return []


# ------------------------------------------------------------------------------------------------------------------------ portainer

class Source:
    def __init__(self, base, token_file):
        self.base, self.token_file = base.rstrip("/"), token_file
        self.lock = threading.Lock()
        self.at, self.data = 0.0, {"hosts": [], "containers": [], "error": None}

    def request(self, method, path, body=None, timeout=15, raw=False):
        token = open(self.token_file).read().strip()
        headers = {"X-API-Key": token}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            text = r.read().decode("utf-8", "replace")
        if raw:
            return text
        return json.loads(text) if text.strip() else None

    def _get(self, path, timeout=15):
        return self.request("GET", path, timeout=timeout)

    def docker(self, env_id, method, path, body=None, timeout=120, raw=False):
        return self.request(method, f"/api/endpoints/{env_id}/docker{path}", body, timeout, raw)

    def _env(self, ep):
        host = {"id": ep["Id"], "name": ep["Name"], "reachable": False}
        rows = []
        try:
            for c in self._get(f"/api/endpoints/{ep['Id']}/docker/containers/json?all=1"):
                ports = sorted({f"{p['PublicPort']}" for p in c.get("Ports", []) if p.get("PublicPort")}, key=int)
                rows.append({"host": ep["Name"], "name": c["Names"][0].lstrip("/"), "image": c["Image"].split("@")[0], "state": c["State"], "status": c["Status"], "ports": ports,
                             "project": c.get("Labels", {}).get("com.docker.compose.project", ""),
                             "id": c["Id"], "env_id": ep["Id"], "image_ref": c["Image"], "image_id": c.get("ImageID", ""),
                             "network_mode": (c.get("HostConfig") or {}).get("NetworkMode", "")})
            host["reachable"] = True
        except Exception as exc:                                         # noqa: BLE001
            host["error"] = str(exc)[:120]
        return host, rows

    def refresh(self, force=False):
        with self.lock:
            if not force and time.time() - self.at < CACHE_S:
                return self.data
            try:
                eps = self._get("/api/endpoints")
                with concurrent.futures.ThreadPoolExecutor(6) as ex:
                    results = list(ex.map(self._env, eps))
                hosts = [h for h, _ in results]
                rows = [r for _, rs in results for r in rs]
                self.data = {"hosts": hosts, "containers": rows, "error": None}
            except Exception as exc:                                     # noqa: BLE001
                self.data = dict(self.data, error=str(exc)[:160])
            self.at = time.time()
            return self.data


def problem(c):
    s = c["status"].lower()
    return "unhealthy" in s or c["state"] in ("restarting", "dead") or (c["state"] == "exited" and "exited (0)" not in s)


def summary(d):
    out = {"hosts": {}, "all": {"running": 0, "stopped": 0, "problem": 0, "total": 0}, "error": d["error"]}
    for h in d["hosts"]:
        rows = [c for c in d["containers"] if c["host"] == h["name"]]
        s = {"reachable": h["reachable"], "running": sum(c["state"] == "running" for c in rows), "total": len(rows), "problem": sum(problem(c) for c in rows)}
        s["stopped"] = s["total"] - s["running"]
        out["hosts"][h["name"]] = s
        for k in ("running", "stopped", "problem", "total"):
            out["all"][k] += s[k]
    return out


# ------------------------------------------------------------------------------------------------------------------- update status

class Updater:
    def __init__(self, src, registry, enable_updates=False, protect=DEFAULT_PROTECT, managed_hosts=(), pin=None):
        self.src, self.reg, self.enable, self.pin = src, registry, enable_updates, pin
        self.protect = re.compile(protect, re.I)
        self.managed_hosts = set(managed_hosts)
        self.lock = threading.Lock()
        self.status, self.checked_at, self.checking = {}, 0.0, False
        self.job = None
        self.stopping = False              # set on SIGTERM: no new update starts, a running one is allowed to finish
        self.portainer_version = None

    # -- which containers are out of scope
    def _excluded(self, c):
        if c["project"].startswith("ix-"):                       # the compose project name of TrueNAS SCALE apps
            return {"state": "managed", "detail": "TrueNAS beheert deze app: bijwerken via TrueNAS Apps"}
        if c["host"] in self.managed_hosts:
            return {"state": "managed", "detail": f"de host {c['host']} wordt elders beheerd: bijwerken daar"}
        p = parse_image(c["image_ref"]) or {}
        if self.protect.search(c["name"]) or p.get("repo", "").startswith("portainer/"):
            out = {"state": "excluded", "detail": "Portainer zelf: bijwerken via Portainer, anders valt deze pagina weg"}
            out.update(self._portainer_note(p))
            return out
        return None

    def _portainer_note(self, p):
        """Version hint for Portainer and its agents, taken from the server's own update check (they are never updated from this page)."""
        v = self.portainer_version or {}
        server = v.get("ServerVersion") or ""
        if p.get("repo") in ("portainer/portainer-ce", "portainer/portainer-ee") and v.get("UpdateAvailable"):
            return {"newer": v.get("LatestVersion"), "detail": f"Portainer {server} draait, {v.get('LatestVersion')} is beschikbaar (bijwerken via Portainer zelf)"}
        if p.get("repo") == "portainer/agent" and VERSION.match(p.get("tag", "")) and VERSION.match(server):
            if _vt(p["tag"]) < _vt(server):
                return {"newer": server, "detail": f"agent {p['tag']} is ouder dan de Portainer-server {server} (bijwerken via Portainer)"}
        return {}

    def _check_one(self, c, repo_digests, tags_cache):
        ex = self._excluded(c)
        if ex:
            return ex
        p = parse_image(c["image_ref"])
        if p is None:
            return {"state": "unknown", "detail": "afbeelding zonder naam of tag"}
        if p["digest"]:
            return {"state": "pinned", "detail": "vastgepind op een digest, wordt niet vergeleken"}
        mine = local_digests(c["image_ref"], repo_digests)
        if not mine:
            return {"state": "unknown", "detail": "lokaal gebouwd of niet via een register opgehaald"}
        remote, why = self.reg.head_digest(p["registry"], p["repo"], p["tag"])
        if remote is None:
            return {"state": "unknown", "detail": why}
        st = {"state": "current" if remote in mine else "outdated", "tag": p["tag"],
              "detail": "image is actueel" if remote in mine else f"er staat een nieuwere image onder :{p['tag']} in het register"}
        if p["registry"] == "docker.io" and VERSION.match(p["tag"]):
            tags = tags_cache.get(p["repo"])
            if tags is None:
                tags = tags_cache[p["repo"]] = self.reg.hub_tags(p["repo"])
            n = newer_tag(p["tag"], tags)
            if n:
                st["newer"] = n
        return st

    def check_all(self):
        with self.lock:
            if self.checking:
                return False
            self.checking = True
        try:
            data = self.src.refresh(force=True)
            try:
                self.portainer_version = self.src._get("/api/system/version", timeout=15)
            except Exception:                                              # noqa: BLE001
                self.portainer_version = None
            digest_cache, tags_cache, out = {}, {}, {}

            def local(c):
                key = (c["env_id"], c["image_id"])
                if key not in digest_cache:
                    try:
                        digest_cache[key] = self.src.docker(c["env_id"], "GET", f"/images/{c['image_id']}/json", timeout=20).get("RepoDigests") or []
                    except Exception:                                      # noqa: BLE001
                        digest_cache[key] = []
                return digest_cache[key]

            def one(c):
                try:
                    return c["host"] + "|" + c["name"], dict(self._check_one(c, local(c), tags_cache), checked=time.time())
                except Exception as exc:                                   # noqa: BLE001
                    return c["host"] + "|" + c["name"], {"state": "unknown", "detail": "controle mislukt: " + str(exc)[:80], "checked": time.time()}
            with concurrent.futures.ThreadPoolExecutor(8) as ex:
                out = dict(ex.map(one, data["containers"]))
            with self.lock:
                self.status, self.checked_at = out, time.time()
            log(f"update check: {sum(v['state'] == 'outdated' for v in out.values())} outdated of {len(out)} containers")
        finally:
            with self.lock:
                self.checking = False
        return True

    def _dependents(self, c, rows):
        refs = {f"container:{c['name']}", f"container:{c['id']}", f"container:{c['id'][:12]}"}
        return [x["name"] for x in rows if x["host"] == c["host"] and x["id"] != c["id"] and x["network_mode"] in refs]

    def report(self):
        rows = self.src.refresh()["containers"]
        items = {}
        for c in rows:
            st = dict(self.status.get(c["host"] + "|" + c["name"]) or {"state": "pending", "detail": "nog niet gecontroleerd"})
            st["can_update"] = bool(self.enable and st["state"] == "outdated" and c["state"] == "running" and not self._dependents(c, rows))
            st["sensitive"] = bool(DATABASE.search(c["image"]))
            if st["state"] == "outdated" and c["state"] != "running":
                st["detail"] += " (container draait niet)"
            elif st["state"] == "outdated" and self.enable and not st["can_update"]:
                st["detail"] += f" (andere containers delen het netwerk: {', '.join(self._dependents(c, rows))})"
            items[c["host"] + "|" + c["name"]] = st
        counts = {}
        for v in items.values():
            counts[v["state"]] = counts.get(v["state"], 0) + 1
        return {"enabled": self.enable, "pin_required": bool(self.pin), "checking": self.checking, "checked_at": self.checked_at, "items": items, "counts": counts}

    # -- updating
    def start_update(self, targets):
        if self.stopping:
            raise RuntimeError("de service wordt herstart: probeer het zo opnieuw")
        rows = self.src.refresh()["containers"]
        by = {(c["host"], c["name"]): c for c in rows}
        rep = self.report()["items"]
        items, problems = [], []
        for t in targets:
            key = (t.get("host"), t.get("name"))
            c = by.get(key)
            if not c:
                problems.append(f"{key[1]} ({key[0]}): niet gevonden")
            elif not rep[key[0] + "|" + key[1]]["can_update"]:
                problems.append(f"{key[1]} ({key[0]}): niet bij te werken ({rep[key[0] + '|' + key[1]]['detail']})")
            else:
                items.append({"host": c["host"], "name": c["name"], "state": "wachten", "detail": ""})
        if problems:
            raise ValueError("; ".join(problems))
        if not items:
            raise ValueError("geen containers gekozen")
        with self.lock:
            if self.job and self.job["state"] == "bezig":
                raise RuntimeError("er loopt al een update")
            self.job = {"state": "bezig", "started": time.time(), "finished": None, "items": items}
        threading.Thread(target=self._run_job, args=(self.job,), daemon=True).start()
        return self.job

    def _run_job(self, job):
        for it in job["items"]:
            it["state"] = "bezig"
            try:
                c = next(x for x in self.src.refresh(force=True)["containers"] if x["host"] == it["host"] and x["name"] == it["name"])
                it["detail"] = self.recreate(c, it)
                it["state"] = "klaar"
                with self.lock:
                    self.status[it["host"] + "|" + it["name"]] = {"state": "current", "detail": "zojuist bijgewerkt", "checked": time.time()}
                log(f"updated {it['host']}/{it['name']}: {it['detail']}")
            except Exception as exc:                                       # noqa: BLE001
                it["state"], it["detail"] = "mislukt", str(exc)[:300]
                log(f"update of {it['host']}/{it['name']} failed: {exc}")
        job["state"], job["finished"] = "klaar", time.time()

    def _pull(self, env_id, ref):
        p = parse_image(ref)
        name = ref.rsplit(":", 1)[0] if re.search(r":[^/]+$", ref) else ref
        out = self.src.docker(env_id, "POST", f"/images/create?fromImage={urllib.parse.quote(name, safe='')}&tag={urllib.parse.quote(p['tag'])}", timeout=900, raw=True)
        for line in out.splitlines():
            try:
                j = json.loads(line)
            except ValueError:
                continue
            if j.get("error"):
                raise RuntimeError("image ophalen mislukt: " + j["error"])

    @staticmethod
    def build_create_body(old, old_image):
        """Create body for the new container from the inspect data of the old one; defaults that only come from the old image are dropped."""
        cfg = dict(old["Config"])
        img = old_image.get("Config") or {}
        cfg["Env"] = [e for e in (cfg.get("Env") or []) if e not in (img.get("Env") or [])]
        for k in ("Cmd", "Entrypoint", "WorkingDir", "User", "Healthcheck"):
            if cfg.get(k) == img.get(k):
                cfg.pop(k, None)
        cfg["Labels"] = {k: v for k, v in (cfg.get("Labels") or {}).items() if (img.get("Labels") or {}).get(k) != v}
        if cfg.get("Hostname") == old["Id"][:12]:
            cfg.pop("Hostname", None)
        host = dict(old["HostConfig"])
        binds = list(host.get("Binds") or [])
        have = {b.split(":")[1] for b in binds if ":" in b} | {m.get("Target") for m in host.get("Mounts") or []}
        for m in old.get("Mounts") or []:                      # anonymous volumes would be lost: mount them by name
            if m.get("Type") == "volume" and re.fullmatch(r"[0-9a-f]{64}", m.get("Name", "")) and m["Destination"] not in have:
                binds.append(f"{m['Name']}:{m['Destination']}" + ("" if m.get("RW", True) else ":ro"))
        if binds:
            host["Binds"] = binds
        body = dict(cfg, HostConfig=host)
        mode = host.get("NetworkMode", "")
        nets = old["NetworkSettings"].get("Networks") or {}
        extra = {}
        if mode not in ("host", "none") and not mode.startswith("container:") and nets:
            first = mode if mode in nets else next(iter(nets))
            def ep(n):
                e = nets[n]
                out = {"Aliases": [a for a in (e.get("Aliases") or []) if a != old["Id"][:12]] or None, "Links": e.get("Links") or None,
                       "IPAMConfig": e.get("IPAMConfig") or None}
                return {k: v for k, v in out.items() if v}
            body["NetworkingConfig"] = {"EndpointsConfig": {first: ep(first)}}
            extra = {n: ep(n) for n in nets if n != first}
        return body, extra

    def recreate(self, c, it):
        env, cid, name = c["env_id"], c["id"], c["name"]
        d = self.src.docker
        old = d(env, "GET", f"/containers/{cid}/json")
        ref = old["Config"]["Image"]
        if parse_image(ref) is None or parse_image(ref)["digest"]:
            raise RuntimeError("image is vastgepind of heeft geen naam")
        old_image = d(env, "GET", f"/images/{old['Image']}/json")
        it["detail"] = "image ophalen"
        self._pull(env, ref)
        body, extra = self.build_create_body(old, old_image)
        stamp = time.strftime("%Y%m%d%H%M%S")
        it["detail"] = "container vervangen"
        d(env, "POST", f"/containers/{cid}/stop?t=30", timeout=60)
        d(env, "POST", f"/containers/{cid}/rename?name={urllib.parse.quote(name + '-old-' + stamp)}")
        new_id = None
        try:
            new_id = d(env, "POST", f"/containers/create?name={urllib.parse.quote(name)}", body)["Id"]
            for net, epc in extra.items():
                d(env, "POST", f"/networks/{urllib.parse.quote(net)}/connect", {"Container": new_id, "EndpointConfig": epc})
            d(env, "POST", f"/containers/{new_id}/start", {})                # Portainer's proxy refuses a start without a JSON body
            self._wait_running(env, new_id)
        except Exception as exc:                                           # noqa: BLE001
            try:                                                           # roll back
                if new_id:
                    d(env, "DELETE", f"/containers/{new_id}?force=1")
                d(env, "POST", f"/containers/{cid}/rename?name={urllib.parse.quote(name)}")
                d(env, "POST", f"/containers/{cid}/start", {})
            except Exception as exc2:                                      # noqa: BLE001
                raise RuntimeError(f"nieuwe container werkt niet ({exc}); TERUGZETTEN MISLUKT ({exc2}): oude container heet {name}-old-{stamp}") from exc
            raise RuntimeError(f"nieuwe container werkt niet ({exc}); de oude container draait weer") from exc
        d(env, "DELETE", f"/containers/{cid}?v=0")
        new_image = d(env, "GET", f"/containers/{new_id}/json")["Image"][:19]
        return f"bijgewerkt naar {new_image}"

    def _wait_running(self, env, cid, timeout=90):
        end, settled = time.time() + timeout, 0
        while time.time() < end:
            st = self.src.docker(env, "GET", f"/containers/{cid}/json")["State"]
            health = (st.get("Health") or {}).get("Status")
            if not st.get("Running") or st.get("Restarting"):
                if st.get("Status") in ("exited", "dead") or st.get("Restarting"):
                    raise RuntimeError(f"container stopt meteen (exit code {st.get('ExitCode')})")
            elif health == "unhealthy":
                raise RuntimeError("healthcheck faalt")
            elif health == "healthy" or (health is None and settled >= 4):
                return
            else:
                settled += 1
            time.sleep(2)
        raise RuntimeError("container werd niet gezond binnen " + str(timeout) + " s")


# --------------------------------------------------------------------------------------------------------------------------- page

PAGE = """<!doctype html><html lang="nl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Alle containers</title>
<style>:root{--bg:#f5f6f8;--card:#fff;--ink:#1c2128;--mute:#6b7480;--line:#dfe3e8;--ok:#1d9a5b;--warn:#d9822b;--bad:#c9352f;--chip:#eef1f5;--acc:#2b5cd6}
@media (prefers-color-scheme:dark){:root{--bg:#14171b;--card:#1c2025;--ink:#e6e9ed;--mute:#97a0ab;--line:#2b3138;--ok:#4cc38a;--warn:#f0a35a;--bad:#ff7b72;--chip:#262b32;--acc:#7da2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.4 system-ui,sans-serif}header{padding:16px 16px 8px;display:flex;flex-wrap:wrap;gap:12px;align-items:center}
h1{font-size:18px;margin:0 12px 0 0}input,select,button{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink)}
button{cursor:pointer}button:disabled{opacity:.5;cursor:default}button.go{border-color:var(--acc);color:var(--acc);font-weight:600}
.chips{display:flex;gap:8px;flex-wrap:wrap;padding:0 16px 8px;align-items:center}.chip{background:var(--chip);border-radius:999px;padding:3px 10px;font-size:12px;color:var(--mute)}.chip b{color:var(--ink)}
main{padding:0 16px 24px;overflow-x:auto}table{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line);border-radius:10px}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
th{font-size:12px;color:var(--mute);text-transform:uppercase;letter-spacing:.04em}td.img{color:var(--mute);max-width:280px;overflow:hidden;text-overflow:ellipsis}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;background:var(--mute)}.running .dot{background:var(--ok)}.bad .dot{background:var(--bad)}.stopped .dot{background:var(--warn)}
.u{font-size:12px;padding:2px 8px;border-radius:999px;background:var(--chip);color:var(--mute)}.u.current{color:var(--ok)}.u.outdated{color:var(--warn);font-weight:600}.u.newer{color:var(--acc)}
.err{color:var(--bad);padding:0 16px 8px}.job{margin:0 16px 8px;padding:8px 12px;background:var(--card);border:1px solid var(--line);border-radius:10px}.job .f{color:var(--bad)}.job .k{color:var(--ok)}
@media (max-width:1000px){th:nth-child(6),td:nth-child(6),th:nth-child(7),td:nth-child(7){display:none}}@media (max-width:820px){th:nth-child(3),td:nth-child(3){display:none}}</style></head><body>
<header><h1>Alle containers</h1><input id="q" placeholder="zoeken..." autofocus><select id="h"><option value="">alle hosts</option></select><select id="s"><option value="">alle statussen</option><option value="running">draait</option><option value="stopped">gestopt</option><option value="bad">probleem</option><option value="outdated">update beschikbaar</option></select>
<button id="chk">Controleer op updates</button><button id="all" class="go" hidden></button></header>
<div class="chips" id="chips"></div><div class="err" id="err"></div><div class="job" id="job" hidden></div>
<main><table><thead><tr><th>Host</th><th>Container</th><th>Image</th><th>Status</th><th>Update</th><th>Poorten</th><th>Stack</th></tr></thead><tbody id="rows"></tbody></table></main>
<script>
let data=[],upd={items:{},counts:{},enabled:false,checking:false,checked_at:0},job=null;const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const H={'Content-Type':'application/json','X-Requested-With':'container-overview'};
function cls(c){const s=c.status.toLowerCase();if(s.includes('unhealthy')||c.state==='restarting'||(c.state==='exited'&&!s.includes('exited (0)')))return'bad';return c.state==='running'?'running':'stopped'}
const key=c=>c.host+'|'+c.name;
const LAB={current:'actueel',outdated:'update beschikbaar',pinned:'vastgepind',unknown:'onbekend',managed:'elders beheerd',excluded:'niet hier',pending:'nog niet gecontroleerd'};
function ucell(c){const u=upd.items[key(c)]||{state:'pending',detail:''};const busy=job&&job.state==='bezig';let h=`<span class="u ${u.state}" title="${esc(u.detail)}">${LAB[u.state]||u.state}</span>`;
if(u.newer)h+=` <span class="u newer" title="${esc(u.state==='excluded'?u.detail:'nieuwere versie in het register; pas de tag aan om te upgraden')}">${esc(u.newer)}</span>`;
if(u.can_update)h+=` <button class="go" data-host="${esc(c.host)}" data-name="${esc(c.name)}" ${busy?'disabled':''}>Update</button>`;return h}
function render(){const q=$('q').value.toLowerCase(),h=$('h').value,s=$('s').value;const rows=data.filter(c=>(!h||c.host===h)&&(!s||(s==='outdated'?(upd.items[key(c)]||{}).state==='outdated':cls(c)===s))&&(!q||(c.name+c.image+c.host+c.project).toLowerCase().includes(q)));
rows.sort((a,b)=>(cls(a)==='bad'?0:cls(a)==='stopped'?1:2)-(cls(b)==='bad'?0:cls(b)==='stopped'?1:2)||a.host.localeCompare(b.host)||a.name.localeCompare(b.name));
$('rows').innerHTML=rows.map(c=>`<tr><td>${esc(c.host)}</td><td><span class="${cls(c)}"><span class="dot"></span></span><b>${esc(c.name)}</b></td><td class="img" title="${esc(c.image)}">${esc(c.image)}</td><td>${esc(c.status)}</td><td>${ucell(c)}</td><td>${esc(c.ports.join(', '))}</td><td>${esc(c.project)}</td></tr>`).join('');
const n=Object.entries(upd.items).filter(([k,v])=>v.can_update&&!v.sensitive).length;const b=$('all');b.hidden=!(upd.enabled&&n>0);b.textContent='Alles bijwerken ('+n+')';b.disabled=!!(job&&job.state==='bezig');$('chk').disabled=upd.checking}
function jobbox(){const b=$('job');if(!job){b.hidden=true;return}b.hidden=false;b.innerHTML='<b>Update '+esc(job.state)+'</b><br>'+job.items.map(i=>`<span class="${i.state==='mislukt'?'f':i.state==='klaar'?'k':''}">${esc(i.name)} (${esc(i.host)}): ${esc(i.state)}${i.detail?' - '+esc(i.detail):''}</span>`).join('<br>')}
async function load(){try{const[r,s,u]=await Promise.all([fetch('api/containers').then(x=>x.json()),fetch('api/summary').then(x=>x.json()),fetch('api/updates').then(x=>x.json())]);data=r.containers;upd=u;
const hs=$('h'),cur=hs.value;hs.innerHTML='<option value="">alle hosts</option>'+r.hosts.map(h=>`<option>${esc(h.name)}</option>`).join('');hs.value=cur;
const t=u.checked_at?new Date(u.checked_at*1000).toLocaleTimeString('nl-NL',{hour:'2-digit',minute:'2-digit'}):'nog niet';
$('chips').innerHTML=`<span class="chip"><b>${s.all.running}</b> draaien</span><span class="chip"><b>${s.all.stopped}</b> gestopt</span><span class="chip"><b>${s.all.problem}</b> probleem</span><span class="chip"><b>${u.counts.outdated||0}</b> updates beschikbaar</span><span class="chip">${u.checking?'controle bezig...':'laatst gecontroleerd: '+t}</span>`+Object.entries(s.hosts).map(([n,v])=>`<span class="chip">${esc(n)}: <b>${v.running}</b>/${v.total}${v.reachable?'':' (niet bereikbaar)'}</span>`).join('');
$('err').textContent=r.error||r.hosts.filter(h=>!h.reachable).map(h=>h.name+': '+(h.error||'niet bereikbaar')).join(' | ');render()}catch(e){$('err').textContent='kan de gegevens niet laden: '+e}}
async function loadjob(){try{job=await fetch('api/job').then(x=>x.json());jobbox();render()}catch(e){}}
const ss={get:k=>{try{return sessionStorage.getItem(k)}catch(e){return null}},set:(k,v)=>{try{sessionStorage.setItem(k,v)}catch(e){}},del:k=>{try{sessionStorage.removeItem(k)}catch(e){}}};
async function post(p,b){const hd=Object.assign({},H);if(upd.pin_required&&p==='api/update'){const pin=ss.get('pin')||prompt('Pincode voor bijwerken:');if(!pin)return false;hd['X-Update-Pin']=pin}
const r=await fetch(p,{method:'POST',headers:hd,body:JSON.stringify(b||{})});const j=await r.json().catch(()=>({}));
if(r.status===403&&j.pin_required){ss.del('pin');alert(j.error);return false}
if(r.ok&&hd['X-Update-Pin'])ss.set('pin',hd['X-Update-Pin']);if(!r.ok)alert(j.error||('fout '+r.status));return r.ok}
$('chk').onclick=async()=>{await post('api/check');setTimeout(load,500)};
const bulk=()=>Object.entries(upd.items).filter(([k,v])=>v.can_update&&!v.sensitive).map(([k])=>({host:k.split('|')[0],name:k.split('|').slice(1).join('|')}));
$('all').onclick=async()=>{const t=bulk();const skipped=Object.values(upd.items).filter(v=>v.can_update&&v.sensitive).length;
if(confirm('Deze '+t.length+' containers bijwerken en herstarten?\\n\\n'+t.map(x=>x.name+' ('+x.host+')').join('\\n')+(skipped?'\\n\\n('+skipped+' database(s) doe je apart)':''))&&await post('api/update',{targets:t}))loadjob()};
$('rows').onclick=async e=>{const b=e.target.closest('button[data-name]');if(!b)return;const t={host:b.dataset.host,name:b.dataset.name};const u=upd.items[t.host+'|'+t.name]||{};
if(confirm('Bijwerken: '+t.name+' ('+t.host+')?\\nDe container wordt gestopt en met de nieuwste image opnieuw gestart.'+(u.sensitive?'\\n\\nLet op: dit is een database. Maak eerst een back-up als je data belangrijk is.':''))&&await post('api/update',{targets:[t]}))loadjob()};
['q','h','s'].forEach(i=>$(i).addEventListener('input',render));load();loadjob();setInterval(load,20000);setInterval(()=>{if(job&&job.state==='bezig'){loadjob();load()}},2500);
</script></body></html>""".encode()


def make_handler(src, upd):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body, ctype="application/json", code=200):
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(json.dumps(obj).encode(), code=code)

        def do_GET(self):                                                # noqa: N802
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                self._send(PAGE, "text/html")
            elif path == "/api/containers":
                self._json(src.refresh())
            elif path == "/api/summary":
                self._json(summary(src.refresh()))
            elif path == "/api/updates":
                self._json(upd.report())
            elif path == "/api/job":
                self._json(upd.job)
            elif path == "/api/all":                       # flat, for the Homepage tiles
                self._json(summary(src.refresh())["all"])
            elif path.startswith("/api/host/"):            # flat counts of one host, e.g. /api/host/docker1
                name = urllib.parse.unquote(path[len("/api/host/"):])
                h = summary(src.refresh())["hosts"].get(name)
                if h is None:
                    self.send_error(404)
                else:
                    self._json(dict(h, reachable=int(h["reachable"])))
            else:
                self.send_error(404)

        def do_POST(self):                                               # noqa: N802
            path = self.path.split("?")[0]
            try:
                n = min(int(self.headers.get("Content-Length") or 0), 1 << 20)
            except ValueError:
                n = 0
            raw = self.rfile.read(n) if n else b""                       # always read the body first: answering early makes some clients reset the connection
            if self.headers.get(HEADER[0]) != HEADER[1]:                 # a cross-site form cannot set this header
                return self._json({"error": "header ontbreekt"}, 403)
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                return self._json({"error": "ongeldige JSON"}, 400)
            if path == "/api/check":
                threading.Thread(target=upd.check_all, daemon=True).start()
                return self._json({"started": True}, 202)
            if path == "/api/update":
                if not upd.enable:
                    return self._json({"error": "bijwerken staat uit (start de service met --enable-updates)"}, 403)
                if upd.pin and not hmac.compare_digest(self.headers.get("X-Update-Pin", ""), upd.pin):
                    return self._json({"error": "pincode ontbreekt of is onjuist", "pin_required": True}, 403)
                try:
                    return self._json(upd.start_update(body.get("targets") or []), 202)
                except ValueError as exc:
                    return self._json({"error": str(exc)}, 400)
                except RuntimeError as exc:
                    return self._json({"error": str(exc)}, 409)
            self.send_error(404)
    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--portainer", default=os.environ.get("PORTAINER_URL", "https://localhost:9443"), help="Portainer base URL (env PORTAINER_URL)")
    ap.add_argument("--token-file", default="/opt/container-overview/portainer_token")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9640)
    ap.add_argument("--enable-updates", action="store_true", help="allow the Update buttons (otherwise status only)")
    ap.add_argument("--protect", default=DEFAULT_PROTECT, help="regex of container names that can never be updated from this page")
    ap.add_argument("--update-pin-file", help="file with a PIN that every update request must send (the page asks for it)")
    ap.add_argument("--managed-hosts", default="", help="comma separated Portainer environment names whose containers are managed elsewhere (shown, never updated here)")
    a = ap.parse_args()
    src = Source(a.portainer, a.token_file)
    pin = open(a.update_pin_file).read().strip() if a.update_pin_file else None
    managed = tuple(h.strip() for h in a.managed_hosts.split(",") if h.strip())
    upd = Updater(src, Registry(), a.enable_updates, a.protect, managed_hosts=managed, pin=pin)

    def loop():
        while True:
            try:
                upd.check_all()
            except Exception as exc:                                     # noqa: BLE001
                log(f"update check failed: {exc}")
            time.sleep(CHECK_EVERY_S)
    threading.Thread(target=loop, daemon=True).start()
    srv = ThreadingHTTPServer((a.bind, a.port), make_handler(src, upd))

    def graceful(*_):
        """SIGTERM (a restart): let a running update finish first, otherwise a container is left stopped halfway."""
        def work():
            upd.stopping = True
            end = time.time() + 100
            while upd.job and upd.job["state"] == "bezig" and time.time() < end:
                time.sleep(1)
            srv.shutdown()
        threading.Thread(target=work, daemon=True).start()
    signal.signal(signal.SIGTERM, graceful)
    signal.signal(signal.SIGINT, graceful)
    srv.serve_forever()


if __name__ == "__main__":
    main()
