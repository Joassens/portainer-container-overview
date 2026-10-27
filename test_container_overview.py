"""Unit tests for container_overview: image references, registry digests (fake registry), status rules and the create body of an updated container.
Run: python -m unittest test_container_overview -v"""
import email.message
import io
import json
import os
import sys
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
import container_overview as co  # noqa: E402


class ImageRefTest(unittest.TestCase):
    def test_parse(self):
        cases = {
            "nginx": ("docker.io", "library/nginx", "latest"),
            "nginx:1.25": ("docker.io", "library/nginx", "1.25"),
            "prom/snmp-exporter:v0.29.0": ("docker.io", "prom/snmp-exporter", "v0.29.0"),
            "ghcr.io/gethomepage/homepage:v2.5.0": ("ghcr.io", "gethomepage/homepage", "v2.5.0"),
            "lscr.io/linuxserver/sonarr": ("lscr.io", "linuxserver/sonarr", "latest"),
            "registry.local:5000/a/b:2": ("registry.local:5000", "a/b", "2"),
            "index.docker.io/library/redis:7": ("docker.io", "library/redis", "7"),
        }
        for ref, exp in cases.items():
            p = co.parse_image(ref)
            self.assertEqual((p["registry"], p["repo"], p["tag"]), exp, ref)

    def test_digest_pin_and_ids(self):
        self.assertEqual(co.parse_image("nginx@sha256:abc")["digest"], "sha256:abc")
        self.assertEqual(co.parse_image("nginx:1.2@sha256:abc")["tag"], "1.2")
        self.assertIsNone(co.parse_image("sha256:0123"))
        self.assertIsNone(co.parse_image(""))

    def test_local_digests_only_for_the_same_repository(self):
        rd = ["prom/snmp-exporter@sha256:aaa", "other/x@sha256:bbb", "docker.io/prom/snmp-exporter@sha256:ccc"]
        self.assertEqual(co.local_digests("prom/snmp-exporter:v0.29.0", rd), {"sha256:aaa", "sha256:ccc"})
        self.assertEqual(co.local_digests("nginx", rd), set())

    def test_newer_tag_keeps_the_shape_of_the_tag(self):
        self.assertEqual(co.newer_tag("v0.29.0", ["v0.29.0", "v0.30.0", "v0.30.1", "latest", "v1.0.0-rc1", "0.40.0"]), "v0.30.1")
        self.assertEqual(co.newer_tag("1.2-alpine", ["1.3-alpine", "1.4", "1.1-alpine"]), "1.3-alpine")
        self.assertIsNone(co.newer_tag("latest", ["1.0"]))
        self.assertIsNone(co.newer_tag("2.5", ["2.5", "2.4.9"]))


class FakeResp(io.BytesIO):
    def __init__(self, body=b"", headers=None):
        super().__init__(body)
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code, headers=None):
    msg = email.message.Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError("http://x", code, "err", msg, None)


class RegistryTest(unittest.TestCase):
    def test_anonymous_token_flow(self):
        calls = []

        def opener(req, timeout):
            calls.append((req.get_method(), req.full_url, req.headers.get("Authorization")))
            if "auth.example/token" in req.full_url:
                return FakeResp(json.dumps({"token": "T"}).encode())
            if req.headers.get("Authorization") != "Bearer T":
                raise http_error(401, {"WWW-Authenticate": 'Bearer realm="https://auth.example/token",service="reg",scope="repository:a/b:pull"'})
            return FakeResp(headers={"Docker-Content-Digest": "sha256:remote"})
        reg = co.Registry(opener)
        self.assertEqual(reg.head_digest("example.io", "a/b", "1"), ("sha256:remote", None))
        self.assertEqual([c[0] for c in calls], ["HEAD", "GET", "HEAD"])
        self.assertEqual(reg.head_digest("example.io", "a/b", "1")[0], "sha256:remote")      # the token is reused
        self.assertEqual(sum(1 for c in calls if "auth.example" in c[1]), 1)

    def test_docker_hub_uses_registry_1_host(self):
        seen = []
        reg = co.Registry(lambda req, t: (seen.append(req.full_url), FakeResp(headers={"Docker-Content-Digest": "sha256:x"}))[1])
        reg.head_digest("docker.io", "library/nginx", "latest")
        self.assertTrue(seen[0].startswith("https://registry-1.docker.io/v2/library/nginx/manifests/latest"))

    def test_errors_become_reasons(self):
        for code, word in ((404, "niet gevonden"), (429, "rate limit"), (500, "500"), (403, "niet openbaar")):
            reg = co.Registry(lambda req, t, c=code: (_ for _ in ()).throw(http_error(c)))
            d, why = reg.head_digest("example.io", "a/b", "1")
            self.assertIsNone(d)
            self.assertIn(word, why)
        reg = co.Registry(lambda req, t: (_ for _ in ()).throw(OSError("boom")))
        self.assertIn("niet bereikbaar", reg.head_digest("example.io", "a/b", "1")[1])


class FakeRegistry:
    def __init__(self, digest="sha256:new", why=None, tags=()):
        self.digest, self.why, self.tags = digest, why, list(tags)

    def head_digest(self, registry, repo, tag):
        return self.digest, self.why

    def hub_tags(self, repo):
        return self.tags


def row(**kw):
    base = {"host": "host1", "name": "app", "image": "x", "image_ref": "ghcr.io/a/app:latest", "state": "running", "status": "Up", "ports": [], "project": "",
            "id": "c" * 64, "env_id": 5, "image_id": "sha256:i", "network_mode": "bridge"}
    base.update(kw)
    return base


class FakeSource:
    def __init__(self, rows):
        self.rows = rows

    def refresh(self, force=False):
        return {"hosts": [], "containers": self.rows, "error": None}


class StatusTest(unittest.TestCase):
    def check(self, c, repo_digests, registry=None, version=None, **kw):
        u = co.Updater(FakeSource([c]), registry or FakeRegistry(), **kw)
        u.portainer_version = version
        return u._check_one(c, repo_digests, {})

    def test_current_and_outdated(self):
        c = row()
        self.assertEqual(self.check(c, ["ghcr.io/a/app@sha256:new"])["state"], "current")
        self.assertEqual(self.check(c, ["ghcr.io/a/app@sha256:old"])["state"], "outdated")

    def test_unknown_pinned_managed_excluded(self):
        self.assertEqual(self.check(row(), [])["state"], "unknown")                                   # no RepoDigests: built locally
        self.assertEqual(self.check(row(), ["ghcr.io/a/app@sha256:o"], FakeRegistry(None, "geen toegang"))["state"], "unknown")
        self.assertEqual(self.check(row(image_ref="ghcr.io/a/app@sha256:p"), ["x"])["state"], "pinned")
        self.assertEqual(self.check(row(host="nas"), [], managed_hosts=("nas",))["state"], "managed")
        self.assertEqual(self.check(row(project="ix-immich"), [])["state"], "managed")
        self.assertEqual(self.check(row(name="portainer", image_ref="portainer/portainer-ce:lts"), [])["state"], "excluded")
        self.assertEqual(self.check(row(name="portainer_agent", image_ref="portainer/agent:2.22.0"), [])["state"], "excluded")

    def test_portainer_version_hints(self):
        v = {"ServerVersion": "2.45.2", "LatestVersion": "2.45.3", "UpdateAvailable": True}
        server = self.check(row(name="portainer", image_ref="portainer/portainer-ce:lts"), [], version=v)
        self.assertEqual(server["newer"], "2.45.3")
        agent = self.check(row(name="portainer_agent", image_ref="portainer/agent:2.22.0"), [], version=v)
        self.assertEqual(agent["newer"], "2.45.2")
        same = self.check(row(name="portainer_agent", image_ref="portainer/agent:2.45.2"), [], version=v)
        self.assertNotIn("newer", same)

    def test_version_hint_for_docker_hub_images(self):
        c = row(image_ref="prom/snmp-exporter:v0.29.0")
        st = self.check(c, ["prom/snmp-exporter@sha256:new"], FakeRegistry(tags=["v0.29.0", "v0.31.0"]))
        self.assertEqual((st["state"], st["newer"]), ("current", "v0.31.0"))

    def test_databases_are_flagged_so_they_stay_out_of_update_all(self):
        for image in ("postgres:18.6-trixie", "ghcr.io/immich-app/postgres:18-vectorchord", "redis:7", "mariadb", "valkey/valkey:9"):
            self.assertTrue(co.DATABASE.search(image), image)
        for image in ("ghcr.io/mealie-recipes/mealie:v3.28.0", "grafana/grafana", "lscr.io/linuxserver/piper:latest", "erikdevries/spotweb"):
            self.assertFalse(co.DATABASE.search(image), image)
        u = co.Updater(FakeSource([row(name="db", image="postgres:18")]), FakeRegistry(), enable_updates=True)
        u.status = {"host1|db": {"state": "outdated", "detail": "x"}}
        item = u.report()["items"]["host1|db"]
        self.assertTrue(item["can_update"] and item["sensitive"])

    def test_report_marks_updatable_only_when_enabled_running_and_not_shared(self):
        a, b = row(name="a"), row(name="b", id="d" * 64, network_mode="container:a")
        u = co.Updater(FakeSource([a, b]), FakeRegistry(), enable_updates=True)
        u.status = {"host1|a": {"state": "outdated", "detail": "x"}, "host1|b": {"state": "outdated", "detail": "x"}}
        items = u.report()["items"]
        self.assertFalse(items["host1|a"]["can_update"], "b shares the network of a")
        self.assertTrue(items["host1|b"]["can_update"])
        self.assertFalse(co.Updater(FakeSource([a]), FakeRegistry(), enable_updates=False).report()["items"]["host1|a"]["can_update"])
        stopped = row(name="s", state="exited")
        u2 = co.Updater(FakeSource([stopped]), FakeRegistry(), enable_updates=True)
        u2.status = {"host1|s": {"state": "outdated", "detail": "x"}}
        self.assertFalse(u2.report()["items"]["host1|s"]["can_update"])

    def test_no_new_update_starts_while_the_service_is_stopping(self):
        u = co.Updater(FakeSource([row()]), FakeRegistry(), enable_updates=True)
        u.status = {"host1|app": {"state": "outdated", "detail": "x"}}
        u.stopping = True
        with self.assertRaises(RuntimeError):
            u.start_update([{"host": "host1", "name": "app"}])

    def test_start_update_refuses_what_cannot_be_updated(self):
        u = co.Updater(FakeSource([row()]), FakeRegistry(), enable_updates=True)
        u.status = {"host1|app": {"state": "current", "detail": "actueel"}}
        with self.assertRaises(ValueError):
            u.start_update([{"host": "host1", "name": "app"}])
        with self.assertRaises(ValueError):
            u.start_update([{"host": "host1", "name": "nope"}])
        with self.assertRaises(ValueError):
            u.start_update([])


class CreateBodyTest(unittest.TestCase):
    def inspect(self, **over):
        old = {"Id": "abcdef123456" + "0" * 52,
               "Config": {"Hostname": "abcdef123456", "Image": "ghcr.io/a/app:latest", "Env": ["PATH=/bin", "NODE_VERSION=20", "MY=1"],
                          "Cmd": ["node", "app.js"], "Entrypoint": None, "WorkingDir": "/app", "User": "", "Healthcheck": {"Test": ["CMD", "true"]},
                          "Labels": {"org.opencontainers.image.version": "1.0", "com.docker.compose.project": "stack", "mine": "yes"}},
               "HostConfig": {"NetworkMode": "net1", "Binds": ["/srv/data:/data"], "RestartPolicy": {"Name": "unless-stopped"}},
               "NetworkSettings": {"Networks": {"net1": {"Aliases": ["abcdef123456", "app"], "IPAMConfig": None, "Links": None},
                                                "net2": {"Aliases": ["app2"], "IPAMConfig": {"IPv4Address": "10.0.0.5"}, "Links": None}}},
               "Mounts": [{"Type": "bind", "Source": "/srv/data", "Destination": "/data", "RW": True},
                          {"Type": "volume", "Name": "f" * 64, "Destination": "/cache", "RW": True},
                          {"Type": "volume", "Name": "named_vol", "Destination": "/named", "RW": True}]}
        old = json.loads(json.dumps(old))
        for k, v in over.items():
            old[k] = v
        return old

    IMAGE = {"Config": {"Env": ["PATH=/bin", "NODE_VERSION=20"], "Cmd": ["node", "app.js"], "WorkingDir": "/app", "User": "", "Healthcheck": {"Test": ["CMD", "true"]},
                        "Labels": {"org.opencontainers.image.version": "1.0"}}}

    def test_image_defaults_are_not_copied_but_own_settings_are(self):
        body, extra = co.Updater.build_create_body(self.inspect(), self.IMAGE)
        self.assertEqual(body["Env"], ["MY=1"])
        for k in ("Cmd", "WorkingDir", "Healthcheck"):
            self.assertNotIn(k, body)
        self.assertEqual(body["Labels"], {"com.docker.compose.project": "stack", "mine": "yes"})
        self.assertNotIn("Hostname", body)
        self.assertEqual(body["HostConfig"]["RestartPolicy"], {"Name": "unless-stopped"})

    def test_a_changed_cmd_is_kept(self):
        old = self.inspect()
        old["Config"]["Cmd"] = ["node", "other.js"]
        body, _ = co.Updater.build_create_body(old, self.IMAGE)
        self.assertEqual(body["Cmd"], ["node", "other.js"])

    def test_anonymous_volume_is_mounted_by_name_and_named_ones_are_not_duplicated(self):
        body, _ = co.Updater.build_create_body(self.inspect(), self.IMAGE)
        self.assertIn("f" * 64 + ":/cache", body["HostConfig"]["Binds"])
        self.assertIn("/srv/data:/data", body["HostConfig"]["Binds"])
        self.assertEqual(len([b for b in body["HostConfig"]["Binds"] if b.endswith(":/data")]), 1)

    def test_networks_first_in_create_rest_connected_later(self):
        body, extra = co.Updater.build_create_body(self.inspect(), self.IMAGE)
        self.assertEqual(list(body["NetworkingConfig"]["EndpointsConfig"]), ["net1"])
        self.assertEqual(body["NetworkingConfig"]["EndpointsConfig"]["net1"]["Aliases"], ["app"], "the old container id alias is dropped")
        self.assertEqual(extra["net2"]["IPAMConfig"], {"IPv4Address": "10.0.0.5"})

    def test_host_network_gets_no_networking_config(self):
        old = self.inspect()
        old["HostConfig"]["NetworkMode"] = "host"
        old["NetworkSettings"]["Networks"] = {"host": {}}
        body, extra = co.Updater.build_create_body(old, self.IMAGE)
        self.assertNotIn("NetworkingConfig", body)
        self.assertEqual(extra, {})


class HandlerTest(unittest.TestCase):
    def setUp(self):
        import threading
        from http.server import ThreadingHTTPServer
        src = FakeSource([row()])
        self.upd = co.Updater(src, FakeRegistry(), enable_updates=True, pin="s3cret")
        self.upd.status = {"host1|app": {"state": "current", "detail": "actueel"}}
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), co.make_handler(src, self.upd))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def call(self, method, path, body=None, headers=None):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_get_endpoints_are_open(self):
        self.assertEqual(self.call("GET", "/api/updates")[1]["pin_required"], True)
        self.assertEqual(self.call("GET", "/api/summary")[0], 200)

    def test_post_needs_the_header(self):
        self.assertEqual(self.call("POST", "/api/update", {"targets": []})[0], 403)
        self.assertEqual(self.call("POST", "/api/check", {})[0], 403)

    def test_update_needs_the_pin_but_check_does_not(self):
        h = {"X-Requested-With": "container-overview"}
        self.assertEqual(self.call("POST", "/api/check", {}, h)[0], 202)
        code, j = self.call("POST", "/api/update", {"targets": [{"host": "host1", "name": "app"}]}, h)
        self.assertEqual((code, j.get("pin_required")), (403, True))
        code, j = self.call("POST", "/api/update", {"targets": [{"host": "host1", "name": "app"}]}, dict(h, **{"X-Update-Pin": "wrong"}))
        self.assertEqual(code, 403)
        code, j = self.call("POST", "/api/update", {"targets": [{"host": "host1", "name": "app"}]}, dict(h, **{"X-Update-Pin": "s3cret"}))
        self.assertEqual(code, 400, "the pin is right, the container is simply not outdated")
        self.assertIn("niet bij te werken", j["error"])

    def test_updates_can_be_switched_off(self):
        self.upd.enable = False
        h = {"X-Requested-With": "container-overview", "X-Update-Pin": "s3cret"}
        self.assertEqual(self.call("POST", "/api/update", {"targets": []}, h)[0], 403)


@unittest.skipUnless(os.name == "posix", "SIGTERM semantics of the real process are tested on POSIX only")
class GracefulStopTest(unittest.TestCase):
    def test_sigterm_stops_an_idle_service_quickly(self):
        import signal
        import socket
        import subprocess
        import time
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        token = os.path.join(os.path.dirname(os.path.abspath(__file__)), "no_such_token")
        p = subprocess.Popen([sys.executable, co.__file__, "--bind", "127.0.0.1", "--port", str(port), "--portainer", "https://127.0.0.1:1", "--token-file", token],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/api/job", timeout=1)
                    break
                except OSError:
                    time.sleep(0.1)
            p.send_signal(signal.SIGTERM)
            self.assertEqual(p.wait(timeout=10), 0)
        finally:
            if p.poll() is None:
                p.kill()


if __name__ == "__main__":
    unittest.main()
