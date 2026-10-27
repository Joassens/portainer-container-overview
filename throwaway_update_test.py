"""End-to-end test of the Update button on a throw-away container, in one Portainer environment of your choice.

Needs a running service with updates enabled and WITHOUT a PIN (python container_overview.py --port 9641 --enable-updates ...).
It retags alpine:3.18 as alpine:latest (so the registry's :latest is newer), runs a container from it with an env var, a label, a restart policy and an
anonymous volume, asks the service to update it and checks what was kept; `rollback` checks that a failed update puts the old container back.
It refuses to run when an alpine image already exists on that Docker host, and removes everything it created (`cleanup`).

  PORTAINER_URL=https://portainer:9443 PORTAINER_TOKEN_FILE=~/.portainer_token TEST_ENV_ID=2 python throwaway_update_test.py setup|run|rollback|cleanup
Optional: SERVICE_URL (default http://127.0.0.1:9641)."""
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import container_overview as co

NAME = "zz-update-test"
SVC = os.environ.get("SERVICE_URL", "http://127.0.0.1:9641")
E = int(os.environ["TEST_ENV_ID"])                                     # the Portainer environment id to run the test in
src = co.Source(os.environ.get("PORTAINER_URL", "https://localhost:9443"), os.path.expanduser(os.environ.get("PORTAINER_TOKEN_FILE", "~/.portainer_token")))
HOST = next(e["Name"] for e in src._get("/api/endpoints") if e["Id"] == E)     # the host name the page shows for it
d = src.docker


def svc(path, body=None):
    req = urllib.request.Request(SVC + path, data=json.dumps(body).encode() if body is not None else None, method="POST" if body is not None else "GET",
                                 headers={"X-Requested-With": "container-overview", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def logs(cid):
    raw = d(E, "GET", f"/containers/{cid}/logs?stdout=1&stderr=1", raw=True)
    return raw.encode("latin-1", "replace").decode("utf-8", "replace") if raw else ""


def find():
    return [c for c in d(E, "GET", "/containers/json?all=1") if "/" + NAME in c["Names"]]


def cleanup():
    for c in find():
        print("removing container", c["Names"], c["Id"][:12])
        d(E, "DELETE", f"/containers/{c['Id']}?force=1&v=1")
    for v in d(E, "GET", "/volumes").get("Volumes") or []:
        if (v.get("Labels") or {}).get("zz.test") == "1":
            print("removing volume", v["Name"][:12])
            d(E, "DELETE", f"/volumes/{v['Name']}")
    for tag in ("alpine:latest", "alpine:3.18"):
        try:
            d(E, "DELETE", f"/images/{tag}?force=0")
            print("removed image", tag)
        except Exception as exc:                                           # noqa: BLE001
            print("image", tag, "kept:", str(exc)[:60])


def setup():
    tags = [t for i in d(E, "GET", "/images/json") for t in (i.get("RepoTags") or [])]
    assert not any(t.startswith("alpine:") for t in tags), "alpine already on this host, refusing to touch it: " + str(tags)
    assert not find(), "test container exists"
    print("pull alpine:3.18 ...")
    d(E, "POST", "/images/create?fromImage=alpine&tag=3.18", timeout=300, raw=True)
    d(E, "POST", "/images/alpine:3.18/tag?repo=alpine&tag=latest")
    body = {"Image": "alpine:latest", "Cmd": ["sh", "-c", "echo run >> /data/log; cat /data/log; echo version-check; sleep 3600"], "Env": ["TEST_VAR=abc"],
            "Labels": {"zz.test": "1"}, "Volumes": {"/data": {}}, "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}}}
    cid = d(E, "POST", f"/containers/create?name={NAME}", body)["Id"]
    d(E, "POST", f"/containers/{cid}/start", {})
    time.sleep(3)
    inspect = d(E, "GET", f"/containers/{cid}/json")
    print("created", cid[:12], "image", inspect["Image"][:19], "mounts", [(m["Type"], m["Name"][:12], m["Destination"]) for m in inspect["Mounts"]])
    print("logs:", logs(cid).strip().replace("\n", " | "))


def rollback():
    """A container that works on alpine 3.18 but exits at once on the newer image: the update must fail and put the old container back."""
    for c in find():
        d(E, "DELETE", f"/containers/{c['Id']}?force=1&v=1")
    d(E, "POST", "/images/alpine:3.18/tag?repo=alpine&tag=latest")                 # :latest is the old image again
    script = 'case "$(cat /etc/alpine-release)" in 3.18*) echo old-ok; sleep 3600;; *) echo broken-on-new-image; exit 3;; esac'
    body = {"Image": "alpine:latest", "Cmd": ["sh", "-c", script], "Labels": {"zz.test": "1"}, "HostConfig": {"RestartPolicy": {"Name": "no"}}}
    cid = d(E, "POST", f"/containers/create?name={NAME}", body)["Id"]
    d(E, "POST", f"/containers/{cid}/start", {})
    time.sleep(3)
    old_image = d(E, "GET", f"/containers/{cid}/json")["Image"]
    print("before: running", d(E, "GET", f"/containers/{cid}/json")["State"]["Running"], "| logs:", logs(cid).strip())
    svc("/api/check", {})
    time.sleep(1)
    for _ in range(30):
        if not svc("/api/updates")[1]["checking"]:
            break
        time.sleep(2)
    code, job = svc("/api/update", {"targets": [{"host": HOST, "name": NAME}]})
    print("start update:", code)
    for _ in range(120):
        j = svc("/api/job")[1]
        if j and j["state"] != "bezig":
            break
        time.sleep(3)
    print("job item:", json.dumps(j["items"][0], ensure_ascii=False))
    after = find()
    allnames = [c["Names"] for c in d(E, "GET", "/containers/json?all=1") if NAME in "".join(c["Names"])]
    a_inspect = d(E, "GET", f"/containers/{after[0]['Id']}/json") if after else None
    checks = {
        "update reported as failed": j["items"][0]["state"] == "mislukt",
        "exactly one container with the test name, no -old- or new leftover": len(allnames) == 1 and allnames[0] == ["/" + NAME],
        "it is the ORIGINAL container": bool(after) and after[0]["Id"] == cid,
        "it is running again": bool(a_inspect) and a_inspect["State"]["Running"],
        "on the old image": bool(a_inspect) and a_inspect["Image"] == old_image,
    }
    for k, v in checks.items():
        print(("PASS " if v else "FAIL ") + k)
    print("RESULT:", "ALL PASS" if all(checks.values()) else "SOME FAILED")


def run():
    before = find()[0]
    b_inspect = d(E, "GET", f"/containers/{before['Id']}/json")
    b_vol = [m["Name"] for m in b_inspect["Mounts"] if m["Destination"] == "/data"][0]
    print("before: id", before["Id"][:12], "image", b_inspect["Image"][:19], "volume", b_vol[:12])
    code, _ = svc("/api/check", {})
    time.sleep(1)
    for _ in range(30):
        if not svc("/api/updates")[1]["checking"]:
            break
        time.sleep(2)
    st = svc("/api/updates")[1]["items"].get(HOST + "|" + NAME)
    print("status before update:", st["state"], "| can_update:", st["can_update"], "|", st["detail"])
    assert st["state"] == "outdated" and st["can_update"], "test container not reported as updatable"
    code, job = svc("/api/update", {"targets": [{"host": HOST, "name": NAME}]})
    print("start update:", code, job if code != 202 else "accepted")
    for _ in range(120):
        j = svc("/api/job")[1]
        if j and j["state"] != "bezig":
            break
        time.sleep(3)
    print("job:", json.dumps(j["items"], ensure_ascii=False))
    after = find()
    print("containers named", NAME, "after:", len(after), "| leftovers *-old-*:", [c["Names"] for c in d(E, "GET", "/containers/json?all=1") if "zz-update-test-old" in "".join(c["Names"])])
    a = after[0]
    a_inspect = d(E, "GET", f"/containers/{a['Id']}/json")
    a_vol = [m["Name"] for m in a_inspect["Mounts"] if m["Destination"] == "/data"][0]
    checks = {
        "new container id": a["Id"] != before["Id"],
        "running": a_inspect["State"]["Running"],
        "image changed": a_inspect["Image"] != b_inspect["Image"],
        "env TEST_VAR kept": "TEST_VAR=abc" in a_inspect["Config"]["Env"],
        "label kept": a_inspect["Config"]["Labels"].get("zz.test") == "1",
        "restart policy kept": a_inspect["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped",
        "same anonymous volume": a_vol == b_vol,
        "volume data survived (2 'run' lines)": logs(a["Id"]).count("run") >= 2,
    }
    for k, v in checks.items():
        print(("PASS " if v else "FAIL ") + k)
    print("logs after:", logs(a["Id"]).strip().replace("\n", " | "))
    st2 = svc("/api/updates")[1]["items"].get(HOST + "|" + NAME)
    print("status after update:", st2["state"], "|", st2["detail"])
    print("RESULT:", "ALL PASS" if all(checks.values()) else "SOME FAILED")


if __name__ == "__main__":
    {"setup": setup, "run": run, "rollback": rollback, "cleanup": cleanup}[sys.argv[1] if len(sys.argv) > 1 else "run"]()

