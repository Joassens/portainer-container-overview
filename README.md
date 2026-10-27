# portainer-container-overview

One page with **all containers of all your Portainer environments**, the **update status** of every image, and an **Update button**.

Portainer CE shows one environment at a time and has no "is there a newer image?" view. This small service (a single Python file, standard library only)
asks Portainer for the containers of every environment, checks the registries for newer images and can recreate a container with the newest image.

> The page and its messages are in Dutch. Translations are welcome as a pull request.

## What it does

- **One table** with host (Portainer environment), container, image, status, ports and compose stack. Search, filter by host or status, refreshes itself.
- **Update status** per container: current, update available, unknown (built locally or private image), pinned (digest), managed elsewhere. It compares the digest of
  `<repo>:<tag>` in the registry (anonymous pull token, `HEAD` on the manifest) with the `RepoDigests` of the local image, the same method as Watchtower and diun.
  So it finds a rebuilt `latest` or `1.2`, not a newer version number; for Docker Hub images with a version tag the newest version tag is shown as a hint.
  Checked every 6 hours and with the "Controleer op updates" button.
- **Update button** (off unless you start the service with `--enable-updates`): pull the image, stop the container, create a new one from its inspect data, start it,
  wait until it runs (and is healthy) and remove the old one. If anything fails the old container is renamed back and started again.
- **Small JSON API** for dashboards such as Homepage (`/api/all`, `/api/host/<name>`, `/api/summary`).
- Notes for Portainer itself and its agents: the version Portainer reports as available, and agents that are older than the server.

## How an update recreates a container

The new container is built from `docker inspect` of the old one, the way Portainer's own "Recreate" does it, with a few safeguards:

- values that only come from the **old image** (environment variables, command, entrypoint, labels, healthcheck, user, working dir) are **not** copied, so the new image's defaults apply;
- **anonymous volumes** are mounted by name in the new container, so their data survives; extra **networks** (with aliases and fixed IPs) are connected before start;
- the old container is removed without its volumes; a failed start puts the old container back.

Not handled: Docker Swarm services, containers that use `network_mode: container:<name>` of the container being updated (refused), and compose files are not re-applied
(the container is recreated on its own, its compose labels are kept).

## Safety

The page has **no login**. Run it on a trusted network, or behind a reverse proxy with authentication.

- All POST requests need the header `X-Requested-With: container-overview` (another website cannot set it).
- `POST /api/update` also needs a **PIN** when you start the service with `--update-pin-file`; the page asks for it once per session. Use it.
- Never updated from this page: Portainer and its agents (stopping them cuts the connection the page works through), containers whose network is shared by another
  container, and anything in `--managed-hosts` or a TrueNAS app (compose project `ix-*`). Databases (postgres, mariadb, mysql, mongo, redis, valkey, influxdb, ...) are left out of
  "update all" and get a backup warning on their own button.
- The Portainer access token is read from a file and never served. Only `GET /api/endpoints` and the Docker API of each environment are used.
  Give the token to a dedicated Portainer user if you want to limit it; updating needs the right to create, stop and remove containers and to pull images.

## Install

1. In Portainer create an access token (*My account > Access tokens*) and save it in a file only the service can read.
2. Choose a PIN and save it in a file (`chmod 600`).
3. Run it (Python 3.11 or newer; tested on 3.11 and 3.13):

```bash
python3 container_overview.py --portainer https://portainer.example:9443 --token-file ./portainer_token \
    --enable-updates --update-pin-file ./update_pin --port 9640
```

Options: `--bind`, `--port`, `--managed-hosts a,b` (environments whose containers are managed elsewhere), `--protect REGEX` (container names that can never be updated, default
Portainer and its agents), `PORTAINER_URL` as an environment variable instead of `--portainer`. Without `--enable-updates` the page is a read-only overview.

A systemd unit:

```ini
[Unit]
Description=container-overview
After=network-online.target

[Service]
Environment=PORTAINER_URL=https://portainer.example:9443
ExecStart=/usr/bin/python3 /opt/container-overview/container_overview.py --token-file /opt/container-overview/portainer_token --enable-updates --update-pin-file /opt/container-overview/update_pin
Restart=always
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

## API

| Path | |
|---|---|
| `GET /` | the page |
| `GET /api/containers`, `/api/summary` | containers, counts per host |
| `GET /api/all`, `/api/host/<name>` | flat counts for dashboard tiles |
| `GET /api/updates` | update status per container (`host|name`), counts, `enabled`, `pin_required` |
| `GET /api/job` | the running or last update job |
| `POST /api/check` | check all images now (header required) |
| `POST /api/update` | `{"targets":[{"host":"..","name":".."}]}` (header and PIN required, one job at a time) |

## Tests

```bash
python -m unittest -v          # unit tests: image references, a fake registry, status rules, the create body, HTTP and PIN
```

`throwaway_update_test.py` is an end-to-end test against a real Docker host (see the header of the file): it runs a throw-away `alpine` container with an old
image, updates it through the service and checks that variables, labels, restart policy and volume data survive, then tests the rollback and cleans up after itself.

A Portainer quirk found this way: its Docker proxy refuses `POST /containers/<id>/start` without a JSON body (`{}` works).

## License

Public domain ([The Unlicense](LICENSE)).
