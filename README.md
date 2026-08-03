# Syslog Web UI

A lightweight, self-contained syslog collector with a web dashboard. It stores all received records in a persistent SQLite database and lets an authenticated administrator add/remove **TCP and UDP listeners** at runtime.

## Deploy

> The dashboard is forwarded to host port **8085** by default and standard syslog UDP is forwarded from host port **514** to the container. Docker port mappings are static: to expose any additional listener added in the UI, add its TCP/UDP mapping to `compose.yaml` and run `docker compose up -d --build` again.

```bash
cd syslogtester
cp .env.example .env
# Edit .env and replace SYSLOG_UI_TOKEN with: openssl rand -hex 32
docker compose up -d --build
```

Open `http://<docker-host>:8085`, sign in with `SYSLOG_UI_TOKEN`, then add a **UDP listener on port 514**. Docker already forwards host UDP/514 to the container. The dashboard is on `WEB_PORT` (8085 by default).

## Send a test message

After adding the UDP port `514` listener in the UI:

```bash
logger -n <docker-host> -P 514 -d -t demo "hello from syslog"
```

After adding TCP port `5514`:

```bash
printf '<13>Aug  3 12:00:00 testhost demo: hello over TCP\n' | nc <docker-host> 5514
```

Messages persist in `./data/syslog.db`. Back up that file only while the container is stopped, or use SQLite's `.backup` command for a consistent live backup.

## Operational notes

- **Firewall:** allow TCP/8085 and UDP/514 (plus only the additional ports you explicitly add to `compose.yaml`). The application binds listeners to `0.0.0.0` inside the container.
- **Additional listeners:** Adding a listener in the UI starts it inside the container. For traffic to reach it from the network, add a matching mapping under `ports:` in `compose.yaml`—for example `- "5514:5514/tcp"` or `- "5514:5514/udp"`—then recreate with `docker compose up -d --build`.
- **Privileged ports:** the container runs as root only to allow standard syslog port 514. It has `no-new-privileges` enabled and uses no third-party Python packages.
- **Authentication:** set a long random `SYSLOG_UI_TOKEN`; the UI/API is inaccessible without it. Put the dashboard behind a reverse proxy/VPN if it is reachable from untrusted networks.
- **Protocol framing:** UDP datagrams are stored individually. TCP input is newline-delimited, which is the common simple syslog TCP framing; RFC6587 octet-counted framing is not implemented.
- **API:** `GET /healthz` is unauthenticated for health checks. Authenticated endpoints are `GET/POST /api/listeners`, `DELETE /api/listeners/<id>`, and `GET /api/messages?q=&limit=`.

## Lifecycle

```bash
# Logs and status
docker compose logs -f
docker compose ps

# Stop without deleting stored records
docker compose down

# Upgrade after replacing these files
docker compose up -d --build
```
