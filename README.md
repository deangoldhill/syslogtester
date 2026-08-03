# Syslog Command Center

A lightweight, self-contained syslog collector and operational dashboard. It persists received records in SQLite, parses RFC5424/RFC3164 and indexed `key=value` payload fields, and manages TCP/UDP listeners at runtime.

## Deploy

> The dashboard is forwarded on host port **8085** by default and standard syslog UDP maps from host port **514**. Docker port mappings are static: expose any listener added in the UI by adding a matching mapping to `compose.yaml`, then recreate the service.

```bash
cd syslogtester
cp .env.example .env
# Set a unique SYSLOG_ADMIN_PASSWORD (12+ characters).
docker compose up -d --build
```

Open the dashboard through its HTTPS endpoint (for example `https://<dashboard-host>`) and sign in as `SYSLOG_ADMIN_USERNAME` (default `admin`) with the first-run password. If the dashboard is reachable outside a trusted network, put a TLS reverse proxy in front of it and restrict direct access to port 8085 with your firewall. Once that administrator has been stored in the database, use **Administration** in the UI to create additional accounts. The bootstrap password is not consulted after an administrator exists: remove `SYSLOG_ADMIN_PASSWORD` from `.env` after first boot, then recreate the container.

## Administration and MFA

- Every administrator has a username and a password stored with PBKDF2-SHA256, a per-password random salt, and 600,000 iterations. Plaintext passwords are never stored.
- Any signed-in administrator can add further administrator accounts from **Administration**.
- An administrator can enrol their own TOTP MFA in the same screen. The interface shows the base32 secret and asks for a valid six-digit code before MFA becomes active. The `otpauth://` URI returned by the API is compatible with standard authenticator apps.
- Sessions are server-side, randomly generated, HTTP-only, SameSite=Strict cookies with an eight-hour lifetime. Set `SYSLOG_COOKIE_SECURE=true` whenever browsers access the dashboard over HTTPS; leave it `false` only for direct HTTP on a trusted LAN. Login attempts are rate-limited per source IP (eight failures per 15 minutes).
- For access outside a trusted LAN, serve the dashboard over **HTTPS** (for example through a TLS-terminating reverse proxy or a VPN) and set `SYSLOG_COOKIE_SECURE=true`.

## Live telemetry

The command-center dashboard refreshes every five seconds and shows:

- total messages received and the current messages-per-minute rate;
- distinct hosts and source IPs;
- the highest-volume hosts;
- a compact, rolling 60-minute ingest-rate graph.

The authenticated API exposes the same data from `GET /api/dashboard` for other dashboards or alerting integrations.

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

## Indexed search and correlation

The collector recognises RFC5424 metadata—including version, event timestamp, host, app, process ID, and message ID—and extracts `key=value` pairs from the application message into indexed SQLite rows. Existing records are automatically reparsed and indexed on upgrade.

Use the search box for ordinary free-text search or field filters. Filters are combined with **AND** and quoted values preserve spaces:

```text
username:carapad
username:carapad reply:Access-Accept
event:AUDIT action:"Login completed"
app:radiusstack-authlog nasipaddress:192.168.42.118
```

Each extracted field appears as a button; select one to correlate every record sharing that field value—for example activity for a username, calling-station MAC, NAS address, administrator account, or source IP.

## Operational notes

- **Firewall:** allow TCP/8085 and UDP/514 only from trusted networks, plus any additional explicitly-mapped listener ports. Use HTTPS through a reverse proxy for untrusted-network access.
- **Additional listeners:** UI listener creation starts it inside the container. To receive network traffic, add a matching mapping such as `- "5514:5514/tcp"` or `- "5514:5514/udp"` to `compose.yaml`, then run `docker compose up -d --build`.
- **Privileged ports:** the container runs as root only so it can bind standard syslog port 514. It has `no-new-privileges` enabled and uses no third-party Python packages.
- **Protocol framing:** UDP datagrams are stored individually. TCP input is newline-delimited and limited to 64 KiB per buffered frame by default (`MAX_TCP_MESSAGE_BYTES`); clients exceeding it are disconnected. RFC6587 octet-counted framing is not implemented.
- **API:** `GET /healthz` is unauthenticated. Authenticated endpoints include listener management, message search, `GET /api/dashboard`, `GET/POST /api/admins`, and the self-service MFA endpoints.

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
