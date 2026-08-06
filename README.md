# Syslog Command Center

A PostgreSQL-backed syslog collector and searchable dashboard. It parses RFC5424/RFC3164 input, indexes `key=value` fields, and supports runtime UDP/TCP listener management.

## Security and access model

- The web application has **no published host port**. Browser access is exclusively `HTTPS → Traefik → Authelia ForwardAuth → syslog-webui`.
- Compose configures ForwardAuth to copy only the verified `Remote-User` response header. The application grants `/admin` and `/api/admin/*` only when that header exactly equals `SYSLOG_ADMIN_USER` (default `dean`). There are no local accounts, passwords, sessions, or MFA endpoints.
- PostgreSQL is on the private `syslog-internal` network only. It has no published port and persists in the named `syslog-postgres` volume.
- UDP/514 remains published for syslog ingestion. Add any additional static TCP/UDP port mapping deliberately before creating a listener for it; browser access is never mapped directly.

## Configure and deploy

```bash
cd /opt/data/syslogtester
cp .env.example .env
# Set unique PostgreSQL credentials and the actual Traefik/Authelia values.
docker compose config
docker compose up -d --build
```

`docker compose config` must succeed before deployment. The existing Traefik network named by `TRAEFIK_NETWORK` must exist. Do not add an `8085` mapping or a PostgreSQL `5432` mapping.

## PostgreSQL migrations and backup

On startup the application applies ordered SQL files under `migrations/`, recording each filename in `schema_migrations`. The initial migration creates normalized listener/message/field/settings tables, B-tree operational indexes, and a GIN full-text index over raw syslog content and its primary metadata. Schema migrations are transactional.

Back up PostgreSQL with a database-aware backup, for example from a trusted host/container with access to the private database network:

```bash
pg_dump -Fc -U "$POSTGRES_USER" -d "$POSTGRES_DB" > syslog-$(date +%F).dump
```

## Dashboard and Syslog Admin

The dashboard provides live telemetry, message search, and correlation filters such as:

```text
username:carapad reply:Access-Accept
event:AUDIT app:radiusstack-authlog
```

The responsive Dashboard, Investigate, and Admin tabs replace cross-page text links. `/admin` is intentionally dean-only. It exposes read-only database health/storage/message/listener statistics, narrowly scoped listener add/remove controls, and parsing-rule APIs. It also controls retention from 1 to 3650 days; saving retention immediately deletes messages older than that setting. No raw configuration editing or arbitrary command execution is available.

### Parsing rules

Admin can list built-in rules (including the PAN-OS CSV parser) and add durable user-defined rules through `GET`/`POST /api/admin/parsing-rules`. User rules use a deliberately bounded model: a 1–120-character literal **prefix**, comma/pipe/tab delimiter, and 1–32 unique field names matching `[a-z][a-z0-9_.-]{0,63}`. During ingestion, only values up to 1024 characters are indexed. There is no user-supplied code, SQL, or regex evaluation. Rules are stored in PostgreSQL migration `002_parsing_rules.sql`.

## Send a test message

After adding the UDP listener on port 514 through `/admin`:

```bash
logger -n <docker-host> -P 514 -d -t demo "hello from syslog"
```

TCP input is newline-delimited and capped at 64 KiB per buffered frame (`MAX_TCP_MESSAGE_BYTES`).
