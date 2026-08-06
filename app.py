#!/usr/bin/env python3
"""PostgreSQL-backed syslog collector and Traefik/Authelia-protected dashboard."""
import csv
import html
import json
import os
import re
import shlex
import socket
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://syslog:syslog@postgres:5432/syslog")
WEB_HOST = os.environ.get("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.environ.get("WEB_PORT", "8085"))
MAX_TCP_MESSAGE_BYTES = max(1024, int(os.environ.get("MAX_TCP_MESSAGE_BYTES", "65536")))
ADMIN_USER = os.environ.get("SYSLOG_ADMIN_USER", "dean")
MIGRATIONS_DIR = Path(__file__).with_name("migrations")
workers = {}
workers_lock = threading.Lock()

KV_RE = re.compile(r'''(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)=(?:"(?P<quoted>(?:\\.|[^"\\])*)"|(?P<bare>[^\s]+))''')
FIELD_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
MAX_RULE_NAME_LENGTH = 80
MAX_MATCH_LITERAL_LENGTH = 120
MAX_RULE_FIELDS = 32
MAX_FIELD_VALUE_LENGTH = 1024
DELIMITERS = {"comma": ",", "pipe": "|", "tab": "\t", ",": ",", "|": "|", "\t": "\t"}


@contextmanager
def db():
    """Open one transactional PostgreSQL connection per operation."""
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as con:
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise


def now():
    return datetime.now(timezone.utc)


def load_migration_sql():
    return [path.read_text(encoding="utf-8") for path in sorted(MIGRATIONS_DIR.glob("*.sql"))]


def apply_migrations():
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    with db() as con:
        con.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        done = {row["version"] for row in con.execute("SELECT version FROM schema_migrations")}
        for path in files:
            if path.name in done:
                continue
            con.execute(path.read_text(encoding="utf-8"))
            con.execute("INSERT INTO schema_migrations(version) VALUES (%s)", (path.name,))


def parse_retention_days(value):
    try:
        days = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Retention must be a whole number of days") from exc
    if not 1 <= days <= 3650:
        raise ValueError("Retention must be between 1 and 3650 days")
    return days


def retention_days(con):
    row = con.execute("SELECT setting_value FROM settings WHERE setting_key='retention_days'").fetchone()
    return parse_retention_days(row["setting_value"] if row else "30")


def purge_expired(con):
    days = retention_days(con)
    return con.execute("DELETE FROM messages WHERE received_at < CURRENT_TIMESTAMP - (%s * INTERVAL '1 day')", (days,)).rowcount


def parse_palo_alto_fields(message):
    """Extract stable, high-value fields from PAN-OS CSV Traffic/Threat logs."""
    try:
        values = next(csv.reader(StringIO(message), strict=True))
    except (csv.Error, StopIteration):
        return {}
    offset = 1 if len(values) > 3 and values[0].isdigit() and values[3] in {"TRAFFIC", "THREAT", "CONFIG", "SYSTEM", "GLOBALPROTECT", "HIPMATCH", "USERID"} else 0
    if len(values) < 36 + offset or values[2 + offset] not in {"TRAFFIC", "THREAT", "CONFIG", "SYSTEM", "GLOBALPROTECT", "HIPMATCH", "USERID"}:
        return {}
    field = lambda index: values[index + offset]
    fields = {
        "vendor": "paloalto", "pan_log_type": field(2).lower(), "pan_subtype": field(3).lower(),
        "pan_serial": field(1), "pan_generated_time": field(5), "src_ip": field(6), "dst_ip": field(7),
        "nat_src_ip": field(8), "nat_dst_ip": field(9), "rule": field(10), "source_user": field(11),
        "destination_user": field(12), "application": field(13), "vsys": field(14),
        "source_zone": field(15), "destination_zone": field(16), "ingress_interface": field(17),
        "egress_interface": field(18), "log_profile": field(19), "session_id": field(21),
        "source_port": field(23), "destination_port": field(24), "nat_source_port": field(25),
        "nat_destination_port": field(26), "protocol": field(28), "action": field(29),
    }
    if field(2) == "TRAFFIC":
        fields.update({"bytes": field(30), "bytes_sent": field(31), "bytes_received": field(32), "packets": field(33), "session_start": field(34), "elapsed_seconds": field(35)})
    if field(2) == "THREAT":
        fields.update({"threat_name": field(30), "threat_id": field(31), "category": field(32), "severity": field(33)})
    return {key: value for key, value in fields.items() if value and value.lower() not in {"n/a", "any", "none"}}


def built_in_parsing_rules():
    """Describe fixed parsers without exposing executable parser configuration."""
    return [{"id": "key-value", "name": "Key=value fields", "kind": "built-in", "description": "Extracts bounded key=value tokens."},
            {"id": "pan-os-csv", "name": "PAN-OS CSV", "kind": "built-in", "description": "Normalizes PAN-OS Traffic and Threat CSV logs."}]


def validate_user_defined_rule(data):
    """Validate the deliberately small, non-executable user parsing-rule language."""
    name = str(data.get("name", "")).strip()
    literal = str(data.get("match_literal", ""))
    delimiter = DELIMITERS.get(str(data.get("delimiter", "")).lower())
    raw_names = data.get("field_names", "")
    names = [part.strip().lower() for part in raw_names.split(",")] if isinstance(raw_names, str) else list(raw_names)
    if not 1 <= len(name) <= MAX_RULE_NAME_LENGTH:
        raise ValueError(f"Rule name must be 1-{MAX_RULE_NAME_LENGTH} characters")
    if not literal or len(literal) > MAX_MATCH_LITERAL_LENGTH:
        raise ValueError(f"Match literal must be 1-{MAX_MATCH_LITERAL_LENGTH} characters")
    if delimiter is None:
        raise ValueError("Delimiter must be comma, pipe, or tab")
    if not 1 <= len(names) <= MAX_RULE_FIELDS or len(set(names)) != len(names):
        raise ValueError(f"Provide 1-{MAX_RULE_FIELDS} unique field names")
    if not all(isinstance(field, str) and FIELD_NAME_RE.fullmatch(field) for field in names):
        raise ValueError("Field names must start with a letter and contain only lowercase letters, digits, dot, dash, or underscore")
    return {"name": name, "match_literal": literal, "delimiter": delimiter, "field_names": names}


def bounded_fields(fields):
    return {str(key).lower(): str(value) for key, value in fields.items()
            if FIELD_NAME_RE.fullmatch(str(key).lower()) and value is not None and 0 < len(str(value)) <= MAX_FIELD_VALUE_LENGTH}


def parse_user_defined_fields(message, rules):
    """Apply literal-prefix, delimited rules only; never evaluate user code, SQL, or regex."""
    fields = {}
    for rule in rules:
        literal, delimiter, names = rule["match_literal"], rule["delimiter"], rule["field_names"]
        if not message.startswith(literal):
            continue
        try:
            values = next(csv.reader(StringIO(message), delimiter=delimiter, strict=True))
        except (csv.Error, StopIteration):
            continue
        fields.update({name: value for name, value in zip(names, values)})
    return bounded_fields(fields)


def user_defined_rules(con):
    return [dict(row) for row in con.execute("SELECT id,name,match_literal,delimiter,field_names,created_at FROM parsing_rules ORDER BY id")]


def parse_fields(message):
    fields = {}
    for match in KV_RE.finditer(message):
        value = match.group("quoted")
        if value is None:
            value = match.group("bare")
        else:
            try:
                value = bytes(value, "utf-8").decode("unicode_escape")
            except UnicodeDecodeError:
                pass
        fields[match.group("key").lower()] = value
    return bounded_fields(fields)


def parse_syslog(raw, user_rules=()):
    parsed = {"facility": None, "severity": None, "hostname": None, "app_name": None,
              "process_id": None, "event_type": None, "event_time": None,
              "syslog_version": None, "message": raw, "fields": {}}
    body = raw
    pri = re.match(r"^<(\d{1,3})>(.*)$", raw, re.S)
    if pri:
        value = int(pri.group(1))
        parsed["facility"], parsed["severity"], body = value // 8, value % 8, pri.group(2)
    r5424 = re.match(r"^(?P<version>\d{1,2})\s+(?P<time>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<proc>\S+)\s+(?P<msgid>\S+)\s*(?P<rest>.*)$", body, re.S)
    if r5424:
        data = r5424.groupdict()
        parsed.update({"syslog_version": int(data["version"]), "event_time": data["time"],
                       "hostname": None if data["host"] == "-" else data["host"],
                       "app_name": None if data["app"] == "-" else data["app"],
                       "process_id": None if data["proc"] == "-" else data["proc"],
                       "event_type": None if data["msgid"] == "-" else data["msgid"]})
        rest = data["rest"].lstrip()
        if rest.startswith("-"):
            rest = rest[1:].lstrip()
        elif rest.startswith("["):
            depth = end = 0
            for position, char in enumerate(rest):
                if char == "[": depth += 1
                elif char == "]":
                    depth -= 1
                    if depth == 0:
                        end = position + 1
                        break
            rest = rest[end:].lstrip() if end else rest
        parsed["message"] = rest
    else:
        r3164 = re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+(\S+)\s+([^:\s]+):?\s*(.*)$", body, re.S)
        if r3164:
            parsed["hostname"], parsed["app_name"], parsed["message"] = r3164.groups()
        else:
            parsed["message"] = body
    parsed["fields"] = parse_fields(parsed["message"])
    palo_payload = (parsed["app_name"] + " " + parsed["message"]) if parsed["app_name"] and re.match(r"^\d+,\d{4}/\d{2}/\d{2}", parsed["app_name"]) else parsed["message"]
    parsed["fields"].update(bounded_fields(parse_palo_alto_fields(palo_payload)))
    parsed["fields"].update(parse_user_defined_fields(parsed["message"], user_rules))
    parsed["fields"] = bounded_fields(parsed["fields"])
    return parsed


def store(listener_id, addr, payload):
    raw = payload.decode("utf-8", errors="replace").rstrip("\r\n\x00")
    if not raw:
        return
    with db() as con:
        parsed = parse_syslog(raw, user_defined_rules(con))
        row = con.execute("""INSERT INTO messages(received_at,listener_id,source_ip,source_port,facility,severity,hostname,app_name,message,raw,event_time,syslog_version,process_id,event_type)
            VALUES(CURRENT_TIMESTAMP,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (listener_id, addr[0], addr[1], parsed["facility"], parsed["severity"], parsed["hostname"], parsed["app_name"], parsed["message"], raw, parsed["event_time"], parsed["syslog_version"], parsed["process_id"], parsed["event_type"])).fetchone()
        if parsed["fields"]:
            with con.cursor() as cursor:
                cursor.executemany("INSERT INTO message_fields(message_id,field_name,field_value) VALUES(%s,%s,%s)", [(row["id"], key, value) for key, value in parsed["fields"].items()])


def reindex_palo_alto_messages():
    """Backfill structured fields for legacy PAN-OS records without touching other fields."""
    with db() as con:
        # Keep startup bounded: legacy indexing is idempotent and completes across restarts.
        rows = list(con.execute("SELECT id, app_name, message FROM messages WHERE source_ip='192.168.4.4'::inet OR hostname='PANFW.deanscloud.com' ORDER BY id DESC LIMIT 1000"))
        entries = []
        for row in rows:
            payload = (row["app_name"] + " " + row["message"]) if row["app_name"] and re.match(r"^\d+,\d{4}/\d{2}/\d{2}", row["app_name"]) else row["message"]
            entries.extend((row["id"], key, value) for key, value in parse_palo_alto_fields(payload).items())
        if entries:
            with con.cursor() as cursor:
                cursor.executemany("INSERT INTO message_fields(message_id,field_name,field_value) VALUES(%s,%s,%s) ON CONFLICT(message_id,field_name) DO UPDATE SET field_value=EXCLUDED.field_value", entries)
        return len(entries)


def udp_listener(listener_id, port, stop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); sock.bind(("0.0.0.0", port)); sock.settimeout(1)
        while not stop.is_set():
            try:
                payload, addr = sock.recvfrom(65535)
                store(listener_id, addr, payload)
            except socket.timeout: pass
            except OSError:
                if not stop.is_set(): raise
    finally: sock.close()


def handle_tcp_client(conn, addr, listener_id, stop):
    buffer = b""
    try:
        with conn:
            while not stop.is_set():
                try: chunk = conn.recv(65535)
                except socket.timeout: continue
                if not chunk: break
                buffer += chunk
                if len(buffer) > MAX_TCP_MESSAGE_BYTES: return
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1); store(listener_id, addr, line)
            if buffer: store(listener_id, addr, buffer)
    except OSError: pass


def tcp_listener(listener_id, port, stop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); sock.bind(("0.0.0.0", port)); sock.listen(32); sock.settimeout(1)
        while not stop.is_set():
            try:
                conn, addr = sock.accept(); conn.settimeout(1)
                threading.Thread(target=handle_tcp_client, args=(conn, addr, listener_id, stop), daemon=True).start()
            except socket.timeout: pass
            except OSError:
                if not stop.is_set(): raise
    finally: sock.close()


def start_listener(row):
    listener_id, port, protocol = row["id"], row["port"], row["protocol"]
    with workers_lock:
        if listener_id in workers: return
        stop = threading.Event(); target = udp_listener if protocol == "udp" else tcp_listener
        thread = threading.Thread(target=target, args=(listener_id, port, stop), name=f"syslog-{protocol}-{port}", daemon=True)
        workers[listener_id] = (stop, thread); thread.start()


def stop_listener(listener_id):
    with workers_lock: entry = workers.pop(listener_id, None)
    if entry: entry[0].set(); entry[1].join(timeout=2)


def is_dean(headers):
    """Require the exact identity copied by Traefik ForwardAuth, never a local credential."""
    return headers.get("Remote-User") == ADMIN_USER


def json_object(raw):
    data = json.loads(raw)
    if not isinstance(data, dict): raise ValueError("JSON request body must be an object")
    return data


def json_response(handler, data, status=200):
    body = json.dumps(data, default=str).encode()
    handler.send_response(status); handler.send_header("Content-Type", "application/json; charset=utf-8"); handler.send_header("Content-Length", str(len(body))); handler.end_headers(); handler.wfile.write(body)


def html_response(handler, body, status=200):
    encoded = body.encode(); handler.send_response(status); handler.send_header("Content-Type", "text/html; charset=utf-8"); handler.send_header("Content-Length", str(len(encoded))); handler.end_headers(); handler.wfile.write(encoded)


def message_rows(con, query):
    try: limit = min(max(int(query.get("limit", ["100"])[0]), 1), 500)
    except ValueError: limit = 100
    text = query.get("q", [""])[0].strip(); where, args = [], []
    try: tokens = shlex.split(text)
    except ValueError: tokens = text.split()
    special = {"host": "hostname", "hostname": "hostname", "app": "app_name", "source": "source_ip::text", "event": "event_type", "type": "event_type"}
    plain = []
    for token in tokens:
        field = re.fullmatch(r"([A-Za-z][A-Za-z0-9_.-]{0,63}):(.*)", token)
        if field and field.group(2):
            key, value = field.group(1).lower(), field.group(2)
            if key in special:
                where.append(f"COALESCE({special[key]}, '') ILIKE %s"); args.append(f"%{value}%")
            else:
                where.append("EXISTS (SELECT 1 FROM message_fields f WHERE f.message_id=messages.id AND f.field_name=%s AND f.field_value ILIKE %s)"); args.extend((key, f"%{value}%"))
        else: plain.append(token)
    if plain:
        where.append("to_tsvector('simple', coalesce(raw, '') || ' ' || coalesce(hostname, '') || ' ' || coalesce(app_name, '') || ' ' || coalesce(event_type, '')) @@ websearch_to_tsquery('simple', %s)")
        args.append(" ".join(plain))
    sql = "SELECT * FROM messages" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT %s"
    rows = [dict(row) for row in con.execute(sql, (*args, limit))]
    if not rows: return rows
    ids = [row["id"] for row in rows]; fields = {message_id: {} for message_id in ids}
    for row in con.execute("SELECT message_id,field_name,field_value FROM message_fields WHERE message_id = ANY(%s) ORDER BY field_name", (ids,)):
        fields[row["message_id"]][row["field_name"]] = row["field_value"]
    for row in rows: row["fields"] = fields[row["id"]]
    return rows


def dashboard_metrics():
    with db() as con:
        total = con.execute("SELECT COUNT(*) count FROM messages").fetchone()["count"]
        last_minute = con.execute("SELECT COUNT(*) count FROM messages WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '1 minute'").fetchone()["count"]
        hosts = [dict(row) for row in con.execute("SELECT COALESCE(hostname, source_ip::text, 'unknown') hostname, COUNT(*) count FROM messages GROUP BY 1 ORDER BY count DESC, hostname LIMIT 8")]
        unique_hosts = con.execute("SELECT COUNT(DISTINCT COALESCE(hostname, source_ip::text)) count FROM messages").fetchone()["count"]
        sources = con.execute("SELECT COUNT(DISTINCT source_ip) count FROM messages").fetchone()["count"]
        rate = [dict(row) for row in con.execute("SELECT to_char(date_trunc('minute', received_at), 'YYYY-MM-DD HH24:MI') AS bucket, COUNT(*) count FROM messages WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '60 minutes' GROUP BY 1 ORDER BY 1")]
    return {"total_messages": total, "messages_last_minute": last_minute, "messages_per_minute": last_minute, "unique_hosts": unique_hosts, "unique_sources": sources, "hosts": hosts, "rate": rate}


PAGE = '''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Syslog Command Center</title><style>body{font-family:system-ui;background:#101827;color:#e5e7eb;margin:0;padding:24px}main{max-width:1500px;margin:auto}section{background:#1f2937;padding:18px;border-radius:10px;margin:16px 0}input,select,button{padding:8px;border-radius:6px;border:1px solid #4b5563;background:#111827;color:white}button{cursor:pointer;background:#2563eb;border:0}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #374151;padding:8px;text-align:left;vertical-align:top;word-break:break-word}pre{white-space:pre-wrap;margin:0}.muted{color:#9ca3af}.metric{display:inline-block;background:#111827;border:1px solid #374151;border-radius:8px;padding:12px;margin:4px;min-width:130px}.metric b{display:block;font-size:25px;color:#93c5fd}</style><main><h1>Syslog Command Center</h1><p class="muted">Access is enforced at Traefik/Authelia. Dean may use <a href="/admin">Syslog Admin</a> or <a href="/insights">Investigation Workspace</a>.</p><section><h2>Live telemetry</h2><div id="metrics"></div><p id="hosts" class="muted"></p></section><section><h2>Search & correlation</h2><form id="filter"><input name="q" size="65" placeholder="Search text or field filters: username:carapad event:AUTHLOG"><select name="limit"><option>100</option><option>250</option><option>500</option></select><button>Search</button></form><div id="messages"></div></section></main><script>const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));async function api(u,o={}){let r=await fetch(u,o);if(!r.ok)throw Error((await r.json()).error);return r.json()}async function refresh(){let x=await api('/api/dashboard');metrics.innerHTML=[['Total',x.total_messages],['Messages / min',x.messages_per_minute],['Hosts',x.unique_hosts],['Sources',x.unique_sources]].map(v=>`<div class=metric>${v[0]}<b>${v[1]}</b></div>`).join('');hosts.textContent='Top hosts: '+(x.hosts.map(v=>v.hostname+' '+v.count).join(' · ')||'No traffic yet');let m=await api('/api/messages?'+new URLSearchParams(new FormData(filter)));let field=v=>Object.entries(v.fields||{}).map(([k,val])=>`<button class="field" data-filter="${esc(k)}:${esc(val)}">${esc(k)}=${esc(val)}</button>`).join('');let london=v=>v?new Date(v).toLocaleString('en-GB',{timeZone:'Europe/London',dateStyle:'short',timeStyle:'medium'}):'-';messages.innerHTML='<p class=muted>'+m.length+' records</p><table><tr><th>Received (London)</th><th>Source</th><th>Host/App</th><th>Message & indexed fields</th></tr>'+m.map(v=>`<tr><td>${esc(london(v.received_at))}</td><td>${esc(v.source_ip)}:${v.source_port}</td><td>${esc(v.hostname||'-')} / ${esc(v.app_name||'-')}</td><td><pre>${esc(v.message)}</pre><div class="fields">${field(v)}</div></td></tr>`).join('')+'</table>';messages.querySelectorAll('button[data-filter]').forEach(b=>b.onclick=()=>{filter.q.value=(filter.q.value+' '+b.dataset.filter).trim();refresh()})}filter.onsubmit=e=>{e.preventDefault();refresh()};refresh();setInterval(refresh,5000)</script>'''

ADMIN_PAGE = '''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Syslog Admin</title><style>body{font-family:system-ui;background:#101827;color:#e5e7eb;margin:0;padding:24px}main{max-width:1100px;margin:auto}section{background:#1f2937;padding:18px;border-radius:10px;margin:16px 0}input,select,button{padding:8px;border-radius:6px;border:1px solid #4b5563;background:#111827;color:white}button{cursor:pointer;background:#2563eb;border:0}.danger{background:#b91c1c}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #374151;padding:8px;text-align:left}.muted{color:#9ca3af}</style><main><h1>Syslog Admin</h1><p class="muted">ForwardAuth identity: dean. This page has no local credentials, session, or MFA.</p><section><h2>Health & storage</h2><pre id="health"></pre></section><section><h2>Retention</h2><form id="retention">Retention (days) <input name="days" type="number" min="1" max="3650" required><button>Save</button></form></section><section><h2>Listeners</h2><form id="add"><input name="port" type="number" min="1" max="65535" required placeholder="Port"><select name="protocol"><option>udp</option><option>tcp</option></select><button>Add listener</button></form><div id="listeners"></div></section><p><a href="/">Back to dashboard</a></p></main><script>async function api(u,o={}){let r=await fetch(u,o);if(!r.ok)throw Error((await r.json()).error);return r.json()}async function refresh(){let x=await api('/api/admin/overview');health.textContent=JSON.stringify(x,null,2);retention.days.value=x.retention_days;listeners.innerHTML='<table><tr><th>Port</th><th>Protocol</th><th>Status</th><th></th></tr>'+x.listeners.map(v=>`<tr><td>${v.port}</td><td>${v.protocol}</td><td>${v.running?'running':'stopped'}</td><td><button class=danger onclick="removeListener(${v.id})">Remove</button></td></tr>`).join('')+'</table>'}async function removeListener(id){if(confirm('Stop and delete this listener?')){await api('/api/admin/listeners/'+id,{method:'DELETE'});refresh()}}add.onsubmit=async e=>{e.preventDefault();await api('/api/admin/listeners',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(add)))});add.reset();refresh()};retention.onsubmit=async e=>{e.preventDefault();await api('/api/admin/retention',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(retention)))});refresh()};refresh()</script>'''

def insight_query_spec():
    """Fixed, bounded investigation dimensions; browser input never becomes SQL."""
    return {"windows": (1, 6, 24, 72, 168), "facets": ("severity", "application", "host", "source_zone", "rule")}


def activity_insights(hours):
    spec = insight_query_spec()
    try: hours = int(hours)
    except (TypeError, ValueError): hours = 24
    if hours not in spec["windows"]: hours = 24
    with db() as con:
        total = con.execute("SELECT COUNT(*) count FROM messages WHERE received_at >= CURRENT_TIMESTAMP - (%s * INTERVAL '1 hour')", (hours,)).fetchone()["count"]
        critical = con.execute("SELECT COUNT(DISTINCT m.id) count FROM messages m JOIN message_fields f ON f.message_id=m.id WHERE m.received_at >= CURRENT_TIMESTAMP - (%s * INTERVAL '1 hour') AND f.field_name='severity' AND lower(f.field_value) IN ('critical','high')", (hours,)).fetchone()["count"]
        timeline = [dict(row) for row in con.execute("SELECT to_char(date_trunc('hour',received_at),'HH24:00') bucket, COUNT(*) count FROM messages WHERE received_at >= CURRENT_TIMESTAMP - (%s * INTERVAL '1 hour') GROUP BY 1 ORDER BY 1", (hours,))]
        def facet(field):
            if field == "host":
                sql = "SELECT COALESCE(hostname,source_ip::text,'unknown') label,COUNT(*) count FROM messages WHERE received_at >= CURRENT_TIMESTAMP - (%s * INTERVAL '1 hour') GROUP BY 1 ORDER BY count DESC,label LIMIT 8"; return [dict(row) for row in con.execute(sql,(hours,))]
            sql = "SELECT f.field_value label,COUNT(*) count FROM message_fields f JOIN messages m ON m.id=f.message_id WHERE m.received_at >= CURRENT_TIMESTAMP - (%s * INTERVAL '1 hour') AND f.field_name=%s GROUP BY 1 ORDER BY count DESC,label LIMIT 8"; return [dict(row) for row in con.execute(sql,(hours,field))]
        facets = {name: facet(name) for name in spec["facets"]}
        recent = message_rows(con, {"limit": ["20"]})
    return {"hours": hours, "total": total, "high_or_critical": critical, "timeline": timeline, "facets": facets, "recent": recent}


INSIGHTS_PAGE = '''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Investigation Workspace</title><style>:root{color-scheme:dark;--bg:#07111f;--card:#0d1b2d;--line:#213551;--text:#e9f2ff;--muted:#9ab0ca;--accent:#55d6be;--alert:#fb7185}*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#07111f,#0c1830);color:var(--text);font:14px system-ui}.shell{max-width:1500px;margin:auto;padding:24px}.top{display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap}.eyebrow{color:var(--accent);font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}h1{margin:4px 0;font-size:28px}a,button,select{font:inherit}a{color:var(--accent)}select,button{border-radius:8px;border:1px solid var(--line);padding:9px 12px;background:#0a1526;color:var(--text)}button{background:var(--accent);color:#06111d;font-weight:800;cursor:pointer}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:12px;margin:20px 0}.card,.panel{background:rgba(13,27,45,.94);border:1px solid var(--line);border-radius:14px;padding:16px}.value{font-size:30px;font-weight:800;color:var(--accent)}.danger{color:var(--alert)}.layout{display:grid;grid-template-columns:1.35fr 1fr;gap:14px}.facets{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.bar{display:grid;grid-template-columns:110px 1fr 38px;gap:8px;align-items:center;margin:7px 0}.track{height:8px;background:#12233b;border-radius:10px}.fill{height:8px;background:linear-gradient(90deg,#55d6be,#67a8ff);border-radius:10px}table{width:100%;border-collapse:collapse;font-size:12px}td,th{padding:9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;word-break:break-word}pre{white-space:pre-wrap;margin:0;color:#bdcde4}.muted{color:var(--muted)}.chart{height:150px;display:flex;align-items:end;gap:4px;padding-top:15px}.column{flex:1;min-width:6px;background:#55d6be;border-radius:4px 4px 0 0;position:relative}.column span{position:absolute;bottom:-20px;font-size:9px;color:var(--muted);white-space:nowrap}@media(max-width:850px){.shell{padding:14px}.layout{grid-template-columns:1fr}.facets{grid-template-columns:1fr}.bar{grid-template-columns:95px 1fr 32px}}</style><main class="shell"><div class="top"><div><div class="eyebrow">Syslog Command Center</div><h1>Investigation Workspace</h1><div class="muted">Operational signal, security triage, and rapid correlation</div></div><div><select id="window"><option value="1">Last hour</option><option value="6">Last 6 hours</option><option value="24" selected>Last 24 hours</option><option value="72">Last 3 days</option><option value="168">Last 7 days</option></select> <button id="refresh">Refresh</button> <a href="/">Explorer</a></div></div><div class="grid" id="summary"></div><div class="layout"><section class="panel"><h2>Event volume</h2><div id="chart" class="chart"></div></section><section class="panel"><h2>Fast facets</h2><div id="facets" class="facets"></div></section></div><section class="panel"><h2>Latest events</h2><div id="recent"></div></section></main><script>const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));async function load(){let d=await (await fetch('/api/insights?hours='+window.value,{cache:'no-store'})).json();summary.innerHTML=[['Events',d.total,''],['High / critical',d.high_or_critical,'danger'],['Window',d.hours+'h',''],['Top source',(d.facets.host[0]||{}).label||'—','']].map(x=>`<div class=card>${x[0]}<div class="value ${x[2]}">${esc(x[1])}</div></div>`).join('');let max=Math.max(1,...d.timeline.map(x=>x.count));chart.innerHTML=d.timeline.map(x=>`<div class=column style="height:${Math.max(5,x.count/max*100)}%" title="${esc(x.bucket)}: ${x.count}"><span>${esc(x.bucket)}</span></div>`).join('')||'<p class=muted>No events in this window.</p>';facets.innerHTML=Object.entries(d.facets).map(([name,rows])=>`<div class=card><b>${esc(name.replace('_',' '))}</b>${rows.map(x=>`<div class=bar><span>${esc(x.label)}</span><div class=track><div class=fill style="width:${Math.max(4,x.count/(rows[0]?.count||1)*100)}%"></div></div><span>${x.count}</span></div>`).join('')||'<p class=muted>No values</p>'}</div>`).join('');recent.innerHTML='<table><tr><th>Received</th><th>Host</th><th>Message</th><th>Fields</th></tr>'+d.recent.map(x=>`<tr><td>${esc(x.received_at)}</td><td>${esc(x.hostname||x.source_ip)}</td><td><pre>${esc(x.message)}</pre></td><td>${esc(Object.entries(x.fields||{}).slice(0,6).map(v=>v.join(':')).join(' · '))}</td></tr>`).join('')+'</table>'}refresh.onclick=load;window.onchange=load;load().catch(e=>console.error(e));</script>'''


TAB_CSS = ".tabs{display:flex;gap:6px;margin:0 0 18px;border-bottom:1px solid #374151}.tab{padding:9px 13px;text-decoration:none;color:#cbd5e1;border-radius:8px 8px 0 0}.tab[aria-selected=true]{background:#2563eb;color:white}.tab:focus-visible{outline:3px solid #93c5fd;outline-offset:2px}@media(max-width:520px){.tabs{gap:2px}.tab{flex:1;text-align:center;padding:9px 4px;font-size:13px}}"


def tabs(active):
    entries = (("Dashboard", "/", "dashboard"), ("Investigate", "/insights", "investigate"), ("Admin", "/admin", "admin"))
    return '<nav class="tabs" role="tablist" aria-label="Syslog sections">' + ''.join(
        f'<a class="tab" role="tab" aria-selected="{str(key == active).lower()}" href="{href}">{label}</a>'
        for label, href, key in entries) + "</nav>"


def add_tabs(page, active):
    page = page.replace("</style>", TAB_CSS + "</style>", 1)
    marker = '<main class="shell">' if '<main class="shell">' in page else "<main>"
    return page.replace(marker, marker + tabs(active), 1)


PAGE = add_tabs(PAGE.replace('Access is enforced at Traefik/Authelia. Dean may use <a href="/admin">Syslog Admin</a> or <a href="/insights">Investigation Workspace</a>.', 'Access is enforced at Traefik/Authelia; Admin remains dean-only.'), "dashboard")
INSIGHTS_PAGE = add_tabs(INSIGHTS_PAGE.replace('<a href="/">Explorer</a>', ''), "investigate")
ADMIN_PAGE = ADMIN_PAGE.replace('</section><p><a href="/">Back to dashboard</a></p></main>', '</section><section><h2>Parsing Rules</h2><p class="muted">Safe literal-prefix CSV-style extraction only: no code, SQL, or regular expressions.</p><form id="rule"><input name="name" maxlength="80" required placeholder="Rule name"><input name="match_literal" maxlength="120" required placeholder="Exact prefix, e.g. ACME,"><select name="delimiter"><option value="comma">comma</option><option value="pipe">pipe</option><option value="tab">tab</option></select><input name="field_names" required placeholder="field_one, field_two (max 32)"><button>Add rule</button></form><div id="rules"></div></section></main>')
ADMIN_PAGE = add_tabs(ADMIN_PAGE, "admin")
ADMIN_PAGE = ADMIN_PAGE.replace('refresh()</script>', '''async function refreshRules(){let x=await api('/api/admin/parsing-rules');rules.textContent='';let table=document.createElement('table');table.innerHTML='<tr><th>Type</th><th>Name</th><th>Match / detail</th><th>Fields</th></tr>';for(const v of [...x.built_in,...x.user_defined]){let row=table.insertRow();row.insertCell().textContent=v.kind||'user-defined';row.insertCell().textContent=v.name;row.insertCell().textContent=v.match_literal||v.description;row.insertCell().textContent=Array.isArray(v.field_names)?v.field_names.join(', '):''}rules.append(table)}rule.onsubmit=async e=>{e.preventDefault();await api('/api/admin/parsing-rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(rule)))});rule.reset();refreshRules()};refresh();refreshRules()</script>''')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): print("web", self.address_string(), fmt % args)
    def require_dean(self):
        if is_dean(self.headers): return True
        json_response(self, {"error": "forbidden"}, 403)
        return False
    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        return json_object(self.rfile.read(length))
    def listener_rows(self, con):
        rows = [dict(row) for row in con.execute("SELECT * FROM listeners ORDER BY port, protocol")]
        with workers_lock:
            for row in rows: row["running"] = row["id"] in workers and workers[row["id"]][1].is_alive()
        return rows
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz": return json_response(self, {"status": "ok"})
        if path == "/": return html_response(self, PAGE)
        if path == "/insights": return html_response(self, INSIGHTS_PAGE)
        if path == "/admin":
            if not is_dean(self.headers): return html_response(self, "<h1>Forbidden</h1>", 403)
            return html_response(self, ADMIN_PAGE)
        if path == "/api/dashboard": return json_response(self, dashboard_metrics())
        if path == "/api/insights": return json_response(self, activity_insights(parse_qs(urlparse(self.path).query).get("hours", [24])[0]))
        if path == "/api/messages":
            with db() as con: return json_response(self, message_rows(con, parse_qs(urlparse(self.path).query)))
        if path == "/api/admin/parsing-rules":
            if not self.require_dean(): return
            with db() as con:
                return json_response(self, {"built_in": built_in_parsing_rules(), "user_defined": user_defined_rules(con)})
        if path == "/api/admin/overview":
            if not self.require_dean(): return
            with db() as con:
                storage = con.execute("SELECT pg_database_size(current_database()) bytes").fetchone()["bytes"]
                messages = con.execute("SELECT COUNT(*) count FROM messages").fetchone()["count"]
                return json_response(self, {"database": "ok", "storage_bytes": storage, "message_count": messages, "retention_days": retention_days(con), "listeners": self.listener_rows(con)})
        return json_response(self, {"error": "not found"}, 404)
    def do_POST(self):
        if not self.require_dean(): return
        path = urlparse(self.path).path
        if path == "/api/admin/parsing-rules":
            try:
                rule = validate_user_defined_rule(self.read_json())
                with db() as con:
                    row = con.execute("INSERT INTO parsing_rules(name,match_literal,delimiter,field_names) VALUES(%s,%s,%s,%s) RETURNING id,name,match_literal,delimiter,field_names,created_at", (rule["name"], rule["match_literal"], rule["delimiter"], json.dumps(rule["field_names"]))).fetchone()
                return json_response(self, dict(row), 201)
            except psycopg.errors.UniqueViolation:
                return json_response(self, {"error": "A parsing rule with that name already exists"}, 409)
            except (ValueError, json.JSONDecodeError) as exc:
                return json_response(self, {"error": str(exc)}, 400)
        if path != "/api/admin/listeners": return json_response(self, {"error": "not found"}, 404)
        listener_id = None
        try:
            data = self.read_json(); port = int(data.get("port")); protocol = str(data.get("protocol", "")).lower()
            if not 1 <= port <= 65535 or protocol not in ("udp", "tcp"): raise ValueError("Port must be 1-65535 and protocol udp or tcp")
            with db() as con: row = con.execute("INSERT INTO listeners(port,protocol) VALUES(%s,%s) RETURNING *", (port, protocol)).fetchone(); listener_id = row["id"]
            start_listener(row); time.sleep(.1)
            with workers_lock: running = workers[listener_id][1].is_alive()
            if not running: raise RuntimeError("could not bind listener")
            result = dict(row); result["running"] = True
            return json_response(self, result, 201)
        except psycopg.errors.UniqueViolation: return json_response(self, {"error": "This port/protocol listener already exists"}, 409)
        except Exception as exc:
            if listener_id:
                stop_listener(listener_id)
                with db() as con: con.execute("DELETE FROM listeners WHERE id=%s", (listener_id,))
            return json_response(self, {"error": str(exc)}, 400)
    def do_PUT(self):
        if not self.require_dean(): return
        if urlparse(self.path).path != "/api/admin/retention": return json_response(self, {"error": "not found"}, 404)
        try:
            days = parse_retention_days(self.read_json().get("days"))
            with db() as con:
                con.execute("INSERT INTO settings(setting_key,setting_value,updated_at) VALUES('retention_days',%s,CURRENT_TIMESTAMP) ON CONFLICT(setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value,updated_at=CURRENT_TIMESTAMP", (str(days),))
                deleted = purge_expired(con)
            return json_response(self, {"retention_days": days, "deleted_messages": deleted})
        except (ValueError, json.JSONDecodeError) as exc: return json_response(self, {"error": str(exc)}, 400)
    def do_DELETE(self):
        if not self.require_dean(): return
        found = re.fullmatch(r"/api/admin/listeners/(\d+)", urlparse(self.path).path)
        if not found: return json_response(self, {"error": "not found"}, 404)
        listener_id = int(found.group(1)); stop_listener(listener_id)
        with db() as con: con.execute("DELETE FROM listeners WHERE id=%s", (listener_id,))
        return json_response(self, {"deleted": listener_id})


def main():
    apply_migrations()
    indexed = reindex_palo_alto_messages()
    if indexed: print(f"Indexed {indexed} Palo Alto fields")
    with db() as con:
        purge_expired(con)
        saved = list(con.execute("SELECT * FROM listeners WHERE enabled"))
    for row in saved: start_listener(row)
    server = ThreadingHTTPServer((WEB_HOST, WEB_PORT), Handler)
    print(f"Syslog UI listening on http://{WEB_HOST}:{WEB_PORT}")
    server.serve_forever()


if __name__ == "__main__": main()
