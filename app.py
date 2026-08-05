#!/usr/bin/env python3
"""PostgreSQL-backed syslog collector and Traefik/Authelia-protected dashboard."""
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
    return fields


def parse_syslog(raw):
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
    return parsed


def store(listener_id, addr, payload):
    raw = payload.decode("utf-8", errors="replace").rstrip("\r\n\x00")
    if not raw:
        return
    parsed = parse_syslog(raw)
    with db() as con:
        row = con.execute("""INSERT INTO messages(received_at,listener_id,source_ip,source_port,facility,severity,hostname,app_name,message,raw,event_time,syslog_version,process_id,event_type)
            VALUES(CURRENT_TIMESTAMP,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (listener_id, addr[0], addr[1], parsed["facility"], parsed["severity"], parsed["hostname"], parsed["app_name"], parsed["message"], raw, parsed["event_time"], parsed["syslog_version"], parsed["process_id"], parsed["event_type"])).fetchone()
        if parsed["fields"]:
            con.executemany("INSERT INTO message_fields(message_id,field_name,field_value) VALUES(%s,%s,%s)", [(row["id"], key, value) for key, value in parsed["fields"].items()])


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


PAGE = '''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Syslog Command Center</title><style>body{font-family:system-ui;background:#101827;color:#e5e7eb;margin:0;padding:24px}main{max-width:1500px;margin:auto}section{background:#1f2937;padding:18px;border-radius:10px;margin:16px 0}input,select,button{padding:8px;border-radius:6px;border:1px solid #4b5563;background:#111827;color:white}button{cursor:pointer;background:#2563eb;border:0}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #374151;padding:8px;text-align:left;vertical-align:top;word-break:break-word}pre{white-space:pre-wrap;margin:0}.muted{color:#9ca3af}.metric{display:inline-block;background:#111827;border:1px solid #374151;border-radius:8px;padding:12px;margin:4px;min-width:130px}.metric b{display:block;font-size:25px;color:#93c5fd}</style><main><h1>Syslog Command Center</h1><p class="muted">Access is enforced at Traefik/Authelia. Dean may use <a href="/admin">Syslog Admin</a>.</p><section><h2>Live telemetry</h2><div id="metrics"></div><p id="hosts" class="muted"></p></section><section><h2>Search & correlation</h2><form id="filter"><input name="q" size="65" placeholder="Search text or field filters: username:carapad event:AUTHLOG"><select name="limit"><option>100</option><option>250</option><option>500</option></select><button>Search</button></form><div id="messages"></div></section></main><script>const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));async function api(u,o={}){let r=await fetch(u,o);if(!r.ok)throw Error((await r.json()).error);return r.json()}async function refresh(){let x=await api('/api/dashboard');metrics.innerHTML=[['Total',x.total_messages],['Messages / min',x.messages_per_minute],['Hosts',x.unique_hosts],['Sources',x.unique_sources]].map(v=>`<div class=metric>${v[0]}<b>${v[1]}</b></div>`).join('');hosts.textContent='Top hosts: '+(x.hosts.map(v=>v.hostname+' '+v.count).join(' · ')||'No traffic yet');let m=await api('/api/messages?'+new URLSearchParams(new FormData(filter)));messages.innerHTML='<p class=muted>'+m.length+' records</p><table><tr><th>Received</th><th>Source</th><th>Host/App</th><th>Message</th></tr>'+m.map(v=>`<tr><td>${esc(v.received_at)}</td><td>${esc(v.source_ip)}:${v.source_port}</td><td>${esc(v.hostname||'-')} / ${esc(v.app_name||'-')}</td><td><pre>${esc(v.message)}</pre></td></tr>`).join('')+'</table>'}filter.onsubmit=e=>{e.preventDefault();refresh()};refresh();setInterval(refresh,5000)</script>'''

ADMIN_PAGE = '''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Syslog Admin</title><style>body{font-family:system-ui;background:#101827;color:#e5e7eb;margin:0;padding:24px}main{max-width:1100px;margin:auto}section{background:#1f2937;padding:18px;border-radius:10px;margin:16px 0}input,select,button{padding:8px;border-radius:6px;border:1px solid #4b5563;background:#111827;color:white}button{cursor:pointer;background:#2563eb;border:0}.danger{background:#b91c1c}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #374151;padding:8px;text-align:left}.muted{color:#9ca3af}</style><main><h1>Syslog Admin</h1><p class="muted">ForwardAuth identity: dean. This page has no local credentials, session, or MFA.</p><section><h2>Health & storage</h2><pre id="health"></pre></section><section><h2>Retention</h2><form id="retention">Retention (days) <input name="days" type="number" min="1" max="3650" required><button>Save</button></form></section><section><h2>Listeners</h2><form id="add"><input name="port" type="number" min="1" max="65535" required placeholder="Port"><select name="protocol"><option>udp</option><option>tcp</option></select><button>Add listener</button></form><div id="listeners"></div></section><p><a href="/">Back to dashboard</a></p></main><script>async function api(u,o={}){let r=await fetch(u,o);if(!r.ok)throw Error((await r.json()).error);return r.json()}async function refresh(){let x=await api('/api/admin/overview');health.textContent=JSON.stringify(x,null,2);retention.days.value=x.retention_days;listeners.innerHTML='<table><tr><th>Port</th><th>Protocol</th><th>Status</th><th></th></tr>'+x.listeners.map(v=>`<tr><td>${v.port}</td><td>${v.protocol}</td><td>${v.running?'running':'stopped'}</td><td><button class=danger onclick="removeListener(${v.id})">Remove</button></td></tr>`).join('')+'</table>'}async function removeListener(id){if(confirm('Stop and delete this listener?')){await api('/api/admin/listeners/'+id,{method:'DELETE'});refresh()}}add.onsubmit=async e=>{e.preventDefault();await api('/api/admin/listeners',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(add)))});add.reset();refresh()};retention.onsubmit=async e=>{e.preventDefault();await api('/api/admin/retention',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(retention)))});refresh()};refresh()</script>'''


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
        if path == "/admin":
            if not is_dean(self.headers): return html_response(self, "<h1>Forbidden</h1>", 403)
            return html_response(self, ADMIN_PAGE)
        if path == "/api/dashboard": return json_response(self, dashboard_metrics())
        if path == "/api/messages":
            with db() as con: return json_response(self, message_rows(con, parse_qs(urlparse(self.path).query)))
        if path == "/api/admin/overview":
            if not self.require_dean(): return
            with db() as con:
                storage = con.execute("SELECT pg_database_size(current_database()) bytes").fetchone()["bytes"]
                messages = con.execute("SELECT COUNT(*) count FROM messages").fetchone()["count"]
                return json_response(self, {"database": "ok", "storage_bytes": storage, "message_count": messages, "retention_days": retention_days(con), "listeners": self.listener_rows(con)})
        return json_response(self, {"error": "not found"}, 404)
    def do_POST(self):
        if not self.require_dean(): return
        if urlparse(self.path).path != "/api/admin/listeners": return json_response(self, {"error": "not found"}, 404)
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
    with db() as con:
        purge_expired(con)
        saved = list(con.execute("SELECT * FROM listeners WHERE enabled"))
    for row in saved: start_listener(row)
    server = ThreadingHTTPServer((WEB_HOST, WEB_PORT), Handler)
    print(f"Syslog UI listening on http://{WEB_HOST}:{WEB_PORT}")
    server.serve_forever()


if __name__ == "__main__": main()
