#!/usr/bin/env python3
"""Small, dependency-free syslog collector with indexed search and correlation."""
import hashlib
import hmac
import json
import os
import re
import shlex
import socket
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "syslog.db")
WEB_HOST = os.environ.get("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.environ.get("WEB_PORT", "8085"))
TOKEN = os.environ.get("SYSLOG_UI_TOKEN", "")
COOKIE_NAME = "syslog_ui_auth"
workers = {}
workers_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS listeners (
  id INTEGER PRIMARY KEY AUTOINCREMENT, port INTEGER NOT NULL, protocol TEXT NOT NULL CHECK(protocol IN ('udp','tcp')),
  enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, UNIQUE(port, protocol)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT NOT NULL, listener_id INTEGER,
  source_ip TEXT NOT NULL, source_port INTEGER NOT NULL, facility INTEGER, severity INTEGER,
  hostname TEXT, app_name TEXT, message TEXT NOT NULL, raw TEXT NOT NULL,
  event_time TEXT, syslog_version INTEGER, process_id TEXT, event_type TEXT,
  FOREIGN KEY(listener_id) REFERENCES listeners(id)
);
CREATE TABLE IF NOT EXISTS message_fields (
  message_id INTEGER NOT NULL, field_name TEXT NOT NULL, field_value TEXT NOT NULL,
  PRIMARY KEY(message_id, field_name), FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_listener ON messages(listener_id);
CREATE INDEX IF NOT EXISTS idx_messages_hostname ON messages(hostname);
CREATE INDEX IF NOT EXISTS idx_messages_app_name ON messages(app_name);
CREATE INDEX IF NOT EXISTS idx_message_fields_lookup ON message_fields(field_name, field_value, message_id);
"""

KV_RE = re.compile(r'''(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)=(?:"(?P<quoted>(?:\\.|[^"\\])*)"|(?P<bare>[^\s]+))''')

def db():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    return con

def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

def migrate(con):
    columns = {row["name"] for row in con.execute("PRAGMA table_info(messages)")}
    for name, kind in (("event_time", "TEXT"), ("syslog_version", "INTEGER"), ("process_id", "TEXT"), ("event_type", "TEXT")):
        if name not in columns:
            con.execute(f"ALTER TABLE messages ADD COLUMN {name} {kind}")

def setup_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    with db() as con:
        con.executescript(SCHEMA)
        migrate(con)
        con.executescript("""
        CREATE INDEX IF NOT EXISTS idx_messages_event_type ON messages(event_type);
        CREATE INDEX IF NOT EXISTS idx_messages_hostname ON messages(hostname);
        CREATE INDEX IF NOT EXISTS idx_messages_app_name ON messages(app_name);
        CREATE INDEX IF NOT EXISTS idx_message_fields_lookup ON message_fields(field_name, field_value, message_id);
        """)
        reindex_existing(con)

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
    """Parse RFC5424/RFC3164 plus key=value payloads; always preserve raw input."""
    parsed = {"facility": None, "severity": None, "hostname": None, "app_name": None,
              "process_id": None, "event_type": None, "event_time": None,
              "syslog_version": None, "message": raw, "fields": {}}
    body = raw
    pri = re.match(r"^<(\d{1,3})>(.*)$", raw, re.S)
    if pri:
        value = int(pri.group(1))
        parsed["facility"], parsed["severity"], body = value // 8, value % 8, pri.group(2)

    # RFC5424: VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG
    r5424 = re.match(r"^(?P<version>\d{1,2})\s+(?P<time>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<proc>\S+)\s+(?P<msgid>\S+)\s*(?P<rest>.*)$", body, re.S)
    if r5424:
        data = r5424.groupdict()
        parsed.update({
            "syslog_version": int(data["version"]), "event_time": data["time"],
            "hostname": None if data["host"] == "-" else data["host"],
            "app_name": None if data["app"] == "-" else data["app"],
            "process_id": None if data["proc"] == "-" else data["proc"],
            "event_type": None if data["msgid"] == "-" else data["msgid"],
        })
        rest = data["rest"].lstrip()
        # Discard NILVALUE or bracketed structured data, retaining the human/application message.
        if rest.startswith("-"):
            rest = rest[1:].lstrip()
        elif rest.startswith("["):
            depth = 0
            end = 0
            for pos, char in enumerate(rest):
                if char == "[": depth += 1
                elif char == "]":
                    depth -= 1
                    if depth == 0:
                        end = pos + 1
                        break
            rest = rest[end:].lstrip() if end else rest
        parsed["message"] = rest
    else:
        # RFC3164: Mmm dd hh:mm:ss HOST TAG: MSG
        r3164 = re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+(\S+)\s+([^:\s]+):?\s*(.*)$", body, re.S)
        if r3164:
            parsed["hostname"], parsed["app_name"], parsed["message"] = r3164.groups()
        else:
            parsed["message"] = body
    parsed["fields"] = parse_fields(parsed["message"])
    return parsed

def index_record(con, message_id, raw, update_message=True):
    parsed = parse_syslog(raw)
    if update_message:
        con.execute("""UPDATE messages SET facility=?,severity=?,hostname=?,app_name=?,message=?,event_time=?,syslog_version=?,process_id=?,event_type=? WHERE id=?""",
                    (parsed["facility"], parsed["severity"], parsed["hostname"], parsed["app_name"], parsed["message"],
                     parsed["event_time"], parsed["syslog_version"], parsed["process_id"], parsed["event_type"], message_id))
    con.execute("DELETE FROM message_fields WHERE message_id=?", (message_id,))
    con.executemany("INSERT INTO message_fields(message_id,field_name,field_value) VALUES(?,?,?)",
                    [(message_id, key, value) for key, value in parsed["fields"].items()])
    return parsed

def reindex_existing(con):
    # Existing database records gain correct RFC5424 metadata and indexed key=value fields on upgrade.
    rows = con.execute("SELECT id,raw FROM messages WHERE NOT EXISTS (SELECT 1 FROM message_fields f WHERE f.message_id=messages.id)").fetchall()
    for row in rows:
        index_record(con, row["id"], row["raw"])

def store(listener_id, addr, payload):
    raw = payload.decode("utf-8", errors="replace").rstrip("\r\n\x00")
    if not raw:
        return
    parsed = parse_syslog(raw)
    with db() as con:
        cur = con.execute("""INSERT INTO messages(received_at,listener_id,source_ip,source_port,facility,severity,hostname,app_name,message,raw,event_time,syslog_version,process_id,event_type)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                          (now(), listener_id, addr[0], addr[1], parsed["facility"], parsed["severity"], parsed["hostname"],
                           parsed["app_name"], parsed["message"], raw, parsed["event_time"], parsed["syslog_version"],
                           parsed["process_id"], parsed["event_type"]))
        con.executemany("INSERT INTO message_fields(message_id,field_name,field_value) VALUES(?,?,?)",
                        [(cur.lastrowid, key, value) for key, value in parsed["fields"].items()])

def udp_listener(listener_id, port, stop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port)); sock.settimeout(1)
        while not stop.is_set():
            try: data, addr = sock.recvfrom(65535); store(listener_id, addr, data)
            except socket.timeout: pass
            except OSError:
                if not stop.is_set(): raise
    finally: sock.close()

def tcp_listener(listener_id, port, stop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port)); sock.listen(32); sock.settimeout(1)
        while not stop.is_set():
            try:
                conn, addr = sock.accept(); conn.settimeout(1)
                threading.Thread(target=handle_tcp_client, args=(conn, addr, listener_id, stop), daemon=True).start()
            except socket.timeout: pass
            except OSError:
                if not stop.is_set(): raise
    finally: sock.close()

def handle_tcp_client(conn, addr, listener_id, stop):
    buf = b""
    try:
        with conn:
            while not stop.is_set():
                try: chunk = conn.recv(65535)
                except socket.timeout: continue
                if not chunk: break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1); store(listener_id, addr, line)
            if buf: store(listener_id, addr, buf)
    except OSError: pass

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

def token_digest(): return hashlib.sha256(TOKEN.encode()).hexdigest()
def authenticated(handler):
    cookie = SimpleCookie(handler.headers.get("Cookie")); value = cookie.get(COOKIE_NAME)
    return bool(TOKEN and value and hmac.compare_digest(value.value, token_digest()))
def json_response(handler, data, status=200):
    body = json.dumps(data, default=str).encode()
    handler.send_response(status); handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body))); handler.end_headers(); handler.wfile.write(body)
def html_response(handler, body, status=200):
    encoded = body.encode(); handler.send_response(status); handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(encoded))); handler.end_headers(); handler.wfile.write(encoded)

def message_rows(con, query):
    try: limit = min(max(int(query.get("limit", ["100"])[0]), 1), 500)
    except ValueError: limit = 100
    text = query.get("q", [""])[0].strip()
    where, args = [], []
    try: tokens = shlex.split(text)
    except ValueError: tokens = text.split()
    special = {"host": "hostname", "hostname": "hostname", "app": "app_name", "source": "source_ip", "event": "event_type", "type": "event_type"}
    for token in tokens:
        field = re.fullmatch(r"([A-Za-z][A-Za-z0-9_.-]{0,63}):(.*)", token)
        if field and field.group(2):
            key, value = field.group(1).lower(), field.group(2)
            if key in special:
                where.append(f"COALESCE({special[key]}, '') LIKE ?"); args.append(f"%{value}%")
            else:
                where.append("EXISTS (SELECT 1 FROM message_fields f WHERE f.message_id=messages.id AND f.field_name=? AND f.field_value LIKE ?)")
                args.extend((key, f"%{value}%"))
        else:
            where.append("(raw LIKE ? OR hostname LIKE ? OR app_name LIKE ? OR source_ip LIKE ? OR event_type LIKE ?)")
            args.extend([f"%{token}%"] * 5)
    sql = "SELECT * FROM messages" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
    rows = [dict(row) for row in con.execute(sql, [*args, limit])]
    if not rows: return rows
    ids = [row["id"] for row in rows]
    fields = {mid: {} for mid in ids}
    marks = ",".join("?" for _ in ids)
    for row in con.execute(f"SELECT message_id,field_name,field_value FROM message_fields WHERE message_id IN ({marks}) ORDER BY field_name", ids):
        fields[row["message_id"]][row["field_name"]] = row["field_value"]
    for row in rows: row["fields"] = fields[row["id"]]
    return rows

PAGE = '''<!doctype html><html><head><meta charset="utf-8"><title>Syslog Web UI</title><style>
body{font-family:system-ui,sans-serif;background:#101827;color:#e5e7eb;margin:0;padding:24px}main{max-width:1450px;margin:auto}h1{margin-top:0}section{background:#1f2937;padding:18px;border-radius:10px;margin:16px 0}input,select,button{padding:8px;border-radius:6px;border:1px solid #4b5563;background:#111827;color:white}button{cursor:pointer;background:#2563eb;border:0}button.danger{background:#b91c1c}button.field{font-size:12px;padding:3px 6px;margin:2px;background:#374151}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #374151;padding:8px;text-align:left;vertical-align:top;word-break:break-word}th{color:#93c5fd}pre{white-space:pre-wrap;margin:0}.muted{color:#9ca3af;font-size:13px}#messages{max-height:650px;overflow:auto}details{max-width:520px}.pill{background:#0f766e;border-radius:12px;padding:2px 7px;display:inline-block}
</style></head><body><main><h1>Syslog Web UI</h1><p class="muted">RFC5424/RFC3164 parser with indexed key=value fields. Click an extracted field to correlate every matching record.</p>
<section><h2>Listeners</h2><form id="add"><input type="number" name="port" min="1" max="65535" placeholder="Port (e.g. 514)" required><select name="protocol"><option value="udp">UDP</option><option value="tcp">TCP</option></select><button>Add listener</button></form><div id="listeners"></div></section>
<section><h2>Search & correlation</h2><form id="filter"><input name="q" size="65" placeholder="Search text or field filters: username:carapad reply:Access-Accept event:AUTHLOG"><select name="limit"><option>100</option><option>250</option><option>500</option></select><button>Search</button><button type="button" onclick="clearSearch()">Clear</button></form><p class="muted">Field filters are ANDed. Indexed RadiusStack examples: <code>username:</code>, <code>admin:</code>, <code>reply:</code>, <code>nasipaddress:</code>, <code>callingstationid:</code>, <code>result:</code>, <code>action:</code>, <code>ip:</code>. Use <code>event:AUDIT</code> or <code>app:radiusstack-authlog</code> for syslog metadata.</p><div id="messages"></div></section>
</main><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(url,opts={}){let r=await fetch(url,opts);if(!r.ok)throw Error(await r.text());return r.json()}
async function listeners(){let x=await api('/api/listeners');document.querySelector('#listeners').innerHTML='<table><tr><th>Port</th><th>Protocol</th><th>State</th><th>Action</th></tr>'+x.map(v=>`<tr><td>${v.port}</td><td>${v.protocol.toUpperCase()}</td><td>${v.running?'running':'stopped'}</td><td><button class="danger" onclick="removeListener(${v.id})">Remove</button></td></tr>`).join('')+'</table>'}
function wireFields(){document.querySelectorAll('button.field').forEach(b=>b.onclick=()=>{const input=document.querySelector('[name=q]');const clause=b.dataset.key+':"'+b.dataset.value.replaceAll('"','\\"')+'"';input.value=(input.value.trim()?input.value.trim()+' ':'')+clause;messages()})}
async function messages(){let f=new FormData(document.querySelector('#filter')),p=new URLSearchParams(f);let x=await api('/api/messages?'+p);document.querySelector('#messages').innerHTML='<p class="muted">'+x.length+' most recent matching records</p><table><tr><th>Received (UTC)</th><th>Event time</th><th>Source</th><th>Host / App</th><th>Event</th><th>Indexed fields (click to correlate)</th><th>Message</th></tr>'+x.map(v=>{let fields=Object.entries(v.fields||{}).map(([k,val])=>`<button class="field" data-key="${esc(k)}" data-value="${esc(val)}">${esc(k)}=${esc(val)}</button>`).join('');return `<tr><td>${esc(v.received_at)}</td><td>${esc(v.event_time||'-')}</td><td>${esc(v.source_ip)}:${v.source_port}<br><span class="muted">${v.facility??'-'}/${v.severity??'-'}</span></td><td>${esc(v.hostname||'-')}<br>${esc(v.app_name||'')}</td><td><span class="pill">${esc(v.event_type||'-')}</span></td><td>${fields||'-'}</td><td><pre>${esc(v.message)}</pre><details><summary>Raw</summary><pre>${esc(v.raw)}</pre></details></td></tr>`}).join('')+'</table>';wireFields()}
function clearSearch(){document.querySelector('[name=q]').value='';messages()} async function removeListener(id){if(confirm('Stop and delete this listener?')){await api('/api/listeners/'+id,{method:'DELETE'});await listeners()}}
document.querySelector('#add').onsubmit=async e=>{e.preventDefault();try{await api('/api/listeners',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(e.target)))});e.target.reset();await listeners()}catch(e){alert(e.message)}};document.querySelector('#filter').onsubmit=e=>{e.preventDefault();messages()};listeners();messages();setInterval(messages,5000);
</script></body></html>'''
LOGIN = '''<!doctype html><title>Syslog Web UI — Sign in</title><style>body{font-family:system-ui;background:#101827;color:#e5e7eb;display:grid;place-items:center;height:80vh}form{background:#1f2937;padding:25px;border-radius:10px}input,button{display:block;padding:10px;margin:10px 0;background:#111827;color:white;border:1px solid #4b5563;border-radius:6px}button{background:#2563eb}</style><form method="post" action="/login"><h1>Syslog Web UI</h1><input name="token" type="password" placeholder="Admin token" autofocus required><button>Sign in</button></form>'''

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): print("web", self.address_string(), fmt % args)
    def require_auth(self):
        if authenticated(self): return True
        if self.path.startswith('/api/'): json_response(self, {"error": "unauthorized"}, 401)
        else: html_response(self, LOGIN, 401)
        return False
    def do_GET(self):
        path = urlparse(self.path)
        if path.path == '/healthz': return json_response(self, {"status": "ok"})
        if not self.require_auth(): return
        if path.path == '/': return html_response(self, PAGE)
        if path.path == '/api/listeners':
            with db() as con: rows = [dict(r) for r in con.execute("SELECT * FROM listeners ORDER BY port, protocol")]
            with workers_lock:
                for row in rows: row['running'] = row['id'] in workers and workers[row['id']][1].is_alive()
            return json_response(self, rows)
        if path.path == '/api/messages':
            with db() as con: return json_response(self, message_rows(con, parse_qs(path.query)))
        return json_response(self, {"error": "not found"}, 404)
    def do_POST(self):
        path = urlparse(self.path)
        if path.path == '/login':
            length = int(self.headers.get('Content-Length', '0')); form = parse_qs(self.rfile.read(length).decode())
            if TOKEN and hmac.compare_digest(form.get('token', [''])[0], TOKEN):
                self.send_response(302); self.send_header('Set-Cookie', f'{COOKIE_NAME}={token_digest()}; HttpOnly; SameSite=Strict; Path=/'); self.send_header('Location', '/'); self.end_headers()
            else: html_response(self, LOGIN, 401)
            return
        if not self.require_auth(): return
        if path.path == '/api/listeners':
            listener_id = None
            try:
                length = int(self.headers.get('Content-Length', '0')); data = json.loads(self.rfile.read(length)); port = int(data['port']); protocol = data['protocol'].lower()
                if not (1 <= port <= 65535) or protocol not in ('udp', 'tcp'): raise ValueError('Port must be 1-65535 and protocol udp or tcp')
                with db() as con:
                    cur = con.execute('INSERT INTO listeners(port,protocol,created_at) VALUES(?,?,?)', (port, protocol, now())); listener_id = cur.lastrowid
                    row = con.execute('SELECT * FROM listeners WHERE id=?', (listener_id,)).fetchone()
                start_listener(row); time.sleep(.1)
                with workers_lock: running = workers[listener_id][1].is_alive()
                if not running: raise RuntimeError('could not bind listener')
                return json_response(self, dict(row), 201)
            except sqlite3.IntegrityError: return json_response(self, {'error': 'This port/protocol listener already exists'}, 409)
            except Exception as exc:
                if listener_id:
                    stop_listener(listener_id)
                    with db() as con: con.execute('DELETE FROM listeners WHERE id=?', (listener_id,))
                return json_response(self, {'error': str(exc)}, 400)
        return json_response(self, {'error': 'not found'}, 404)
    def do_DELETE(self):
        if not self.require_auth(): return
        found = re.fullmatch(r'/api/listeners/(\d+)', urlparse(self.path).path)
        if not found: return json_response(self, {'error': 'not found'}, 404)
        listener_id = int(found.group(1)); stop_listener(listener_id)
        with db() as con: con.execute('DELETE FROM listeners WHERE id=?', (listener_id,))
        return json_response(self, {'deleted': listener_id})

def main():
    if not TOKEN: raise SystemExit('SYSLOG_UI_TOKEN must be set to a long random value.')
    setup_db()
    with db() as con: saved = list(con.execute("SELECT * FROM listeners WHERE enabled=1"))
    for row in saved: start_listener(row)
    server = ThreadingHTTPServer((WEB_HOST, WEB_PORT), Handler)
    print(f'Syslog UI listening on http://{WEB_HOST}:{WEB_PORT}')
    server.serve_forever()
if __name__ == '__main__': main()
