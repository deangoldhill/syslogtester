#!/usr/bin/env python3
"""Small, dependency-free syslog collector and web UI."""
import hashlib
import hmac
import json
import os
import re
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
  FOREIGN KEY(listener_id) REFERENCES listeners(id)
);
CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_listener ON messages(listener_id);
"""

def db():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    return con

def setup_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    with db() as con:
        con.executescript(SCHEMA)

def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

def parse_syslog(raw):
    """Best-effort RFC3164/RFC5424 metadata extraction while retaining original raw text."""
    facility = severity = None
    m = re.match(r"^<(\d{1,3})>(.*)$", raw, re.S)
    body = raw
    if m:
        pri = int(m.group(1)); facility, severity, body = pri // 8, pri % 8, m.group(2)
    hostname = app_name = None
    # RFC5424: VERSION TIMESTAMP HOST APP ... MSG
    m5424 = re.match(r"^\d{1,2}\s+\S+\s+(\S+)\s+(\S+)(?:\s+\S+){0,4}\s*(.*)$", body, re.S)
    if m5424:
        hostname, app_name, message = m5424.groups()
    else:
        # RFC3164: Mmm dd hh:mm:ss HOST TAG: MSG
        m3164 = re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+(\S+)\s+([^:\s]+):?\s*(.*)$", body, re.S)
        if m3164:
            hostname, app_name, message = m3164.groups()
        else:
            message = body
    return facility, severity, hostname, app_name, message

def store(listener_id, addr, payload):
    raw = payload.decode("utf-8", errors="replace").rstrip("\r\n\x00")
    if not raw:
        return
    facility, severity, hostname, app_name, message = parse_syslog(raw)
    with db() as con:
        con.execute("""INSERT INTO messages(received_at,listener_id,source_ip,source_port,facility,severity,hostname,app_name,message,raw)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (now(), listener_id, addr[0], addr[1], facility, severity, hostname, app_name, message, raw))

def udp_listener(listener_id, port, stop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port)); sock.settimeout(1)
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(65535); store(listener_id, addr, data)
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
        stop = threading.Event()
        target = udp_listener if protocol == "udp" else tcp_listener
        thread = threading.Thread(target=target, args=(listener_id, port, stop), name=f"syslog-{protocol}-{port}", daemon=True)
        workers[listener_id] = (stop, thread); thread.start()

def stop_listener(listener_id):
    with workers_lock:
        entry = workers.pop(listener_id, None)
    if entry: entry[0].set(); entry[1].join(timeout=2)

def token_digest(): return hashlib.sha256(TOKEN.encode()).hexdigest()
def authenticated(handler):
    if not TOKEN: return False
    cookie = SimpleCookie(handler.headers.get("Cookie")); value = cookie.get(COOKIE_NAME)
    return bool(value and hmac.compare_digest(value.value, token_digest()))

def json_response(handler, data, status=200):
    body = json.dumps(data, default=str).encode()
    handler.send_response(status); handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body))); handler.end_headers(); handler.wfile.write(body)

def html_response(handler, body, status=200):
    encoded = body.encode(); handler.send_response(status); handler.send_header("Content-Type", "text/html; charset=utf-8"); handler.send_header("Content-Length", str(len(encoded))); handler.end_headers(); handler.wfile.write(encoded)

PAGE = '''<!doctype html><html><head><meta charset="utf-8"><title>Syslog Web UI</title><style>
body{font-family:system-ui,sans-serif;background:#101827;color:#e5e7eb;margin:0;padding:24px}main{max-width:1300px;margin:auto}h1{margin-top:0}section{background:#1f2937;padding:18px;border-radius:10px;margin:16px 0}input,select,button{padding:8px;border-radius:6px;border:1px solid #4b5563;background:#111827;color:white}button{cursor:pointer;background:#2563eb;border:0}button.danger{background:#b91c1c}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #374151;padding:8px;text-align:left;vertical-align:top;word-break:break-word}th{color:#93c5fd}pre{white-space:pre-wrap;margin:0}.muted{color:#9ca3af}#messages{max-height:600px;overflow:auto}
</style></head><body><main><h1>Syslog Web UI</h1><p class="muted">Listeners bind to all host interfaces. Records are stored in SQLite.</p>
<section><h2>Listeners</h2><form id="add"><input type="number" name="port" min="1" max="65535" placeholder="Port (e.g. 514)" required><select name="protocol"><option value="udp">UDP</option><option value="tcp">TCP</option></select><button>Add listener</button></form><div id="listeners"></div></section>
<section><h2>Messages</h2><form id="filter"><input name="q" placeholder="Search raw message, host, app, IP"><select name="limit"><option>100</option><option>250</option><option>500</option></select><button>Refresh</button></form><div id="messages"></div></section>
</main><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(url,opts={}){let r=await fetch(url,opts);if(!r.ok)throw Error(await r.text());return r.json()}
async function listeners(){let x=await api('/api/listeners');document.querySelector('#listeners').innerHTML='<table><tr><th>Port</th><th>Protocol</th><th>State</th><th>Action</th></tr>'+x.map(v=>`<tr><td>${v.port}</td><td>${v.protocol.toUpperCase()}</td><td>${v.running?'running':'stopped'}</td><td><button class="danger" onclick="removeListener(${v.id})">Remove</button></td></tr>`).join('')+'</table>'}
async function messages(){let f=new FormData(document.querySelector('#filter')),p=new URLSearchParams(f);let x=await api('/api/messages?'+p);document.querySelector('#messages').innerHTML='<p class="muted">'+x.length+' most recent matching records</p><table><tr><th>Received (UTC)</th><th>Source</th><th>Pri</th><th>Host / App</th><th>Message</th></tr>'+x.map(v=>`<tr title="${esc(v.raw)}"><td>${esc(v.received_at)}</td><td>${esc(v.source_ip)}:${v.source_port}</td><td>${v.facility??'-'}/${v.severity??'-'}</td><td>${esc(v.hostname||'-')}<br>${esc(v.app_name||'')}</td><td><pre>${esc(v.message)}</pre></td></tr>`).join('')+'</table>'}
async function removeListener(id){if(confirm('Stop and delete this listener?')){await api('/api/listeners/'+id,{method:'DELETE'});await listeners()}}
document.querySelector('#add').onsubmit=async e=>{e.preventDefault();try{await api('/api/listeners',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(e.target)))});e.target.reset();await listeners()}catch(e){alert(e.message)}};document.querySelector('#filter').onsubmit=e=>{e.preventDefault();messages()};listeners();messages();setInterval(messages,5000);
</script></body></html>'''
LOGIN = '''<!doctype html><title>Syslog Web UI — Sign in</title><style>body{font-family:system-ui;background:#101827;color:#e5e7eb;display:grid;place-items:center;height:80vh}form{background:#1f2937;padding:25px;border-radius:10px}input,button{display:block;padding:10px;margin:10px 0;background:#111827;color:white;border:1px solid #4b5563;border-radius:6px}button{background:#2563eb}</style><form method="post" action="/login"><h1>Syslog Web UI</h1><input name="token" type="password" placeholder="Admin token" autofocus required><button>Sign in</button></form>'''

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): print("web", self.address_string(), fmt % args)
    def require_auth(self):
        if authenticated(self): return True
        if self.path.startswith('/api/'):
            json_response(self, {"error":"unauthorized"}, 401)
        else:
            html_response(self, LOGIN, 401)
        return False
    def do_GET(self):
        path = urlparse(self.path)
        if path.path == '/healthz': return json_response(self, {"status":"ok"})
        if not self.require_auth(): return
        if path.path == '/': return html_response(self, PAGE)
        if path.path == '/api/listeners':
            with db() as con: rows = [dict(r) for r in con.execute("SELECT * FROM listeners ORDER BY port, protocol")]
            with workers_lock:
                for r in rows: r['running'] = r['id'] in workers and workers[r['id']][1].is_alive()
            return json_response(self, rows)
        if path.path == '/api/messages':
            p = parse_qs(path.query); limit = min(max(int(p.get('limit',['100'])[0]),1),500); q=p.get('q',[''])[0].strip()
            sql="SELECT * FROM messages"; args=[]
            if q: sql += " WHERE raw LIKE ? OR hostname LIKE ? OR app_name LIKE ? OR source_ip LIKE ?"; args=[f'%{q}%']*4
            sql += " ORDER BY id DESC LIMIT ?"; args.append(limit)
            with db() as con: return json_response(self, [dict(r) for r in con.execute(sql,args)])
        return json_response(self, {"error":"not found"}, 404)
    def do_POST(self):
        path=urlparse(self.path)
        if path.path == '/login':
            length=int(self.headers.get('Content-Length','0')); form=parse_qs(self.rfile.read(length).decode())
            if TOKEN and hmac.compare_digest(form.get('token',[''])[0], TOKEN):
                self.send_response(302); self.send_header('Set-Cookie',f'{COOKIE_NAME}={token_digest()}; HttpOnly; SameSite=Strict; Path=/'); self.send_header('Location','/'); self.end_headers()
            else: html_response(self, LOGIN, 401)
            return
        if not self.require_auth(): return
        if path.path == '/api/listeners':
            try:
                length=int(self.headers.get('Content-Length','0')); data=json.loads(self.rfile.read(length)); port=int(data['port']); protocol=data['protocol'].lower()
                if not (1 <= port <= 65535) or protocol not in ('udp','tcp'): raise ValueError('Port must be 1-65535 and protocol udp or tcp')
                with db() as con:
                    cur=con.execute('INSERT INTO listeners(port,protocol,created_at) VALUES(?,?,?)',(port,protocol,now())); listener_id=cur.lastrowid
                    row=con.execute('SELECT * FROM listeners WHERE id=?',(listener_id,)).fetchone()
                start_listener(row); time.sleep(.1)
                with workers_lock: running=workers[listener_id][1].is_alive()
                if not running: raise RuntimeError('could not bind listener')
                return json_response(self, dict(row), 201)
            except sqlite3.IntegrityError: return json_response(self, {'error':'This port/protocol listener already exists'},409)
            except Exception as exc:
                if 'listener_id' in locals():
                    stop_listener(listener_id)
                    with db() as con: con.execute('DELETE FROM listeners WHERE id=?',(listener_id,))
                return json_response(self, {'error':str(exc)},400)
        return json_response(self, {'error':'not found'},404)
    def do_DELETE(self):
        if not self.require_auth(): return
        m=re.fullmatch(r'/api/listeners/(\d+)',urlparse(self.path).path)
        if not m: return json_response(self, {'error':'not found'},404)
        listener_id=int(m.group(1)); stop_listener(listener_id)
        with db() as con: con.execute('DELETE FROM listeners WHERE id=?',(listener_id,))
        return json_response(self, {'deleted':listener_id})

def main():
    if not TOKEN:
        raise SystemExit('SYSLOG_UI_TOKEN must be set to a long random value.')
    setup_db()
    with db() as con: saved=list(con.execute("SELECT * FROM listeners WHERE enabled=1"))
    for row in saved: start_listener(row)
    server=ThreadingHTTPServer((WEB_HOST, WEB_PORT),Handler)
    print(f'Syslog UI listening on http://{WEB_HOST}:{WEB_PORT}')
    server.serve_forever()
if __name__ == '__main__': main()
