#!/usr/bin/env python3
"""
sysmon_server.py - watch several machines on one web page.

Every sysmon.py started with --connect sends its live view here, and the page shows
all of them side by side, updating every second. Only the standard library is needed.

    python sysmon_server.py                        # listen on port 8765
    python sysmon_server.py --port 9000
    python sysmon.py --connect 192.168.1.10:8765   # on each machine to watch

Then open http://192.168.1.10:8765/ in a browser. Monitoring tools can read every
session's latest data as JSON from http://192.168.1.10:8765/api/sessions.

With --password (or the SYSMON_PASSWORD environment variable) the page, the JSON and
sending reports all need that password; sysmon.py takes the same --password. On its own
the password isn't encryption: it and the reports cross the network readable to anyone
who can capture the traffic. --cert and --key make the server speak HTTPS, which encrypts
both; sysmon.py then needs --server-cert with a copy of the certificate.

    python sysmon_server.py --cert sysmon.crt --key sysmon.key --password ...
    python sysmon.py --connect 192.168.1.10:8765 --server-cert sysmon.crt --password ...
"""

from __future__ import annotations

__version__ = "1.0.0"  # keep equal to sysmon.py's; this script doesn't import it, to run without psutil

import argparse
import base64
import hashlib
import hmac
import html
import json
import os
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_PORT = 8765
MAX_REPORT = 256 << 10  # bytes; a real report is ~12 KB on a 20-thread machine, more on bigger ones
MAX_SESSIONS = 200      # with MAX_REPORT: at most ~50 MB of reports kept
FORGET_AFTER = 3600     # seconds a session that stopped reporting stays listed


def missing_after(interval):
    """Seconds without a report before a session counts as not responding."""
    return 3 * interval + 2


def public_id(session):
    """The id a session is listed under. The id sysmon.py sends stays secret: whoever knows it
    can send reports in that session's name, or end it."""
    return hashlib.sha256(session.encode()).hexdigest()[:16]


class Sessions:
    """The latest report of every sysmon.py session, by the (secret) id sysmon.py sends."""

    def __init__(self):
        self.lock = threading.Lock()
        # session id -> (time received, entry, snapshot and lines as UTF-8 JSON). Kept as text:
        # a report of many tiny values takes up to 25 times its size as Python objects.
        self.latest = {}

    def report(self, report, address, now=None):
        """Store a report sent by sysmon.py from `address`; ValueError if it isn't one."""
        now = time.time() if now is None else now
        session = report.get("session") if isinstance(report, dict) else None
        if not isinstance(session, str) or not 0 < len(session) <= 64:
            raise ValueError("report without a session id")
        if report.get("ended") is True:  # sysmon.py was closed
            with self.lock:
                self.latest.pop(session, None)
            return
        interval, snapshot, lines = report.get("interval"), report.get("snapshot"), report.get("lines")
        if not isinstance(interval, (int, float)) or not 0 < interval <= 86400:
            raise ValueError("report without a valid interval")
        if not isinstance(snapshot, dict):
            raise ValueError("report without a snapshot")
        if not isinstance(lines, list) or not all(isinstance(line, str) for line in lines):
            raise ValueError("report without the screen lines")
        system = snapshot.get("system") if isinstance(snapshot.get("system"), dict) else {}
        host = str(system.get("host") or address)[:100]
        entry = {"session": public_id(session), "host": host, "address": address, "interval": interval,
                 "last_report": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now))}
        # Anything that would make the list invalid JSON, and so break the page for everyone, is
        # refused here: NaN (allow_nan) and lone surrogates such as "\ud800" (encode()).
        data = json.dumps({"snapshot": snapshot, "lines": lines}, ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False).encode()
        with self.lock:
            self._forget(now)
            if session not in self.latest:
                if len(self.latest) >= MAX_SESSIONS:
                    raise ValueError(f"already {MAX_SESSIONS} sessions")
                # sysmon.py restarted on that machine: its old session is the one that stopped.
                for old, (seen, previous, _) in list(self.latest.items()):
                    if previous["host"] == host and now - seen > missing_after(previous["interval"]):
                        del self.latest[old]
            self.latest[session] = (now, entry, data)

    def _sorted(self, now):
        """[(entry with "live" and "seconds_since_report", JSON text)] of every session, by host."""
        now = time.time() if now is None else now
        with self.lock:
            self._forget(now)
            items = [({**entry, "live": now - seen <= missing_after(entry["interval"]),
                       "seconds_since_report": round(now - seen, 1)}, data)
                     for seen, entry, data in self.latest.values()]
        return sorted(items, key=lambda item: (item[0]["host"].lower(), item[0]["session"]))

    def listing(self, now=None):
        """Every session, sorted by host, with whether it is still reporting (without its report)."""
        return [entry for entry, _ in self._sorted(now)]

    def listing_json(self, now=None):
        """listing() with each session's snapshot and lines, as the UTF-8 JSON /api/sessions serves.
        Pieced together from the stored text: nothing is unpacked into Python objects again."""
        return b"[" + b",".join(json.dumps(entry)[:-1].encode() + b"," + data[1:]
                                for entry, data in self._sorted(now)) + b"]"

    def _forget(self, now):
        for session, (seen, entry, _) in list(self.latest.items()):
            if now - seen > missing_after(entry["interval"]) + FORGET_AFTER:
                del self.latest[session]


class Handler(BaseHTTPRequestHandler):
    """GET / is the web page, GET /api/sessions the JSON, POST /report takes a sysmon.py update."""

    server_version = "sysmon-server"
    timeout = 10  # drop connections that stall mid-request

    def do_GET(self):
        if not self._allowed():
            return self._ask_for_password()
        path = self.path.split("?")[0]
        if path == "/":
            page = PAGE.replace("$CONNECT", html.escape(self.server.connect_command))
            self._reply(200, page.encode(), "text/html; charset=utf-8")
        elif path == "/api/sessions":
            self._reply(200, self.server.sessions.listing_json(), "application/json")
        else:
            self._reply(404, b"Not found\n")

    def do_POST(self):
        if not self._allowed():
            return self._ask_for_password()
        if self.path != "/report":
            return self._reply(404, b"Not found\n")
        # A web page can post form data or plain text to another site unasked, and the browser
        # adds the password it remembers for it; JSON needs this server's consent, which it never
        # gives. So this keeps a page someone on the network visits from adding fake machines.
        if self.headers.get_content_type() != "application/json":
            return self._reply(415, b"Reports must be sent as application/json\n")
        try:
            length = int(self.headers.get("Content-Length", 0))
            if not 0 <= length <= MAX_REPORT:
                return self._reply(413, b"Report too large\n")
            self.server.sessions.report(json.loads(self.rfile.read(length)), self.client_address[0])
        except (ValueError, RecursionError) as error:  # also malformed or too deeply nested JSON
            return self._reply(400, f"{error}\n".encode())
        self._reply(204)

    def _allowed(self):
        """Whether the request has the server's password (HTTP Basic auth, any user name)."""
        if not self.server.password:
            return True
        scheme, _, encoded = self.headers.get("Authorization", "").partition(" ")
        try:
            given = base64.b64decode(encoded, validate=True).partition(b":")[2]
        except ValueError:  # not base64
            return False
        return scheme.lower() == "basic" and hmac.compare_digest(given, self.server.password.encode())

    def _ask_for_password(self):
        # Browsers answer this by asking for a user name and password.
        self._reply(401, b"Password required\n",
                    headers={"WWW-Authenticate": 'Basic realm="sysmon", charset="UTF-8"'})

    def _reply(self, status, body=b"", content_type="text/plain; charset=utf-8", headers=None):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_request(self, code="-", size="-"):
        pass  # every machine reports every second; only errors are worth printing


class Server(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # A client that hangs up, or fails the TLS handshake (http:// to an HTTPS server, or a
        # browser that doesn't trust the certificate yet), is routine: no traceback for those.
        if not isinstance(sys.exc_info()[1], (ConnectionError, ssl.SSLError)):
            super().handle_error(request, client_address)


def make_server(bind, port, connect_hint=None, password=None, cert=None, key=None):
    """A server ready to serve_forever(), speaking HTTPS when given a certificate and its private
    key (PEM files). connect_hint is the IP:PORT the page tells sysmon.py to --connect to; port 0
    picks a free port (the tests use that)."""
    context = None
    if cert:  # first, so a bad file fails before the port is taken
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
    server = Server((bind, port), Handler)
    if context:
        # The handshake then happens in each request's own thread, with its timeout, instead of in
        # the loop that accepts connections, where one stalled client would hold up everyone.
        server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    server.sessions = Sessions()
    server.password = password or None
    address = connect_hint or f"{bind or lan_address()}:{server.server_address[1]}"
    server.url = f"{'https' if cert else 'http'}://{address}/"
    server.connect_command = (f"python sysmon.py --connect {address}"
                              + (f" --server-cert {os.path.basename(cert)}" if cert else "")
                              + (" --password …" if server.password else ""))
    return server


def lan_address():
    """This machine's address on the local network, as other machines reach it."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(("192.0.2.1", 9))  # picks the outgoing interface; sends nothing
            return probe.getsockname()[0]
        except OSError:
            return socket.gethostname()


def main():
    parser = argparse.ArgumentParser(
        description="Shows every sysmon.py started with --connect on one web page.")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                        help=f"port to listen on (default: {DEFAULT_PORT})")
    parser.add_argument("--bind", default="", metavar="ADDRESS",
                        help="listen on this IPv4 address only (default: every network interface; "
                             "IPv6 isn't supported yet)")
    parser.add_argument("--password", default=os.environ.get("SYSMON_PASSWORD"),
                        help="require this password to view the page and to send reports "
                             "(default: the SYSMON_PASSWORD environment variable, if set)")
    parser.add_argument("--cert", metavar="FILE",
                        help="serve HTTPS with this certificate (PEM file); needs --key")
    parser.add_argument("--key", metavar="FILE",
                        help="the certificate's private key (PEM file); it never leaves this machine")
    parser.add_argument("--version", action="version", version=f"sysmon_server {__version__}")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("the port must be 0-65535")
    if bool(args.cert) != bool(args.key):
        parser.error("--cert and --key go together")
    for path in filter(None, (args.cert, args.key)):  # the ssl module's own error doesn't name the file
        if not os.path.isfile(path):
            parser.error(f"no such file: {path}")
    try:
        server = make_server(args.bind, args.port, password=args.password, cert=args.cert, key=args.key)
    except ssl.SSLError as error:  # before OSError, which it is a kind of
        sys.exit(f"Can't use {args.cert} and {args.key} ({error.reason or error}): both must be "
                 "PEM files, and the key the certificate's own")
    except OSError as error:
        sys.exit(f"Can't listen on port {args.port}: {error.strerror}")
    print(f"sysmon server: open {server.url} in a browser")
    if args.cert:
        print(f"HTTPS: copy {args.cert} (only the certificate, not the key) to each machine to watch.")
    print(f"On each machine to watch, run:  {server.connect_command}")
    if server.password:
        print("Password protected: the browser asks for it (any user name works).")
    else:
        print("No password set: anyone who can reach this port can see and send reports (see --password).")
    if not args.cert:
        print("No HTTPS: the reports and any password can be read on the network (see --cert).")
    print("Ctrl+C stops the server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sysmon sessions</title>
<!-- The logo (Assets/Img/SysMon-logo/svg/sysmon-icon.svg) is inlined: this script stays a single file. -->
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect x='2' y='2' width='96' height='96' rx='22' fill='%230b1116' stroke='%23243039' stroke-width='1'/%3E%3Cpath d='M14 54 H31 L39 36 L50 72 L60 24 L68 54 H86' fill='none' stroke='%233ddc97' stroke-width='7' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>
  :root { color-scheme: dark; --bg: #0c0c0c; --panel: #161616; --line: #2c2c2c; --text: #cccccc;
          --muted: #8a8a8a; --live: #23d18b; --lost: #f14c4c; }
  body { margin: 0; padding: 16px; background: var(--bg); color: var(--text);
         font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
  header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 16px; margin-bottom: 16px; }
  h1 { display: flex; align-items: center; gap: 10px; margin: 0; font-size: 18px; }
  .logo { width: 28px; height: 28px; align-self: center; }
  code, pre { font-family: "Cascadia Mono", Consolas, "DejaVu Sans Mono", Menlo, monospace; }
  .muted { color: var(--muted); }
  #sessions { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 760px), 1fr)); gap: 16px; }
  details { min-width: 0; background: var(--panel); border: 1px solid var(--line); border-radius: 6px; }
  summary { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 12px; padding: 8px 12px;
            cursor: pointer; list-style: none; }
  summary::-webkit-details-marker { display: none; }
  summary::before { content: "▸"; color: var(--muted); }
  details[open] > summary::before { content: "▾"; }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--live); }
  .host { font-weight: 600; }
  .state { color: var(--lost); }
  .lost .dot { background: var(--lost); }
  .lost pre { opacity: .45; }
  pre { margin: 0; padding: 10px 12px 12px; border-top: 1px solid var(--line); overflow-x: auto;
        font-size: 13px; line-height: 1.25; }
</style>
</head>
<body>
<header>
  <h1><svg class="logo" viewBox="0 0 100 100" aria-hidden="true"><rect x="2" y="2" width="96" height="96" rx="22" fill="#0b1116" stroke="#243039" stroke-width="1"/><path d="M14 54 H31 L39 36 L50 72 L60 24 L68 54 H86" fill="none" stroke="#3ddc97" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/></svg>sysmon sessions</h1>
  <span id="note" class="muted">Loading…</span>
</header>
<p id="empty" hidden>No sessions yet. On each machine to watch, run
  <code>$CONNECT</code></p>
<main id="sessions"></main>
<script>
// Terminal colors (the ANSI codes sysmon.py draws with) as CSS colors.
const PALETTE = {
  30: "#000000", 31: "#cd3131", 32: "#0dbc79", 33: "#e5e510", 34: "#2472c8", 35: "#bc3fbc", 36: "#11a8cd", 37: "#e5e5e5",
  90: "#767676", 91: "#f14c4c", 92: "#23d18b", 93: "#f5f543", 94: "#3b8eea", 95: "#d670d6", 96: "#29b8db", 97: "#ffffff",
};
const list = document.getElementById("sessions");
const note = document.getElementById("note");
const empty = document.getElementById("empty");
const cards = new Map();

function escapeHtml(text) {
  return text.replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"})[c]);
}

// One line of sysmon's screen as HTML. split() with a capture group returns text and codes
// taking turns: "text, codes, text, codes, ...", e.g. "1;36" for bold cyan.
function ansiToHtml(line) {
  let html = "", style = {};
  line.split(/\x1b\[([\d;]*)m/).forEach((part, i) => {
    if (i % 2 === 0) {  // text
      const css = (style.color ? `color:${style.color};` : "") + (style.bold ? "font-weight:bold;" : "")
                + (style.dim ? "opacity:.6;" : "");
      html += css ? `<span style="${css}">${escapeHtml(part)}</span>` : escapeHtml(part);
    } else if (!/^[34]8;/.test(part)) {  // codes; 256-color and RGB ones are left out
      for (const code of part.split(";").map(Number)) {
        if (code === 0) style = {};
        else if (code === 1) style.bold = true;
        else if (code === 2) style.dim = true;
        else if (PALETTE[code]) style.color = PALETTE[code];
      }
    }
  });
  return html;
}

// "12 s", "5 min", "2 h"
function ago(seconds) {
  return seconds < 90 ? `${Math.round(seconds)} s` : seconds < 5400 ? `${Math.round(seconds / 60)} min`
       : `${Math.round(seconds / 3600)} h`;
}

// The card of a session, made the first time it's seen and reused after that.
function cardFor(id) {
  if (!cards.has(id)) {
    const card = document.createElement("details");
    card.open = true;
    card.innerHTML = '<summary><span class="dot"></span><span class="host"></span><span class="muted address"></span>'
                   + '<span class="muted os"></span><span class="load"></span><span class="state"></span></summary><pre></pre>';
    cards.set(id, card);
  }
  return cards.get(id);
}

function fill(card, session) {
  // Only text changes in the summary, so a click on it is never lost to a redraw.
  const set = (name, text) => { card.querySelector("." + name).textContent = text; };
  const snapshot = session.snapshot, cpu = (snapshot.cpu || {}).usage_percent, ram = (snapshot.memory || {}).percent;
  set("host", session.host);
  set("address", session.address);
  set("os", (snapshot.system || {}).os || "");
  set("load", [typeof cpu === "number" ? `CPU ${cpu.toFixed(0)} %` : "",
               typeof ram === "number" ? `RAM ${ram.toFixed(0)} %` : ""].filter(Boolean).join("   "));
  set("state", session.live ? "" : `no report for ${ago(session.seconds_since_report)}`);
  card.classList.toggle("lost", !session.live);
  card.querySelector("pre").innerHTML = session.lines.map(ansiToHtml).join("\n");
}

async function refresh() {
  let sessions;
  try {
    // From the origin: a page opened as http://user:password@host/ can't fetch relative URLs.
    const response = await fetch(location.origin + "/api/sessions", {cache: "no-store"});
    if (!response.ok) {
      throw new Error(response.status === 401 ? "Password not accepted: reload the page to enter it again"
                                              : `The server answered ${response.status} ${response.statusText}`);
    }
    sessions = await response.json();
  } catch (error) {
    // fetch() throws a TypeError when the server can't be reached at all
    note.textContent = error instanceof TypeError ? "Can't reach the server, retrying…" : error.message;
    return;
  }
  const shown = new Set();
  sessions.forEach((session, i) => {
    const card = cardFor(session.session);
    fill(card, session);
    if (list.children[i] !== card) list.insertBefore(card, list.children[i] || null);
    shown.add(session.session);
  });
  for (const [id, card] of cards) {
    if (!shown.has(id)) { card.remove(); cards.delete(id); }
  }
  const live = sessions.filter(session => session.live).length;
  note.textContent = sessions.length
    ? `${sessions.length} session${sessions.length > 1 ? "s" : ""}, ${live} live · updated ${new Date().toLocaleTimeString()}`
    : "";
  empty.hidden = sessions.length > 0;
}

(async function loop() { await refresh(); setTimeout(loop, 1000); })();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
