#!/usr/bin/env python3
"""honeypot-lite — a real-time trap for scanners and brute-forcers.

Three low-interaction traps on ports you choose:
  ssh-banner  — greets scanners with an OpenSSH banner, captures what they send
  telnet-auth — presents `login:` / `Password:` and records every credential
                scripts type into it (the juiciest feed)
  http        — serves a convincing empty site and logs every path, header
                and user-agent that touches it

Every event prints to a live feed the moment it lands and is appended to a
JSONL file for forensics. Ctrl+C prints a session summary.

DEFENSIVE TOOL, RUN AT YOUR OWN RESPONSIBILITY: point this only at networks
and machines you own or are authorized to test. See the README's ethics
section before deploying.
"""

import argparse
import json
import socketserver
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
PAGE = (b"<!DOCTYPE html><html><head><title>Index of /</title></head>"
        b"<body><h1>Index of /</h1><hr></body></html>")


class Store:
    """Thread-safe JSONL forensics + live console feed."""

    def __init__(self, path=None, feed=True):
        self.path = path
        self.feed = feed
        self.lock = threading.Lock()
        self.counts = {"ssh": 0, "telnet": 0, "http": 0}
        self.ips = {}

    def record(self, kind, **data):
        rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "kind": kind, **data}
        with self.lock:
            self.counts[kind] = self.counts.get(kind, 0) + 1
            ip = data.get("ip")
            if ip:
                self.ips[ip] = self.ips.get(ip, 0) + 1
            if self.path:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            if self.feed:
                self._print(rec)
        return rec

    def _print(self, rec):
        stamp = rec["ts"][11:19]
        kind = rec["kind"].upper().ljust(6)
        ip = rec.get("ip", "-").ljust(16)
        if rec["kind"] == "ssh":
            detail = f"banner-probe: {rec.get('payload', '')[:60]!r}"
        elif rec["kind"] == "telnet":
            detail = f"user={rec.get('user', '')!r} password={rec.get('password', '')!r}"
        else:
            detail = f"{rec.get('method', '')} {rec.get('path', '')} ua={rec.get('user_agent', '')!r}"
        print(f"\x1b[90m{stamp}\x1b[0m \x1b[33m{kind}\x1b[0m \x1b[36m{ip}\x1b[0m {detail}", flush=True)

    def summary(self):
        top = ", ".join(f"{ip} x{n}" for ip, n in sorted(self.ips.items(), key=lambda kv: -kv[1])[:5])
        return (f"ssh {self.counts.get('ssh', 0)} | telnet {self.counts.get('telnet', 0)} | "
                f"http {self.counts.get('http', 0)} — top: {top or 'nobody showed up'}")


STORE = None


def bind_store(store):
    global STORE
    STORE = store


class SSHTrap(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(BANNER)
            self.request.settimeout(6)
            payload = self.request.recv(1024).decode("utf-8", errors="replace").strip()
            STORE.record("ssh", ip=self.client_address[0], payload=payload)
        except (TimeoutError, ConnectionError, OSError):
            STORE.record("ssh", ip=self.client_address[0], payload="<timed out or dropped>")


class TelnetTrap(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(8)
            self.request.sendall(b"Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-56-generic x86_64)\r\n\r\nlogin: ")
            user = self.request.recv(256).decode("utf-8", errors="replace").strip()
            self.request.sendall(b"Password: ")
            password = self.request.recv(256).decode("utf-8", errors="replace").strip()
            STORE.record("telnet", ip=self.client_address[0], user=user, password=password)
            self.request.sendall(b"\r\nAuthentication failure\r\n")
        except (TimeoutError, ConnectionError, OSError):
            STORE.record("telnet", ip=self.client_address[0], user="", password="", note="dropped")


class HTTPTrap(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence the default stderr logging; Store handles it
        pass

    def _record_and_serve(self):
        STORE.record("http", ip=self.client_address[0], method=self.command,
                     path=self.path, user_agent=self.headers.get("User-Agent", ""))
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    do_GET = do_POST = do_HEAD = _record_and_serve


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main(argv=None):
    p = argparse.ArgumentParser(description="real-time low-interaction honeypot")
    p.add_argument("--ssh", type=int, default=2222, help="ssh-banner trap port (default 2222)")
    p.add_argument("--telnet", type=int, default=2323, help="telnet-auth trap port (default 2323)")
    p.add_argument("--http", type=int, default=8080, help="http trap port (default 8080)")
    p.add_argument("--log", default="honeypot.jsonl", help="JSONL forensics file")
    p.add_argument("--quiet", action="store_true", help="no live feed, only the JSONL")
    args = p.parse_args(argv)

    bind_store(Store(args.log, feed=not args.quiet))

    ssh_srv = ReusableTCPServer(("0.0.0.0", args.ssh), SSHTrap)
    tel_srv = ReusableTCPServer(("0.0.0.0", args.telnet), TelnetTrap)
    http_srv = ThreadingHTTPServer(("0.0.0.0", args.http), HTTPTrap)
    servers = [(ssh_srv, "ssh"), (tel_srv, "telnet"), (http_srv, "http")]

    for srv, name in servers:
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
    print(f"traps armed: ssh:{args.ssh} telnet:{args.telnet} http:{args.http} "
          f"— forensics: {args.log} — Ctrl+C to stop", flush=True)

    try:
        threading.Event().wait()   # run until Ctrl+C
    except KeyboardInterrupt:
        pass
    finally:
        for srv, _ in servers:
            srv.shutdown()
        print("\nsession summary:", STORE.summary())
    return 0


if __name__ == "__main__":
    sys.exit(main())
