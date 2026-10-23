#!/usr/bin/env python3
"""
Forward proxy — configurable host/port, protocol filter, domain filter, live log.

Usage:
  python proxy.py
  python proxy.py --host 127.0.0.1 --port 8080
  python proxy.py --protocol https
  python proxy.py --allow-domain "example.com,*.github.com"
  python proxy.py --block-domain "*.ads.com,doubleclick.net"
  acyber.ir | mrmtwoj.ir
"""
import socket, threading, select, argparse, fnmatch
from urllib.parse import urlparse
from datetime import datetime

BUFFER_SIZE = 8192
TIMEOUT     = 30

# ---- runtime config (filled by CLI) ----
CFG = {
    "protocol":       "all",   # all | http | https
    "allow_domains":  [],      # whitelist (empty = allow all)
    "block_domains":  [],      # blacklist
}

# ---------------- helpers ----------------
def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)

def domain_match(host, pattern):
    return fnmatch.fnmatch(host.lower(), pattern.lower())

def domain_ok(host):
    host = host.lower()
    if CFG["allow_domains"] and not any(domain_match(host, p) for p in CFG["allow_domains"]):
        return False
    if any(domain_match(host, p) for p in CFG["block_domains"]):
        return False
    return True

def proto_ok(proto):
    return CFG["protocol"] == "all" or CFG["protocol"] == proto

def deny(client, reason):
    try:
        client.sendall(f"HTTP/1.1 403 Forbidden\r\nX-Deny-Reason: {reason}\r\n\r\n".encode())
    except Exception:
        pass

# ---------------- per-connection handler ----------------
def handle_client(client, addr):
    remote = None
    try:
        # --- read request header ---
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = client.recv(BUFFER_SIZE)
            if not chunk:
                return
            request += chunk

        head = request.split(b"\r\n\r\n", 1)[0].decode(errors="ignore")
        lines = head.split("\r\n")
        method, target, version = lines[0].split(" ", 2)
        headers = lines[1:]

        # ---------- HTTPS (CONNECT tunnel) ----------
        if method.upper() == "CONNECT":
            if not proto_ok("https"):
                log(f"[DENY-PROTO]   HTTPS  {target}  <- {addr[0]}")
                return deny(client, "protocol")
            host, _, port = target.partition(":")
            port = int(port or 443)
            if not domain_ok(host):
                log(f"[DENY-DOMAIN]  HTTPS  {host}  <- {addr[0]}")
                return deny(client, "domain")

            log(f"[HTTPS]        {host}:{port}  <- {addr[0]}")
            remote = socket.create_connection((host, port), timeout=TIMEOUT)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            pair = [client, remote]
            while True:
                r, _, _ = select.select(pair, [], [], TIMEOUT)
                if not r:
                    break
                for s in r:
                    data = s.recv(BUFFER_SIZE)
                    if not data:
                        return
                    (remote if s is client else client).sendall(data)
            return

        # ---------- HTTP ----------
        parsed = urlparse(target)
        if parsed.hostname:                                  # absolute form
            host = parsed.hostname
            port = parsed.port or 80
            path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        else:                                                # origin form
            host_hdr = next((h.split(":", 1)[1].strip()
                             for h in headers if h.lower().startswith("host:")), None)
            if not host_hdr:
                return deny(client, "no-host")
            host, _, port = host_hdr.partition(":")
            port = int(port or 80)
            path = target

        if not proto_ok("http"):
            log(f"[DENY-PROTO]   HTTP   {host}{path}  <- {addr[0]}")
            return deny(client, "protocol")
        if not domain_ok(host):
            log(f"[DENY-DOMAIN]  HTTP   {host}{path}  <- {addr[0]}")
            return deny(client, "domain")

        log(f"[HTTP]         {method} http://{host}:{port}{path}  <- {addr[0]}")

        remote = socket.create_connection((host, port), timeout=TIMEOUT)
        rebuilt = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        remote.sendall(rebuilt.encode() + request.split(b"\r\n\r\n", 1)[1])

        while True:
            data = remote.recv(BUFFER_SIZE)
            if not data:
                break
            client.sendall(data)

    except Exception as e:
        log(f"[ERR] {addr[0]}: {e}")
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception:
            pass
    finally:
        for s in (client, remote):
            if s:
                try: s.close()
                except Exception: pass

# ---------------- entry point ----------------
def main():
    p = argparse.ArgumentParser(description="Forward proxy with filters")
    p.add_argument("--host", default="127.0.0.1",
                   help="Bind IP (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=5090,
                   help="Bind port (default 5090)")
    p.add_argument("--protocol", choices=["all", "http", "https"], default="all",
                   help="Only allow this protocol (default all)")
    p.add_argument("--allow-domain", default="",
                   help="Whitelist, comma-separated, wildcards ok (*.example.com)")
    p.add_argument("--block-domain", default="",
                   help="Blacklist, comma-separated, wildcards ok (*.ads.com)")
    a = p.parse_args()

    CFG["protocol"] = a.protocol
    if a.allow_domain:
        CFG["allow_domains"] = [d.strip() for d in a.allow_domain.split(",") if d.strip()]
    if a.block_domain:
        CFG["block_domains"] = [d.strip() for d in a.block_domain.split(",") if d.strip()]

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.host, a.port))
    srv.listen(200)

    log(f"Proxy listening on {a.host}:{a.port}")
    log(f"Protocol filter : {CFG['protocol']}")
    if CFG["allow_domains"]:
        log(f"Whitelist       : {CFG['allow_domains']}")
    if CFG["block_domains"]:
        log(f"Blacklist       : {CFG['block_domains']}")

    try:
        while True:
            c, addr = srv.accept()
            threading.Thread(target=handle_client, args=(c, addr), daemon=True).start()
    except KeyboardInterrupt:
        log("Shutting down…")
        srv.close()

if __name__ == "__main__":
    main()
