#!/usr/bin/env python3
"""Public front for frps: /health for Render, everything else (HTTP + WS)
proxied to frps on 127.0.0.1:18080. frps routes tunneled HTTP services by
Host/locations; the tunnel client (frpc) dials in over WSS from behind NAT.
Only stdlib is used.
"""
import http.client
import json
import os
import shutil
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

UP_HOST = os.environ.get("UPSTREAM_HOST", "127.0.0.1")
UP_PORT = int(os.environ.get("UPSTREAM_PORT", "18080"))
DEBUG_TOKEN = os.environ.get("DEBUG_TOKEN", os.environ.get("FRP_TOKEN", ""))

REQLOG = deque(maxlen=50)
REQLOCK = threading.Lock()


def note(entry):
    entry["ts"] = time.strftime("%H:%M:%S")
    with REQLOCK:
        REQLOG.append(entry)


class H(BaseHTTPRequestHandler):
    server_version = "tunnel-gw/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, obj):
        try:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/debug" and self._debug_ok():
            return self._serve_debug()
        if self.headers.get("Upgrade", "").lower() == "websocket":
            note({"m": "GET", "p": path, "ws": True,
                  "ua": self.headers.get("User-Agent", "")[:60]})
            return self._bridge_ws(path)
        if path in ("/health", "/healthz"):
            return self._send(200, {"ok": True})
        if path == "/info":
            return self._send(200, {"service": "tunnel-server", "via": "frps"})
        note({"m": "GET", "p": path, "ws": False,
              "ua": self.headers.get("User-Agent", "")[:60]})
        return self._proxy_http()

    def _debug_ok(self):
        q = urlparse(self.path).query
        return DEBUG_TOKEN and ("token=" + DEBUG_TOKEN) in q

    def _serve_debug(self):
        import socket as _s
        try:
            c = _s.create_connection((UP_HOST, UP_PORT), timeout=5)
            c.close()
            up = "open"
        except Exception as e:
            up = "closed: %s" % e
        with REQLOCK:
            log = list(REQLOG)
        return self._send(200, {"upstream": up, "recent": log})

    def do_POST(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            return self._bridge_ws(urlparse(self.path).path)
        return self._proxy_http()

    def do_PUT(self):
        return self._proxy_http()

    def do_DELETE(self):
        return self._proxy_http()

    def _proxy_http(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else None
        fwd = {k: v for k, v in self.headers.items()
               if k.lower() not in ("host", "content-length", "connection")}
        conn = http.client.HTTPConnection(UP_HOST, UP_PORT, timeout=120)
        try:
            conn.request(self.command, self.path, body=body, headers=fwd)
            resp = conn.getresponse()
            payload = resp.read()
            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in ("connection", "transfer-encoding", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._send(502, {"error": "upstream failed: %s" % e})
        finally:
            conn.close()

    def _bridge_ws(self, target):
        import base64
        import hashlib
        import os as _os
        import select
        import socket as _socket
        GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        ckey = self.headers.get("Sec-WebSocket-Key", "")
        if not ckey:
            return self._send(400, {"error": "missing Sec-WebSocket-Key"})
        accept = base64.b64encode(
            hashlib.sha1((ckey + GUID).encode()).digest()).decode()
        try:
            self.connection.sendall(
                ("HTTP/1.1 101 Switching Protocols\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode("latin-1"))
        except (BrokenPipeError, ConnectionResetError):
            return
        try:
            backend = _socket.create_connection((UP_HOST, UP_PORT), timeout=15)
            bkey = base64.b64encode(_os.urandom(16)).decode()
            backend.sendall(
                ("GET %s HTTP/1.1\r\n"
                 "Host: %s:%d\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-WebSocket-Key: %s\r\n"
                 "Sec-WebSocket-Version: 13\r\n\r\n"
                 % (target, UP_HOST, UP_PORT, bkey)).encode("latin-1"))
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = backend.recv(4096)
                if not chunk:
                    raise ConnectionError("backend closed during handshake")
                head += chunk
            if b" 101 " not in head.split(b"\r\n", 1)[0]:
                raise ConnectionError("backend refused: %s" % head[:60])
            note({"m": "WS-BRIDGE", "p": target, "r": "101 established"})
        except Exception:
            try:
                backend.close()
            except Exception:
                pass
            note({"m": "WS-BRIDGE", "p": target, "r": "backend failed"})
            return
        try:
            backend.setblocking(False)
            self.connection.setblocking(False)
            while True:
                r, _, _ = select.select([self.connection, backend], [], [], 300)
                if not r:
                    break
                for src in r:
                    dst = backend if src is self.connection else self.connection
                    try:
                        data = src.recv(65536)
                    except BlockingIOError:
                        continue
                    if not data:
                        raise ConnectionError("closed")
                    dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                backend.close()
            except Exception:
                pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    print("tunnel gateway on 0.0.0.0:%d -> %s:%d" % (port, UP_HOST, UP_PORT), flush=True)
    srv.serve_forever()
