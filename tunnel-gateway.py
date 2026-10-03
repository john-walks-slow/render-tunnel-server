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
from urllib.parse import urlparse, unquote

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
        note({"m": "GET", "p": path,
              "up": self.headers.get("Upgrade", ""),
              "conn": self.headers.get("Connection", ""),
              "key": bool(self.headers.get("Sec-WebSocket-Key")),
              "ua": self.headers.get("User-Agent", "")[:40]})
        if self.headers.get("Upgrade", "").lower() == "websocket":
            return self._bridge_ws(path)
        if path in ("/health", "/healthz"):
            return self._send(200, {"ok": True})
        if path == "/info":
            return self._send(200, {"service": "tunnel-server", "via": "frps"})
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
        path = urlparse(self.path).path
        note({"m": "POST", "p": path,
              "up": self.headers.get("Upgrade", ""),
              "key": bool(self.headers.get("Sec-WebSocket-Key")),
              "cl": self.headers.get("Content-Length", ""),
              "te": self.headers.get("Transfer-Encoding", ""),
              "ua": self.headers.get("User-Agent", "")[:40]})
        if self.headers.get("Upgrade", "").lower() == "websocket":
            return self._bridge_ws(path)
        return self._proxy_http()

    def do_PUT(self):
        return self._proxy_http()

    def do_DELETE(self):
        return self._proxy_http()

    def _read_body(self):
        te = self.headers.get("Transfer-Encoding", "")
        if "chunked" in te.lower():
            chunks = []
            while True:
                line = self.rfile.readline().strip().split(b";")[0]
                try:
                    n = int(line, 16)
                except ValueError:
                    break
                if n == 0:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(n))
                self.rfile.readline()
            return b"".join(chunks)
        length = self.headers.get("Content-Length")
        if length:
            try:
                return self.rfile.read(int(length))
            except ValueError:
                return None
        return None

    def _proxy_http(self):
        body = self._read_body()
        # Preserve the original Host: frps routes tunneled HTTP by Host.
        host = self.headers.get("Host", "%s:%d" % (UP_HOST, UP_PORT))
        conn = http.client.HTTPConnection(UP_HOST, UP_PORT, timeout=120)
        try:
            conn.putrequest(self.command, self.path, skip_host=True,
                            skip_accept_encoding=True)
            conn.putheader("Host", host)
            for k, v in self.headers.items():
                if k.lower() not in ("host", "content-length", "connection",
                                     "accept-encoding"):
                    conn.putheader(k, v)
            if body is not None:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
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
        # Decode %XX: edges (Cloudflare) normalize reserved chars like '!'
        # but backends (frps /~!frp) match the raw path.
        target = unquote(target)
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
        backend_head = b""
        try:
            backend = _socket.create_connection((UP_HOST, UP_PORT), timeout=15)
            backend.settimeout(10)
            bkey = base64.b64encode(_os.urandom(16)).decode()
            origin = self.headers.get("Origin", "http://%s:%d" % (UP_HOST, UP_PORT))
            backend.sendall(
                ("GET %s HTTP/1.1\r\n"
                 "Host: %s:%d\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-WebSocket-Key: %s\r\n"
                 "Sec-WebSocket-Version: 13\r\n"
                 "Origin: %s\r\n\r\n"
                 % (target, UP_HOST, UP_PORT, bkey, origin)).encode("latin-1"))
            head = b""
            try:
                while b"\r\n\r\n" not in head:
                    chunk = backend.recv(4096)
                    if not chunk:
                        break
                    head += chunk
            except Exception:
                pass
            backend_head = head[:100]
            if b" 101 " not in head.split(b"\r\n", 1)[0]:
                raise ConnectionError("backend refused: %s" % backend_head)
            note({"m": "WS-BRIDGE", "p": target, "r": "101 established"})
        except Exception as e:
            try:
                backend.close()
            except Exception:
                pass
            note({"m": "WS-BRIDGE", "p": target, "r": "backend failed: %s | saw: %s" % (e, backend_head)})
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
