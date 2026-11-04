"""A fake Lantern Zero gateway for relay/deploy/smoke-test.sh.

It declares the Lantern Zero purpose, serves a fixed key configuration,
and echoes POST bodies. A body starting with `slow` and two digits makes
it wait that many seconds before answering, like a held long-poll. Each
request's headers are printed, so the test can check what the relay
forwards.
"""
import http.server, time, sys
P = b"LanternZero v0 4bca76ac-1094-4330-97df-03d5c81b576d"
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def send(self, code, ct, body):
        self.send_response(code); self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        print("GET", self.path, dict(self.headers), flush=True)
        if self.path == "/.well-known/ohttp-gateway?allowed_purposes":
            self.send(200, "application/x-ohttp-allowed-purposes", b"\x00\x01" + bytes([len(P)]) + P)
        elif self.path == "/.well-known/ohttp-gateway":
            self.send(200, "application/ohttp-keys", b"\x01\x02\x03\x04")
        else:
            self.send(404, "text/plain", b"")
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n)
        print("POST", self.path, dict(self.headers), flush=True)
        if body.startswith(b"slow"):
            time.sleep(int(body[4:6]))
        self.send(200, "message/ohttp-res", body)
http.server.ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
