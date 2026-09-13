"""OPTIONAL local test app (vulnerable-by-design) for offline WebGuard Pro demos.

Primary usage is now PUBLIC targets (e.g. https://portofolio-fajar-cs.vercel.app/).
This file is only a fallback when you want an offline localhost demo:

Run:  python test_target.py   (serves http://127.0.0.1:8765)
Then scan target http://127.0.0.1:8765 with scope 127.0.0.1 in WebGuard Pro.

WARNING: intentionally vulnerable — bind to 127.0.0.1 ONLY. Never expose publicly.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PORT = 8765

INDEX = """<!DOCTYPE html><html><head><title>WebGuard TestLab</title></head><body>
<h1>WebGuard TestLab (local authorized target)</h1>
<form action="/search" method="GET"><input name="q" value=""><input type=submit value=Search></form>
<form action="/login" method="POST"><input name="user"><input name="password" type="password"><input type=submit value=Login></form>
<form action="/upload" method="POST" enctype="multipart/form-data"><input type="file" name="file"><input type=submit value=Upload></form>
<a href="/page?id=1">item 1</a> <a href="/api/users">api</a> <a href="/page?url=http://example.com">fetch</a>
<script>var h = location.hash; document.getElementById('x').innerHTML = h;</script><div id=x></div>
<script src="/static/app.js"></script>
</body></html>"""


class H(BaseHTTPRequestHandler):
    server_version = "TestLab/1.0"
    def log_message(self, *a): pass
    def _send(self, body, code=200, ctype="text/html"):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        p = urlparse(self.path)
        q = parse_qs(p.query)
        if p.path == "/robots.txt":
            return self._send("User-agent: *\nDisallow: /admin\n", ctype="text/plain")
        if p.path == "/sitemap.xml":
            return self._send('<urlset><url><loc>http://127.0.0.1:8765/page?id=1</loc></url></urlset>', ctype="text/xml")
        if p.path == "/search":
            v = q.get("q", [""])[0]
            return self._send(f"<html><body>results for {v}</body></html>")  # reflected (vuln)
        if p.path == "/page":
            v = q.get("id", ["1"])[0]
            if "'" in v:
                return self._send("<html><body>MySQLSyntaxError near '' at line 1</body></html>")
            return self._send(f"<html><body>item {v}</body></html>")
        if p.path == "/api/users":
            import json
            return self._send(json.dumps([{"id": 1, "email": "test@example.com"}]), ctype="application/json")
        if p.path == "/.env":
            return self.send_error(404)
        if p.path == "/static/app.js":
            return self._send("var x = document.URL; document.write(x);", ctype="text/javascript")
        return self._send(INDEX)
    def do_POST(self):
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            return self._send("<html><body>login failed</body></html>")
        if self.path == "/upload":
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            return self._send("<html><body>upload success stored</body></html>")
        return self.send_error(404)
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE")
        self.end_headers()
    def do_TRACE(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"TRACE ok")


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", PORT), H)
    print(f"TestLab on http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    srv.serve_forever()
