#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 09 — File Upload: Unrestricted · Easy · 100 pts
=========================================================
The avatar uploader accepts any file and serves it back from /uploads/ with a Content-Type
guessed from the extension — so an uploaded .html/.svg is rendered (and its JS runs) in the
app's own origin. Safe analogue of DVWA's shell upload: "execution" = your uploaded page
calling the app's solve() helper (/static/ctf.js). Nothing is ever executed on the host.

Run:  python3 app.py
"""
import os, sys, re, json, shutil, mimetypes, urllib.parse, html
from email.parser import BytesParser
from email.policy import HTTP
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
import common
import socketserver

CID = "upload_easy"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]
UPLOADS = os.path.join(HERE, "uploads")
MAX_SIZE, MAX_FILES = 64 * 1024, 100
RENDERABLE = {"text/html", "image/svg+xml", "application/xhtml+xml"}

CTF_JS = """// Shared site helper. Any page served from this origin can call solve().
function solve() {
  fetch('/api/solve').then(r => r.json()).then(d => {
    const msg = d.ok ? 'FLAG: ' + d.flag : d.msg;
    try { const p = document.createElementNS('http://www.w3.org/1999/xhtml', 'pre');
          p.textContent = msg; (document.body || document.documentElement).appendChild(p); } catch (e) {}
    alert(msg);
  });
}
"""


def parse_multipart(content_type, body):
    """Minimal stdlib multipart/form-data parser -> {field: (filename, content_type, bytes)}."""
    msg = BytesParser(policy=HTTP).parsebytes(
        b"Content-Type: " + content_type.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + body)
    out = {}
    if not msg.is_multipart():
        return out
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if name:
            out[name] = (part.get_filename(), part.get_content_type(), part.get_payload(decode=True) or b"")
    return out


def safe_name(name):
    """Keeps writes inside uploads/ (no path tricks). This is NOT the vulnerability."""
    name = os.path.basename((name or "").replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".")[:80]
    return name or "upload.bin"


def served_type(name):
    return mimetypes.guess_type(name)[0] or "application/octet-stream"


def prune():
    files = sorted((os.path.join(UPLOADS, f) for f in os.listdir(UPLOADS)), key=os.path.getmtime)
    for f in files[:-MAX_FILES]:
        os.remove(f)


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        result = qs.get("result", [None])[0]
        if u.path == "/":
            self.index(result, msg=qs.get("msg", [""])[0])
            return
        if u.path == "/static/ctf.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(CTF_JS.encode())
            return
        if u.path.startswith("/uploads/"):
            self.serve_upload(urllib.parse.unquote(u.path[len("/uploads/"):]))
            return
        if u.path == "/api/solve":
            self.api_solve()
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        if self.path == "/upload":
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_SIZE + 4096:
                self.redirect("/?msg=" + urllib.parse.quote("File too large (64 KB max)."))
                return
            fields = parse_multipart(self.headers.get("Content-Type", ""), self.rfile.read(length))
            if "file" not in fields or not fields["file"][0]:
                self.redirect("/?msg=" + urllib.parse.quote("No file received."))
                return
            filename, _ctype, data = fields["file"]
            # ======= VULN HERE =======
            # No validation at all: any extension / any content is accepted and later served
            # with a type guessed from the extension (text/html, image/svg+xml, ...).
            # Fix: allow-list (png/jpg/gif), verify magic bytes, re-encode images, random names,
            #      serve as application/octet-stream + Content-Disposition: attachment from a separate origin.
            name = safe_name(filename)
            with open(os.path.join(UPLOADS, name), "wb") as f:
                f.write(data[:MAX_SIZE])
            # ==========================
            prune()
            self.redirect("/?msg=" + urllib.parse.quote(f"Uploaded! Your avatar is at /uploads/{name}"))
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def serve_upload(self, name):
        name = os.path.basename(name)
        path = os.path.join(UPLOADS, name)
        if not name or not os.path.isfile(path):
            self.send_html(common.render("<p>404 — no such upload</p>", C["title"], self.challenge), 404)
            return
        with open(path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", served_type(name))
        self.end_headers()
        self.wfile.write(data)

    def api_solve(self):
        """Awards the flag only when solve() runs inside an uploaded file rendered as a document."""
        ref = urllib.parse.urlparse(self.headers.get("Referer", ""))
        name = os.path.basename(urllib.parse.unquote(ref.path)) if ref.path.startswith("/uploads/") else ""
        path = os.path.join(UPLOADS, name)
        if name and os.path.isfile(path) and served_type(name) in RENDERABLE:
            out = {"ok": True, "flag": FLAG}
        else:
            out = {"ok": False, "msg": "solve() must run from inside an uploaded file that the server renders."}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(out).encode())

    def index(self, result=None, msg=""):
        m = f"<p class='warn'>{html.escape(msg)}</p>" if msg else ""
        files = sorted(os.listdir(UPLOADS), key=lambda f: os.path.getmtime(os.path.join(UPLOADS, f)))[-8:]
        listing = "".join(f"<div class='row'><a href='/uploads/{html.escape(f, True)}'>{html.escape(f)}</a>"
                          f"<span class='note'>{html.escape(served_type(f))}</span></div>" for f in reversed(files))
        body = f"""
        <script src="/static/ctf.js"></script>
        <p class="note">Upload a profile picture. Files are served back from <code>/uploads/&lt;name&gt;</code>.
           Every page on this site may use the shared helper <code>/static/ctf.js</code>, which defines
           <code>solve()</code>.</p>
        {m}
        <form method="POST" action="/upload" enctype="multipart/form-data">
          <input type="file" name="file">
          <button type="submit">Upload avatar</button>
        </form>
        <h2>Recent uploads</h2>{listing or "<p class='note'>None yet.</p>"}"""
        self.send_html(common.render(body, C["title"], self.challenge, result))


def main():
    common._db().close()
    shutil.rmtree(UPLOADS, ignore_errors=True)
    os.makedirs(UPLOADS)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", C["port"]), Handler) as httpd:
        print(f"[{CID}] http://127.0.0.1:{C['port']}  ({C['difficulty']}, {C['points']} pts)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
