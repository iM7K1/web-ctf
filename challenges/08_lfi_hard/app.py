#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 08 — LFI: Traversal with Filter Bypass · Hard · 250 pts
=================================================================
Same document viewer, but a naive filter strips the literal "../" ONCE, and it runs on the
raw (still URL-encoded) parameter before decoding. Bypass with nesting (....//) or
URL-encoding (..%2f).

Safety: reads are confined to this challenge folder (a lab sandbox).

Run:  python3 app.py
"""
import os, sys, urllib.parse, html
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
import common
import socketserver

CID = "lfi_hard"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]
FILES_DIR = os.path.join(HERE, "www", "files")
SANDBOX = os.path.realpath(HERE)

PUBLIC = {
    "report.txt": "Q3 report\n=========\nRevenue up 4%. Nothing secret here.\n",
    "readme.txt": "Patched! After last week's incident we now strip ../ from file names.\n",
    "notes.txt": "TODO: move secret/flag.txt somewhere safer.\n",
}


def init_files():
    os.makedirs(FILES_DIR, exist_ok=True)
    os.makedirs(os.path.join(HERE, "secret"), exist_ok=True)
    for name, text in PUBLIC.items():
        with open(os.path.join(FILES_DIR, name), "w") as f:
            f.write(text)
    with open(os.path.join(HERE, "secret", "flag.txt"), "w") as f:
        f.write(FLAG + "\n")


def read_in_sandbox(path):
    real = os.path.realpath(path)
    if not (real == SANDBOX or real.startswith(SANDBOX + os.sep)):
        return None, "That path is outside this lab's sandbox (the CTF won't read host files)."
    if not os.path.isfile(real):
        return None, "File not found."
    with open(real, "r", errors="replace") as f:
        return f.read(4096), None


def raw_param(query, key):
    """Return the raw (NOT yet URL-decoded) value of a query parameter."""
    for part in query.split("&"):
        k, _, v = part.partition("=")
        if k == key:
            return v
    return ""


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        result = qs.get("result", [None])[0]
        if u.path == "/":
            self.index(result)
            return
        if u.path == "/download":
            raw = raw_param(u.query, "file")
            # ======= VULN HERE =======
            # Naive "WAF": strips "../" a single time, BEFORE URL-decoding.
            #   ....//  -> ../     and     ..%2f -> (survives) -> ../ after decoding
            # Fix: decode fully, normalise with realpath, then verify the result is inside
            #      FILES_DIR (containment check); reject anything else.
            filtered = raw.replace("../", "")
            name = urllib.parse.unquote_plus(filtered)
            path = os.path.join(FILES_DIR, name)
            # ==========================
            content, err = read_in_sandbox(path)
            self.show(urllib.parse.unquote_plus(raw), name, content, err, result)
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def index(self, result=None):
        links = "".join(f"<div class='row'><a href='/download?file={n}'>{n}</a></div>" for n in PUBLIC)
        body = f"""<p class="note">Document portal v2 — now with path filtering™.</p>{links}"""
        self.send_html(common.render(body, C["title"], self.challenge, result))

    def show(self, requested, used, content, err, result=None):
        dbg = (f"<p class='note'>Requested: <code>{html.escape(requested)}</code><br>"
               f"After filter: <code>{html.escape(used)}</code></p>")
        if err:
            inner = f"<p class='bad'>{html.escape(err)}</p>"
        else:
            inner = f"<pre style='white-space:pre-wrap'>{html.escape(content)}</pre>"
            if "FLAG{" in content:
                inner += f"<div class='flag'>🚩 {html.escape(FLAG)}</div>"
        body = f"""<h2>Document viewer</h2>{dbg}{inner}<p><a href="/">Back</a></p>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))


def main():
    common._db().close()
    init_files()
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
