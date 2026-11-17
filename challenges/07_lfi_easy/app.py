#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 07 — Path Traversal · Easy · 100 pts
==============================================
/download?file=report.txt reads from www/files/ with no containment check.
The flag is in secret/flag.txt (outside www/files/).

Safety: reads are confined to this challenge folder (a lab sandbox), so the traversal can
escape files/ but can never read host files such as /etc/passwd.

Run:  python3 app.py
"""
import os, sys, urllib.parse, html
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
import common
import socketserver

CID = "lfi_easy"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]
FILES_DIR = os.path.join(HERE, "www", "files")
SANDBOX = os.path.realpath(HERE)

PUBLIC = {
    "report.txt": "Q3 report\n=========\nRevenue up 4%. Nothing secret here.\n",
    "welcome.txt": "Welcome to the document portal.\n",
    "policy.txt": "Security policy: secrets are stored in /secret/ — never in the public files folder.\n",
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
            name = qs.get("file", [""])[0]
            # ======= VULN HERE =======
            # The user-supplied name is joined to the base folder with no containment check.
            # Fix: real = os.path.realpath(os.path.join(FILES_DIR, name));
            #      if not real.startswith(os.path.realpath(FILES_DIR) + os.sep): 403
            path = os.path.join(FILES_DIR, name)
            # ==========================
            content, err = read_in_sandbox(path)
            self.show(name, content, err, result)
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def index(self, result=None):
        links = "".join(f"<div class='row'><a href='/download?file={n}'>{n}</a></div>" for n in PUBLIC)
        body = f"""<p class="note">Document portal — public files:</p>{links}"""
        self.send_html(common.render(body, C["title"], self.challenge, result))

    def show(self, name, content, err, result=None):
        if err:
            inner = f"<p class='bad'>{html.escape(err)}</p>"
        else:
            inner = f"<pre style='white-space:pre-wrap'>{html.escape(content)}</pre>"
            if "FLAG{" in content:
                inner += f"<div class='flag'>🚩 {html.escape(FLAG)}</div>"
        body = f"""<h2>{html.escape(name)}</h2>{inner}<p><a href="/">Back</a></p>"""
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
