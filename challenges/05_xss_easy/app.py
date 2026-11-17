#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 05 — XSS: Reflected · Easy · 100 pts
==============================================
?q= is echoed into the page with no encoding. The page defines solve(); when it runs,
it sends the current query string to /api/solve. The server re-checks that the reflected
q really contains executable script calling solve() (a simulated "did JS run?" check),
then returns the flag, which solve() shows on the page.

Run:  python3 app.py
"""
import os, sys, re, json, urllib.parse, html
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import common
import socketserver

CID = "xss_easy"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]

# Shapes of q that, reflected raw into HTML, execute solve() in a browser.
EXEC_PATTERNS = [
    re.compile(r"<script[^>]*>[^<]*\bsolve\s*\(", re.I),
    re.compile(r"<[a-z][^>]*\son[a-z]+\s*=[^>]*\bsolve\s*\(", re.I),
]

SOLVE_JS = """
<script>
function solve() {
  fetch('/api/solve', {method: 'POST', body: location.search})
    .then(r => r.json()).then(d => {
      const el = document.getElementById('flag');
      el.textContent = d.ok ? '🚩 ' + d.flag : d.msg;
      el.style.display = 'block';
    });
}
</script>"""


def is_executing_payload(q):
    return any(p.search(q or "") for p in EXEC_PATTERNS)


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        if u.path == "/":
            self.search_page(qs.get("q", [None])[0], qs.get("result", [None])[0])
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        if self.path == "/api/solve":
            length = int(self.headers.get("Content-Length", 0))
            search = self.rfile.read(length).decode("utf-8", "replace").lstrip("?")
            q = urllib.parse.parse_qs(search, keep_blank_values=True).get("q", [""])[0]
            if is_executing_payload(q):
                out = {"ok": True, "flag": FLAG}
            else:
                out = {"ok": False, "msg": "solve() was called, but not from script injected via ?q= . Try again."}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(out).encode())
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def search_page(self, q, result=None):
        results = ""
        if q is not None:
            # ======= VULN HERE =======
            # q is inserted into the HTML without encoding.
            # Fix: html.escape(q) (context-aware output encoding) + a Content-Security-Policy.
            results = f"<p>Results for: <b>{q}</b></p><p class='note'>No articles matched.</p>"
            # ==========================
        body = f"""
        {SOLVE_JS}
        <p class="note">Search the knowledge base. Make the page run <code>solve()</code> to get the flag.</p>
        <form method="GET" action="/">
          <label>Search</label><input name="q" autocomplete="off">
          <button type="submit">Search</button>
        </form>
        {results}
        <div id="flag" class="flag" style="display:none"></div>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))


def main():
    common._db().close()
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
