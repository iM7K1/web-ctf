#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 02 — Broken Access Control (vertical priv-esc + forced browsing) · Hard · 250 pts
==========================================================================================
A normal user logs in. The admin panel is NOT linked anywhere in the UI (find it via
robots.txt / content discovery), and the server decides "is admin?" from a
client-controlled cookie (role=...).

Run:  python3 app.py
"""
import os, sys, secrets, urllib.parse, html
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import common
import socketserver

CID = "idor_hard"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]

USERS = {"guest": {"password": "guest", "role": "user"},
         "admin": {"password": secrets.token_hex(12), "role": "admin"}}  # admin password is unguessable
SESSIONS = {}  # token -> username

ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /backup/\n"


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def current_user(self):
        return SESSIONS.get(self.cookies().get("ba_session"))

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        result = qs.get("result", [None])[0]

        if u.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(ROBOTS.encode())
            return
        if u.path == "/":
            if self.current_user():
                self.dashboard(result)
            else:
                self.login_page(result=result)
            return
        if u.path in ("/admin", "/admin/"):
            self.admin_page(result)
            return
        if u.path == "/logout":
            SESSIONS.pop(self.cookies().get("ba_session"), None)
            self.redirect("/", [("Set-Cookie", "ba_session=; Path=/; Max-Age=0"),
                                ("Set-Cookie", "role=; Path=/; Max-Age=0")])
            return
        self.send_html(common.render("<p>404 — Not found.</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            data = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            name, pw = data.get("username", [""])[0], data.get("password", [""])[0]
            user = USERS.get(name)
            if user and secrets.compare_digest(user["password"], pw):
                tok = secrets.token_hex(16)
                SESSIONS[tok] = name
                # The role is handed to the client in a plain, unsigned, non-HttpOnly cookie.
                self.redirect("/", [("Set-Cookie", f"ba_session={tok}; Path=/; HttpOnly"),
                                    ("Set-Cookie", f"role={user['role']}; Path=/")])
            else:
                self.login_page(error="Invalid credentials. Use guest / guest.")
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    # ---- pages ----
    def login_page(self, error="", result=None):
        err = f"<p class='bad'>{html.escape(error)}</p>" if error else ""
        body = f"""
        <p class="note">Staff portal. Demo account: <code>guest</code> / <code>guest</code></p>
        {err}
        <form method="POST" action="/login">
          <label>Username</label><input name="username" value="guest" autocomplete="off">
          <label>Password</label><input name="password" type="password" value="guest">
          <button type="submit">Log in</button>
        </form>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))

    def dashboard(self, result=None):
        me = self.current_user()
        body = f"""
        <h2>Welcome, {html.escape(me)}</h2>
        <div class="row"><span>Your tickets</span><b>0 open</b></div>
        <div class="row"><span>Announcements</span><b>Cafeteria closed Friday</b></div>
        <p class="note">Menu: <a href="/">Dashboard</a> · <a href="/logout">Log out</a></p>
        <p class="note">There is an administration area somewhere on this site, but it isn't in the menu.
           Do some content discovery (think gobuster / dirb).</p>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))

    def admin_page(self, result=None):
        me = self.current_user()
        if not me:
            self.send_html(common.render("<p class='bad'>401 — Please <a href='/'>log in</a> first.</p>",
                                         C["title"], self.challenge, result), 401)
            return

        # ======= VULN HERE =======
        # Authorization is decided by a CLIENT-CONTROLLED cookie, not by the server-side session.
        # Fix: role = USERS[SESSIONS[token]]["role"]; deny unless role == "admin" (deny-by-default).
        role = self.cookies().get("role", "user")
        is_admin = role == "admin"
        # ==========================

        if not is_admin:
            body = (f"<h2>Admin panel</h2><p class='bad'>403 — Forbidden. Your role is "
                    f"<code>{html.escape(role)}</code>; this area requires <code>admin</code>.</p>")
            self.send_html(common.render(body, C["title"], self.challenge, result), 403)
            return
        body = f"""
        <h2>Admin panel</h2>
        <p class="warn">⚠️ You are <b>{html.escape(me)}</b> (a normal user) but the server believed your
           <code>role</code> cookie. That's vertical privilege escalation.</p>
        <div class="row"><span>Users</span><b>{len(USERS)}</b></div>
        <div class="row"><span>System secret</span><b>👇</b></div>
        <div class="flag">🚩 {html.escape(FLAG)}</div>"""
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
