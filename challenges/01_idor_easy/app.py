#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 01 — IDOR (Broken Access Control) · Easy · 100 pts
============================================================
REFERENCE IMPLEMENTATION. Build the other 9 challenges the same way:
  - subclass CTFHandler, set CHALLENGE_ID
  - render pages with common.render(..., challenge=self.challenge, result=...)
  - call self.handle_flag_submit() on POST /submit
  - mark the vulnerable line with  # ======= VULN HERE =======

Run:  python3 app.py     (serves on its registered port)
"""
import os, sys, secrets, urllib.parse, html
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import common
import socketserver

CID = "idor_easy"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]

# In-memory "database". User 102 holds the flag (an account you don't own).
USERS = {
    "101": {"username": "ahmed", "password": "password101", "role": "user",
            "email": "ahmed@lab.local", "balance": "500", "secret": "Nothing here — try another account."},
    "102": {"username": "admin", "password": "x", "role": "admin",
            "email": "admin@lab.local", "balance": "999999", "secret": FLAG},
    "103": {"username": "sara",  "password": "password103", "role": "user",
            "email": "sara@lab.local", "balance": "1200", "secret": "Just another normal account."},
}
SESSIONS = {}  # token -> user id


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def current_user(self):
        return SESSIONS.get(self.cookies().get("session"))

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        result = qs.get("result", [None])[0]

        if u.path == "/":
            me = self.current_user()
            if me:
                self.account_page(qs, result)
            else:
                self.login_page(result=result)
            return
        if u.path == "/account":
            self.account_page(qs, result)
            return
        if u.path == "/logout":
            SESSIONS.pop(self.cookies().get("session"), None)
            self.redirect("/", [("Set-Cookie", "session=; Path=/; Max-Age=0")])
            return
        self.send_html(common.render("<p>404</p>", challenge=self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            data = urllib.parse.parse_qs(self.rfile.read(length).decode())
            uid, pw = data.get("userid", [""])[0], data.get("password", [""])[0]
            user = USERS.get(uid)
            if user and user["password"] == pw:
                tok = secrets.token_hex(16)
                SESSIONS[tok] = uid
                self.redirect(f"/account?id={uid}", [("Set-Cookie", f"session={tok}; Path=/; HttpOnly")])
            else:
                self.login_page(error="Invalid credentials. Use 101 / password101.")
            return
        self.send_html(common.render("<p>404</p>", challenge=self.challenge), 404)

    # ---- pages ----
    def login_page(self, error="", result=None):
        err = f"<p class='bad'>{html.escape(error)}</p>" if error else ""
        body = f"""
        <p class="note">Log in to view your account. Demo account: <code>101</code> / <code>password101</code></p>
        {err}
        <form method="POST" action="/login">
          <label>User ID</label><input name="userid" value="101" autocomplete="off">
          <label>Password</label><input name="password" type="password" value="password101">
          <button type="submit">Log in</button>
        </form>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))

    def account_page(self, qs, result=None):
        me = self.current_user()
        if not me:
            self.redirect("/")
            return

        # ======= VULN HERE =======
        # The id comes straight from the URL and is trusted. There is NO check
        # that requested_id == me. Fix:  if requested_id != me: return 403.
        requested_id = qs.get("id", [me])[0]
        user = USERS.get(requested_id)
        # ==========================

        if not user:
            self.send_html(common.render(
                f"<p>No such user.</p><p><a href='/account?id={me}'>Back to my account</a></p>",
                C["title"], self.challenge, result))
            return

        warn = ""
        if requested_id != me:
            warn = (f"<p class='warn'>⚠️ You are logged in as user {html.escape(me)} "
                    f"but viewing user {html.escape(requested_id)} — that's IDOR.</p>")
        flag_box = f"<div class='flag'>🚩 {html.escape(user['secret'])}</div>" if "FLAG{" in user["secret"] else ""
        secret_cell = "👇" if flag_box else html.escape(user["secret"])

        body = f"""
        {warn}
        <h2>Account — user {html.escape(requested_id)}</h2>
        <div class="row"><span>Username</span><b>{html.escape(user['username'])}</b></div>
        <div class="row"><span>Email</span><b>{html.escape(user['email'])}</b></div>
        <div class="row"><span>Role</span><b>{html.escape(user['role'])}</b></div>
        <div class="row"><span>Balance</span><b>{html.escape(user['balance'])}</b></div>
        <div class="row"><span>Secret</span><b>{secret_cell}</b></div>
        {flag_box}
        <p class="note">Your account is <code>/account?id={html.escape(me)}</code>.
           Change the id in the URL and see whose data you can reach.</p>
        <p><a href="/account?id={html.escape(me)}">My account</a> &nbsp;·&nbsp; <a href="/logout">Log out</a></p>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))


def main():
    common._db().close()  # ensure scoreboard exists
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
