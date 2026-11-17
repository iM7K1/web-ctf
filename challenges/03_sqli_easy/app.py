#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 03 — SQL Injection: Login Bypass · Easy · 100 pts
===========================================================
The login query is built by string concatenation over a real sqlite3 DB (app.db, in this folder).

Run:  python3 app.py
"""
import os, sys, secrets, sqlite3, urllib.parse, html
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
import common
import socketserver

CID = "sqli_easy"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]
DB = os.path.join(HERE, "app.db")


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    con.executemany("INSERT INTO users(username, password, role) VALUES (?,?,?)", [
        ("admin", secrets.token_hex(16), "admin"),   # unguessable password
        ("ahmed", "ahmed123", "user"),
        ("sara",  "sara2024", "user"),
    ])
    con.commit()
    con.close()


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        if u.path == "/":
            self.login_page(result=qs.get("result", [None])[0])
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            data = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            self.do_login(data.get("username", [""])[0], data.get("password", [""])[0])
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_login(self, username, password):
        # ======= VULN HERE =======
        # User input is concatenated straight into the SQL string.
        # Fix: con.execute("SELECT ... WHERE username = ? AND password = ?", (username, password))
        query = ("SELECT id, username, role FROM users "
                 "WHERE username = '" + username + "' AND password = '" + password + "'")
        # ==========================
        con = sqlite3.connect(DB)
        try:
            row = con.execute(query).fetchone()
        except sqlite3.Error as e:
            self.login_page(error=f"SQL error: {e}", query=query)
            return
        finally:
            con.close()

        if not row:
            self.login_page(error="Invalid username or password.", query=query)
            return
        uid, name, role = row
        flag = f"<div class='flag'>🚩 {html.escape(FLAG)}</div>" if role == "admin" else \
               "<p class='note'>Logged in as a normal user — no secrets here. Who is the interesting account?</p>"
        body = f"""
        <h2>Welcome, {html.escape(name)}</h2>
        <div class="row"><span>User id</span><b>{uid}</b></div>
        <div class="row"><span>Role</span><b>{html.escape(role)}</b></div>
        {flag}
        <p class="note">Query that ran:<br><code>{html.escape(query)}</code></p>
        <p><a href="/">Back to login</a></p>"""
        self.send_html(common.render(body, C["title"], self.challenge))

    def login_page(self, error="", query="", result=None):
        err = f"<p class='bad'>{html.escape(error)}</p>" if error else ""
        q = f"<p class='note'>Query that ran:<br><code>{html.escape(query)}</code></p>" if query else ""
        body = f"""
        <p class="note">Admin login. Only the <code>admin</code> account sees the secret — and you don't know its password.</p>
        {err}{q}
        <form method="POST" action="/login">
          <label>Username</label><input name="username" autocomplete="off">
          <label>Password</label><input name="password" type="password">
          <button type="submit">Log in</button>
        </form>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))


def main():
    common._db().close()
    init_db()
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
