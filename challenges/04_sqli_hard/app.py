#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 04 — SQL Injection: UNION Data Extraction · Hard · 250 pts
====================================================================
A product search reflects query rows (2 columns) into the page. The flag lives in a
different table (secrets). Mirrors the Mutillidae credit_cards UNION lab.

Run:  python3 app.py
"""
import os, sys, sqlite3, urllib.parse, html
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
import common
import socketserver

CID = "sqli_hard"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]
DB = os.path.join(HERE, "app.db")


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price TEXT)")
    con.executemany("INSERT INTO products(name, price) VALUES (?,?)", [
        ("USB-C cable", "$9"), ("Mechanical keyboard", "$89"), ("Wireless mouse", "$25"),
        ("27\" monitor", "$249"), ("Laptop stand", "$39"), ("Webcam HD", "$59"),
    ])
    con.execute("CREATE TABLE credit_cards (ccid INTEGER PRIMARY KEY, ccnumber TEXT, expiration TEXT)")
    con.executemany("INSERT INTO credit_cards(ccnumber, expiration) VALUES (?,?)",
                    [("4444111122223333", "2027-01"), ("5555666677778888", "2028-06")])
    con.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, flag TEXT)")
    con.execute("INSERT INTO secrets(flag) VALUES (?)", (FLAG,))
    con.commit()
    con.close()


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
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def search_page(self, q, result=None):
        rows_html, err, query = "", "", ""
        if q is not None:
            # ======= VULN HERE =======
            # The search term is concatenated into the query and every returned row is reflected.
            # Fix: con.execute("... WHERE name LIKE ?", ('%' + q + '%',)) + least-privilege DB user.
            query = "SELECT name, price FROM products WHERE name LIKE '%" + q + "%'"
            # ==========================
            con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)  # read-only: no damage possible
            try:
                rows = con.execute(query).fetchall()
                for r in rows:
                    cells = "".join(f"<b>{html.escape(str(v))}</b>" for v in r)
                    rows_html += f"<div class='row'>{cells}</div>"
                    if any("FLAG{" in str(v) for v in r):
                        rows_html += f"<div class='flag'>🚩 {html.escape(FLAG)}</div>"
                if not rows:
                    rows_html = "<p class='note'>No products found.</p>"
            except sqlite3.Error as e:
                err = f"<p class='bad'>SQL error: {html.escape(str(e))}</p>"
            finally:
                con.close()
        qv = html.escape(q or "", quote=True)
        body = f"""
        <p class="note">Product catalogue search.</p>
        <form method="GET" action="/">
          <label>Search products</label><input name="q" value="{qv}" autocomplete="off">
          <button type="submit">Search</button>
        </form>
        {err}
        {rows_html}"""
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
