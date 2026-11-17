#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
index.py — Scoreboard / challenge index (port 8000)
Reads the shared scoreboard DB and lists every challenge with its status.
"""
import os, sys, html, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common
import http.server, socketserver

PORT = 8000


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if urllib.parse.urlparse(self.path).path not in ("/", "/index.html"):
            self.send_response(404); self.end_headers(); return

        solved = common.solved_ids()
        total = common.total_score()
        max_pts = sum(c["points"] for c in common.CHALLENGES)

        # group into type pairs (easy, hard)
        rows = ""
        for c in common.CHALLENGES:
            done = c["id"] in solved
            dcls = "easy" if c["difficulty"] == "Easy" else "hard"
            status = "<span class='ok'>✓ solved</span>" if done else "<span class='note'>unsolved</span>"
            rows += f"""
            <div class="row">
              <span>
                <a href="http://127.0.0.1:{c['port']}/">{html.escape(c['title'])}</a><br>
                <span class="tag">{html.escape(c['type'])}</span>
                <span class="tag {dcls}">{c['difficulty']}</span>
                <span class="tag pts">{c['points']} pts</span>
              </span>
              <span>{status}</span>
            </div>"""

        body = f"""
        <h1>🚩 Web App Pentesting CTF</h1>
        <p class="note">Based on your course: Broken Access Control, SQL Injection, XSS,
           Path Traversal/LFI, and Insecure File Upload — each with an Easy and a Hard challenge.</p>
        <div class="row"><span><b>Total score</b></span>
             <span class="warn"><b>{total} / {max_pts}</b></span></div>
        {rows}
        <p class="note" style="margin-top:18px">
           Open a challenge, exploit it, grab the <code>FLAG{{...}}</code>, and submit it on that
           challenge page to score. This board updates on refresh.</p>"""
        page = common.render(body, "CTF Scoreboard")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode("utf-8"))

    def log_message(self, *a):
        pass


def main():
    common._db().close()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", PORT), Handler) as httpd:
        print(f"[scoreboard] http://127.0.0.1:{PORT}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
