# 09 — File Upload: Unrestricted · Easy · 100 pts

**Course ref:** Lab5 DVWA file upload → "RCE".

## Scenario
An avatar uploader accepts anything and serves it from `/uploads/<name>`, with a Content-Type guessed from the extension. Every page on the site can use the shared helper `/static/ctf.js`, which defines `solve()`.

This is a safe analogue of the DVWA web-shell lab. Here, "code execution" means your uploaded file runs JavaScript in the app's origin. Nothing ever runs on the host.

## Walkthrough
1. Create `pwn.html`:
   ```html
   <script src="/static/ctf.js"></script><script>solve()</script>
   ```
   or an SVG:
   ```html
   <svg xmlns="http://www.w3.org/2000/svg" onload="solve()"><script href="/static/ctf.js"/></svg>
   ```
2. Upload it, then open `http://127.0.0.1:8009/uploads/pwn.html`.
3. It is served as `text/html`, so the script runs and `solve()` shows the flag: `FLAG{unrestricted_upload_served}`

`/api/solve` only answers when the request comes from an upload that the server renders as a document (HTML/SVG/XHTML).

## The bug
`/upload` has no validation at all (`# ======= VULN HERE =======`).

## The fix
- Allow-list extensions (`png`, `jpg`, `gif`), verify magic bytes, and re-encode images.
- Store files under random names.
- Serve uploads as `application/octet-stream` with `X-Content-Type-Options: nosniff` and `Content-Disposition: attachment`, from a separate, cookie-less origin.
