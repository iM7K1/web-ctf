# 10 — File Upload: Bypass the Extension Filter · Hard · 250 pts

**Course ref:** Lab5 DVWA upload (medium/high), Ch07 Filter Evasion.

## Scenario
A "hardened" uploader:
1. blocks `html, htm, xhtml, shtml, svg, xml, js, php, phtml`, but compares only the **last** extension, and case-sensitively;
2. requires `Content-Type: image/*`, but trusts the header the client sends;
3. keeps your file name. The file server picks the Content-Type from the **first** extension it recognises (like Apache `mod_mime` with multiple extensions).

## Walkthrough
Use the same payload as in challenge 09:
```html
<script src="/static/ctf.js"></script><script>solve()</script>
```
Upload it with either bypass:
- **Case:** name it `pwn.HtMl` and spoof the Content-Type (Burp, or `curl -F "file=@pwn.html;filename=pwn.HtMl;type=image/png"`).
- **Double extension:** name it `pwn.html.png`. The browser already sends `image/png`, the last extension `png` passes the filter, and the file is served as `text/html`.

Open `/uploads/<name>`. The script runs and `solve()` shows `FLAG{upload_filter_bypass_exec}`.

## The bug
A case-sensitive blacklist on the last extension, a trusted client Content-Type, an attacker-controlled stored name, and type detection from the first extension (`# ======= VULN HERE =======`).

## The fix
- Use a strict allow-list on the lower-cased final extension, verify magic bytes, and re-encode images.
- Ignore the client's Content-Type.
- Store files under a random name with a fixed extension.
- Serve with `X-Content-Type-Options: nosniff` as a download from a separate origin.
