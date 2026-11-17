# 02 — Broken Access Control (forced browsing + vertical priv-esc) · Hard · 250 pts

**Course ref:** Ch04 — OWASP A01 ("force-browse to hidden functionality"), Ch03 / Lab2 content discovery (gobuster, dirb).

## Scenario
A staff portal. Log in as `guest` / `guest`. The admin area exists but isn't linked from the menu.

## Walkthrough
1. Content discovery: `GET /robots.txt` lists `Disallow: /admin` (or run `gobuster dir -u http://127.0.0.1:8002 -w common.txt`).
2. `GET /admin` returns **403: your role is `user`**.
3. Look at your cookies: the login set `role=user` in a plain, unsigned cookie that JavaScript can read. Change it to `role=admin` (DevTools → Application → Cookies, or Burp) and reload `/admin`:
   ```
   curl -b "ba_session=<your session>; role=admin" http://127.0.0.1:8002/admin
   ```
4. Flag: `FLAG{broken_access_vertical_esc}`

## The bug
`admin_page()` decides authorization from `self.cookies().get("role")`, a value the client controls (see `# ======= VULN HERE =======`).

## The fix
Look up the role server-side from the session, and deny by default:
```python
user = SESSIONS.get(token)
if not user or USERS[user]["role"] != "admin":
    return 403
```
Hiding a URL (leaving it out of the menu, or listing it in robots.txt) is not access control.
