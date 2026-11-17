# 05 — XSS: Reflected · Easy · 100 pts

**Course ref:** Ch04 XSS, Lab4 reflected XSS (like xss-game level 1).

## Scenario
A search page echoes `?q=` back into the HTML. The page defines `solve()`. Make the page run it.

## Walkthrough
```
http://127.0.0.1:8005/?q=<script>solve()</script>
```
(`<img src=x onerror=solve()>` also works.) `solve()` sends the URL's query string to `/api/solve`. The server checks that `q` really contains executable script that calls `solve()`, then the flag appears on the page: `FLAG{r3flected_xss_proven}`.
Calling `solve()` from the DevTools console without an injection does **not** return the flag.

## The bug
`search_page()` inserts `q` into the HTML without encoding (`# ======= VULN HERE =======`).

## The fix
Use context-aware output encoding (`html.escape(q)` for HTML body context) and add a Content-Security-Policy such as `script-src 'self'` that blocks inline script.
