# 01 — IDOR (Broken Access Control) · Easy · 100 pts

**Course ref:** Ch04 — OWASP A01 Broken Access Control ("change an ID in the URL to view another user's data").

## Scenario
Log in as user `101` (password `password101`). Your account page is `/account?id=101`.

## Exploit
Change the id in the URL to another user:
```
/account?id=102
```
User 102 is an account you don't own; its secret is the flag:
```
FLAG{idor_h0rizontal_pr1v_esc}
```
Submit it in the "Submit flag" box to score.

## The bug
In `account_page()` the `id` is taken from the URL and trusted — there is no check that it
belongs to the logged-in user (see `# ======= VULN HERE =======`).

## The fix
```python
if requested_id != session_user_id:
    return 403  # deny by default; check object ownership on every request
```
