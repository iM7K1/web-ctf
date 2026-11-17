# 03 — SQL Injection: Login Bypass · Easy · 100 pts

**Course ref:** Ch05 SQL Injection, Lab4 (Mutillidae login bypass).

## Scenario
An admin login backed by a real sqlite3 DB (`app.db`, rebuilt on every start). The admin's password is random.

## Walkthrough
Query: `SELECT id, username, role FROM users WHERE username = '<u>' AND password = '<p>'`

- Username `admin' --` and any password: the `--` comments out the password check.
- Or username `' OR '1'='1' --`: this returns every row, and the first row is admin.

The page shows the query that ran, so you can watch the injection. Flag: `FLAG{sql1_auth_bypass_comment}`

## The bug
`do_login()` builds the SQL by string concatenation (`# ======= VULN HERE =======`).

## The fix
Use a parameterized query or prepared statement:
```python
con.execute("SELECT id, username, role FROM users WHERE username = ? AND password = ?", (u, p))
```
Also store password hashes (bcrypt/argon2), not plaintext, and don't show SQL errors to users.
