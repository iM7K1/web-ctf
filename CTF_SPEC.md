# 🚩 Web App Pentesting CTF — Build Spec (for Claude Code)

> A self-hosted CTF of **10 challenges = 5 vulnerability types × (Easy + Hard)**, built to match **our course**
> (Ch01 Ethical Hacking, Ch02 Web Architecture, Ch03 Recon, Ch04 Intro + XSS, Ch05 SQL Injection,
> Ch06 CSRF, Ch07 Filter Evasion & WAF Bypass) and our hands-on labs (gobuster/dirb content discovery,
> Mutillidae SQLi union-extraction, stored/reflected XSS, LFI & Directory Traversal, DVWA file upload → RCE).
>
> **UI language: English.** Every challenge has a **Hints button**, a **flag-submission box**, and **points**.
> A shared **scoreboard** tracks total score. Standard library only. Binds to `127.0.0.1` only.
>
> ⚠️ Deliberately vulnerable, for authorized self-practice on localhost — never deploy to a network.

---

## ✅ What is already built (reference engine — reuse, don't rebuild)
- **`common.py`** — shared engine: English dark theme + `render()`, the **scoreboard** (shared `scoreboard.db`
  via `sqlite3`), the **Hints** panel, the **flag-submit** endpoint (`CTFHandler.handle_flag_submit`), and the
  **`CHALLENGES` registry** (id, title, type, difficulty, points, port, flag, hints) for all 10.
- **`challenges/01_idor_easy/app.py`** — the **reference challenge**. Copy its pattern for the other 9.
- **`index.py`** — scoreboard on port **8000**.
- **`run_all.py`** — launches the scoreboard + every challenge that has an `app.py`.

**Your job:** implement the remaining 9 challenges (`challenges/02_…` … `challenges/10_…`) following the exact
pattern of `01_idor_easy`, using the flag/points/hints already defined in `common.CHALLENGES`.

### The pattern each challenge follows
```python
import common, socketserver
CID = "sqli_easy"; C = common.CHALLENGE_BY_ID[CID]
class Handler(common.CTFHandler):
    CHALLENGE_ID = CID
    def do_GET(self):  ...   # render with common.render(body, C["title"], self.challenge, result)
    def do_POST(self):       # if path=="/submit": self.handle_flag_submit()
# mark the bug with:  # ======= VULN HERE =======
# serve on C["port"], bind 127.0.0.1 only
```

---

## 📁 Target layout
```
web-ctf/
  common.py              # DONE
  index.py               # DONE (scoreboard :8000)
  run_all.py             # DONE
  scoreboard.db          # auto-created
  challenges/
    01_idor_easy/   app.py  README.md   # DONE (reference)
    02_idor_hard/   app.py  README.md
    03_sqli_easy/   app.py  README.md
    04_sqli_hard/   app.py  README.md
    05_xss_easy/    app.py  README.md
    06_xss_hard/    app.py  README.md
    07_lfi_easy/    app.py  README.md
    08_lfi_hard/    app.py  README.md
    09_upload_easy/ app.py  README.md
    10_upload_hard/ app.py  README.md
  SOLUTIONS.md           # all flags + walkthroughs (instructor)
  solve_all.sh           # one script that exploits every challenge and checks the flag returns
```
Ports: scoreboard 8000; challenges 8001–8010 (already set in `common.CHALLENGES`).

---

## 🧩 The 10 challenges (flags & hints already in `common.CHALLENGES`)

### Type 1 — Broken Access Control  (Ch04 A01)
**1. IDOR — Easy · :8001 · 100 pts** ✅ *(built)*
- Log in as 101, change `/account?id=101` → `id=102` to read another user's secret (the flag).
- Fix: `if requested_id != session_user: 403`.

**2. Broken Access — Hard · :8002 · 250 pts**
- **Vertical** privilege escalation + forced browsing (ties to Ch04 "force-browse to hidden functionality"
  and the gobuster/dirb content-discovery labs). A normal user logs in; `/admin` is **not linked** in the UI.
- Two-part: (a) discover `/admin` (list it in `robots.txt` or leave it unlinked), (b) the server decides admin
  by a **client-controlled** signal — e.g. a cookie `role=user` or a hidden form field. Set `role=admin` → `/admin` returns the flag.
- Fix: server-side role check from the session, never from a client value; deny-by-default.

### Type 2 — SQL Injection  (Ch05 + Lab4)
**3. SQLi — Login Bypass · Easy · :8003 · 100 pts**
- Login query built by **string concatenation** over `sqlite3`. `admin' --` or `' OR '1'='1' --` logs you in → flag.
- Use a real `sqlite3` DB; build the query by concatenation **on purpose** (no parameters). Keep a `users` table.
- Fix: parameterized queries / prepared statements.

**4. SQLi — UNION Extraction · Hard · :8004 · 250 pts**
- Mirrors the Mutillidae lab (`' union select ccid,ccnumber,... from credit_cards --`). A search/lookup page
  reflects query rows into the page. The flag lives in a **different table** (e.g. `secrets(flag TEXT)`).
- Player must: find column count (`' ORDER BY n --`), then `' UNION SELECT a,b FROM secrets --` to surface the flag.
- Fix: parameterized queries + least privilege; don't reflect arbitrary columns.

### Type 3 — Cross-Site Scripting  (Ch04 XSS + Lab4 + Ch07 bypass)
**5. XSS — Reflected · Easy · :8005 · 100 pts**
- `?q=` echoed into the page unencoded (like xss-game level 1). The page defines a JS helper `solve()` that,
  when executed, reveals/awards the flag (e.g. `solve()` sets a visible element to the flag, or calls an
  endpoint that returns it). Payload: `?q=<script>solve()</script>`.
- Fix: context-aware output encoding + CSP.

**6. XSS — Stored + Filter Bypass · Hard · :8006 · 250 pts**
- A comments/guestbook page stores input and shows it to all viewers, **including a simulated admin bot**
  (an endpoint `/admin/visit` that renders stored comments server-side with the admin's cookie = the flag,
  or that "runs" a known payload shape). A **blacklist blocks the word `script`** (Ch07: blacklists fail).
- Player bypasses with an event handler: `<img src=x onerror=...>` or `<svg onload=...>` (the Lab4 technique)
  to exfiltrate/reveal the admin cookie → flag.
- Keep "exfiltration" local: the onerror/onload handler hits a local collector endpoint that, for the correct
  payload shape, returns the flag. Do NOT make real external requests.
- Fix: context-aware output encoding, sanitise on store, `HttpOnly` cookies, CSP.

### Type 4 — Path Traversal / LFI  (Lab4 LFI & Directory Traversal)
**7. Path Traversal · Easy · :8007 · 100 pts**
- `/download?file=report.txt` reads from a `files/` folder with no containment check.
  `?file=../../secret/flag.txt` escapes and reads the flag (kept outside `files/`).
- Fix: `realpath` + verify the resolved path stays under the allowed base dir.

**8. LFI — Filter Bypass · Hard · :8008 · 250 pts**
- Same idea, but a **naive filter** strips the literal `../` **once** (Ch07 evasion). Player bypasses with
  URL-encoding (`..%2f`) or nested `....//` (which collapses to `../` after one strip) to rebuild traversal → flag.
- Fix: decode fully, normalise, then containment-check; reject on any traversal.

### Type 5 — Insecure File Upload  (Lab5 DVWA upload)
**9. File Upload — Unrestricted · Easy · :8009 · 100 pts**
- Avatar uploader accepts any type; uploaded files are **served back** with a type guessed from extension.
  Upload an `.html`/`.svg` that calls the page's `solve()` (served same-origin) → flag. (Safe analogue of the
  DVWA shell-upload lab — "execution" is confined to the server returning the flag, no real RCE on the host.)
- Fix: allow-list extensions + validate content; serve uploads as `application/octet-stream` from a separate origin.

**10. File Upload — Filter Bypass · Hard · :8010 · 250 pts**
- Uploader blocks dangerous extensions **and** checks `Content-Type`, but weakly (Ch07): bypass via double
  extension (`shell.html.txt`→`shell.html`), case (`.HtMl`), or spoofed `Content-Type`. The smuggled file is
  then "executed"/rendered in the app context and returns the flag.
- Fix: strong allow-list, verify magic bytes, never trust client Content-Type, randomise stored names.

---

## 🧰 Implementation rules
- **English UI** everywhere (the engine is already English).
- Each challenge: `common.render(body, C["title"], self.challenge, result)` → gives header, **Hints** panel,
  and **flag-submit** box for free. Handle `POST /submit` with `self.handle_flag_submit()`.
- Mark the bug with `# ======= VULN HERE =======` and a one-line note of the correct fix.
- **Isolation & safety:** bind `127.0.0.1` only; keep all file/DB side effects inside the challenge folder
  (e.g. `files/`, `uploads/`, a local `app.db`); never execute attacker input as a real OS process; never make
  outbound network calls. Command-injection-style RCE is simulated in-process, not run on the host.
- Per-challenge `README.md`: scenario, course/lab reference, walkthrough, the correct fix.
- **`SOLUTIONS.md`**: every flag + a minimal exploit for each (instructor copy).
- **`solve_all.sh`**: programmatically exploit each challenge and assert the flag is returned, then submit it and
  check the scoreboard total. Run it and confirm all 10 pass before finishing.

## 🏁 Build order (test each before moving on)
1. `02_idor_hard` → 2. `03_sqli_easy` → 3. `04_sqli_hard` → 4. `05_xss_easy` → 5. `06_xss_hard`
→ 6. `07_lfi_easy` → 7. `08_lfi_hard` → 8. `09_upload_easy` → 9. `10_upload_hard`.
After each: run its `app.py`, exploit it, confirm the flag, then add its line to `solve_all.sh`.

## ➕ Optional swaps (also in our syllabus — offer if the instructor wants to replace a pair)
- **CSRF (Ch06):** GET-based `<img>` auto-fire + POST auto-submit form; defence = CSRF token + SameSite.
- **Content Discovery (Ch03/Lab2):** a `gobuster`-style hidden-file hunt (`robots.txt`, `backup.old`, `.git/`)
  that leaks the flag — pairs well as "Security Misconfiguration".
- **WAF/Filter Evasion (Ch07):** already woven into every **Hard** variant (blacklist/encoding bypass).

## 🎯 Definition of Done
- [ ] 10 challenges, each on its port; `run_all.py` starts them + the scoreboard.
- [ ] Every challenge has a working Hints button, flag box, and awards points once.
- [ ] `solve_all.sh` exploits all 10 and the scoreboard reaches **1750/1750**.
- [ ] `# VULN HERE` + README + fix for each; `SOLUTIONS.md` complete.
- [ ] Standard library only, `127.0.0.1` only, no outbound calls, no real host RCE.
