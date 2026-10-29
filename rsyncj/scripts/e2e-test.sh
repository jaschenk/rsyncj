#!/usr/bin/env bash
#
# End-to-end test for rsyncj: starts a real TLS server, creates a user and exercises
# directory sync, delta reuse, deletion, single-file sync, dry-run, authentication,
# path-traversal protection, host-key pinning and the JSON stats APIs.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_JAR="$ROOT/rsyncj-server/target/rsyncj-server.jar"
CLIENT_JAR="$ROOT/rsyncj-client/target/rsyncj-client.jar"
WORK="$(mktemp -d /tmp/rsyncj-e2e.XXXXXX)"
PORT="${RSYNCJ_TEST_PORT:-18443}"
STATS_PORT="${RSYNCJ_TEST_STATS_PORT:-18444}"
PASSWORD="e2e-S3cret-passphrase"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok  $*"; }

if [[ ! -f "$SERVER_JAR" || ! -f "$CLIENT_JAR" ]]; then
  echo "Building project..."
  (cd "$ROOT" && mvn -q -DskipTests package)
fi

if ! command -v java >/dev/null 2>&1; then
  fail "java not found on PATH (JDK 25 required)"
fi
JAVA_VERSION="$(java -version 2>&1 | head -1)"
echo "Using $JAVA_VERSION"
echo "Work directory: $WORK"

mkdir -p "$WORK/src/sub/deep" "$WORK/data" "$WORK/state"
head -c 2000000 /dev/urandom > "$WORK/src/big.bin"
echo "hello world" > "$WORK/src/a.txt"
echo "nested" > "$WORK/src/sub/b.txt"
echo "deep" > "$WORK/src/sub/deep/c.txt"
: > "$WORK/src/empty.txt"

export RSYNCJ_PASSWORD="$PASSWORD"
java -jar "$SERVER_JAR" add-user alice --state "$WORK/state" >/dev/null

java -jar "$SERVER_JAR" serve \
  --root "$WORK/data" --state "$WORK/state" \
  --port "$PORT" --stats-port "$STATS_PORT" > "$WORK/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
  if python3 - "$PORT" <<'PY' 2>/dev/null
import socket, sys
s = socket.socket(); s.settimeout(0.5)
s.connect(("127.0.0.1", int(sys.argv[1]))); s.close()
PY
  then break; fi
  sleep 0.2
done
kill -0 "$SERVER_PID" 2>/dev/null || { cat "$WORK/server.log"; fail "server did not start"; }
echo "Server started on port $PORT"
echo

CLIENT=(java -jar "$CLIENT_JAR")
KNOWN=(--known-hosts "$WORK/known_hosts")
REMOTE="alice@127.0.0.1:$PORT"

echo "1. initial directory sync"
"${CLIENT[@]}" sync "$WORK/src" "$REMOTE:/backup" "${KNOWN[@]}" > "$WORK/out1.txt"
diff -r "$WORK/src" "$WORK/data/backup" >/dev/null || fail "initial sync differs"
pass "directory contents identical"

echo "2. delta transfer after inserting 100 KiB"
python3 - "$WORK/src/big.bin" <<'PY'
import sys
p = sys.argv[1]
data = open(p, "rb").read()
new = bytes(100000) + data[:len(data) - 50000]
new = bytearray(new)
new[500000:500010] = b"X" * 10
open(p, "wb").write(bytes(new))
PY
"${CLIENT[@]}" sync "$WORK/src" "$REMOTE:/backup" "${KNOWN[@]}" > "$WORK/out2.txt"
diff -r "$WORK/src" "$WORK/data/backup" >/dev/null || fail "delta sync differs"
grep -q "efficiency: 9" "$WORK/out2.txt" || fail "expected high delta efficiency, got: $(grep efficiency "$WORK/out2.txt")"
pass "delta sync correct ($(grep efficiency "$WORK/out2.txt" | tr -s ' '))"

echo "3. unchanged re-sync sends no data"
"${CLIENT[@]}" sync "$WORK/src" "$REMOTE:/backup" "${KNOWN[@]}" > "$WORK/out3.txt"
grep -q "data sent : 0 B" "$WORK/out3.txt" || fail "expected zero bytes sent: $(grep 'data sent' "$WORK/out3.txt")"
pass "zero-byte re-sync"

echo "4. --delete removes extraneous remote files"
rm -rf "$WORK/src/sub/deep"
echo "new" > "$WORK/src/new.txt"
"${CLIENT[@]}" sync "$WORK/src" "$REMOTE:/backup" "${KNOWN[@]}" --delete > "$WORK/out4.txt"
[[ ! -e "$WORK/data/backup/sub/deep" ]] || fail "extraneous directory not deleted"
diff -r "$WORK/src" "$WORK/data/backup" >/dev/null || fail "delete sync differs"
pass "deletion mirrored the source"

echo "5. single file sync (explicit name and trailing slash)"
echo "single file payload" > "$WORK/one.txt"
"${CLIENT[@]}" sync "$WORK/one.txt" "$REMOTE:/single/one.txt" "${KNOWN[@]}" >/dev/null
cmp "$WORK/one.txt" "$WORK/data/single/one.txt" || fail "single file content differs"
"${CLIENT[@]}" sync "$WORK/one.txt" "$REMOTE:/single/" "${KNOWN[@]}" >/dev/null
cmp "$WORK/one.txt" "$WORK/data/single/one.txt" || fail "trailing-slash single file differs"
pass "single file sync"

echo "6. dry-run does not modify the server"
echo "changed" >> "$WORK/src/new.txt"
"${CLIENT[@]}" sync "$WORK/src" "$REMOTE:/backup" "${KNOWN[@]}" --dry-run >/dev/null
grep -q "^new$" "$WORK/data/backup/new.txt" || fail "dry-run modified the destination"
"${CLIENT[@]}" sync "$WORK/src" "$REMOTE:/backup" "${KNOWN[@]}" >/dev/null
grep -q "^changed$" "$WORK/data/backup/new.txt" || fail "real sync after dry-run failed"
pass "dry-run left the destination untouched"

echo "7. wrong password is rejected"
if RSYNCJ_PASSWORD="wrong-password" "${CLIENT[@]}" sync "$WORK/one.txt" "$REMOTE:/x" "${KNOWN[@]}" > "$WORK/out7.txt" 2>&1; then
  fail "wrong password was accepted"
fi
grep -q "auth_failed" "$WORK/out7.txt" || fail "expected auth_failed, got: $(cat "$WORK/out7.txt")"
pass "authentication failure reported"

echo "8. path traversal is rejected"
if "${CLIENT[@]}" sync "$WORK/one.txt" "$REMOTE:/../../etc/evil" "${KNOWN[@]}" > "$WORK/out8.txt" 2>&1; then
  fail "path traversal was accepted"
fi
grep -qi "traversal" "$WORK/out8.txt" || fail "expected traversal rejection, got: $(cat "$WORK/out8.txt")"
pass "traversal rejected"

echo "9. changed server key is rejected"
cp "$WORK/known_hosts" "$WORK/known_hosts.bad"
sed -i 's/^\([^ ]*\) .*/\1 0000000000000000000000000000000000000000000000000000000000000000/' "$WORK/known_hosts.bad"
if "${CLIENT[@]}" sync "$WORK/one.txt" "$REMOTE:/x" --known-hosts "$WORK/known_hosts.bad" > "$WORK/out9.txt" 2>&1; then
  fail "host key mismatch was accepted"
fi
grep -q "HOST KEY MISMATCH" "$WORK/out9.txt" || fail "expected host key mismatch, got: $(cat "$WORK/out9.txt")"
pass "host key mismatch detected"

echo "10. stats over the authenticated protocol"
"${CLIENT[@]}" stats "$REMOTE" "${KNOWN[@]}" > "$WORK/stats.json"
python3 - "$WORK/stats.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["server"]["product"].startswith("rsyncj/"), s["server"]
assert s["syncs"]["filesSynced"] > 0, s["syncs"]
assert s["storage"]["files"] > 0, s["storage"]
assert any(f["path"].endswith("big.bin") for f in s["files"]), s["files"]
PY
pass "stats JSON is valid and populated"

echo "11. stats over HTTPS with bearer token"
TOKEN="$(cat "$WORK/state/stats-token")"
curl -sk -H "Authorization: Bearer $TOKEN" "https://127.0.0.1:$STATS_PORT/api/stats" > "$WORK/http-stats.json"
python3 - "$WORK/http-stats.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["syncs"]["total"] > 0
PY
CODE="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$STATS_PORT/api/stats")"
[[ "$CODE" == "401" ]] || fail "unauthenticated stats request returned $CODE"
[[ "$(curl -sk "https://127.0.0.1:$STATS_PORT/health")" == *'"ok"'* ]] || fail "health endpoint failed"
pass "HTTPS stats endpoint authorised and protected"

echo "12. stats survive a restart"
BEFORE="$("${CLIENT[@]}" stats "$REMOTE" "${KNOWN[@]}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["syncs"]["total"])')"
kill "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null || true
java -jar "$SERVER_JAR" serve --root "$WORK/data" --state "$WORK/state" \
  --port "$PORT" --stats-port "$STATS_PORT" >> "$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  python3 - "$PORT" <<'PY' 2>/dev/null && break
import socket, sys
s = socket.socket(); s.settimeout(0.5)
s.connect(("127.0.0.1", int(sys.argv[1]))); s.close()
PY
  sleep 0.2
done
AFTER="$("${CLIENT[@]}" stats "$REMOTE" "${KNOWN[@]}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["syncs"]["total"])')"
[[ "$AFTER" -ge "$BEFORE" ]] || fail "stats not restored ($BEFORE -> $AFTER)"
pass "cumulative stats restored ($BEFORE syncs)"

echo
echo "All end-to-end tests passed."
