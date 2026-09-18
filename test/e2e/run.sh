#!/usr/bin/env bash
# Real-OpenSSH end-to-end smoke test:
#   device (real sshd, password auth) --ssh -R--> relay <--ssh-- end user
# Covers: auto-ID registration banner, password bridge exec (root + user+alias),
# status JSON endpoint, TCP-forwarding refusal warning, custom alias.
set -u

cd "$(dirname "$0")/../.."
ROOT="$PWD"
WORK="$(mktemp -d)"
PIDS=""
E2E_PASS=0
cleanup() {
  [ -n "$PIDS" ] && kill $PIDS 2>/dev/null
  pkill -P $$ 2>/dev/null
  if [ "$E2E_PASS" = 1 ]; then rm -rf "$WORK"; else echo "work dir kept: $WORK" >&2; fi
}
trap cleanup EXIT

fail() { echo "E2E FAIL: $*" >&2; [ -f "$WORK/relay.log" ] && tail -20 "$WORK/relay.log" >&2; exit 1; }
note() { echo "== $*"; }

PORT_RELAY=21022
PORT_SSHD=22022
PASS=devpass
export SSH_ASKPASS_REQUIRE=force
export DISPLAY=:0

command -v sshd >/dev/null || fail "no sshd binary"
[ -x "$ROOT/relay" ] || fail "relay binary missing (run: make build)"

# ---------- device sshd (the machine behind NAT) ----------
mkdir -p "$WORK/sshd"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/sshd/hostkey" <<<y >/dev/null 2>&1
cat > "$WORK/sshd/sshd_config" <<EOF
Port $PORT_SSHD
ListenAddress 127.0.0.1
HostKey $WORK/sshd/hostkey
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PidFile $WORK/sshd/sshd.pid
LogLevel ERROR
EOF
mkdir -p /run/sshd
echo "root:$PASS" | chpasswd
/usr/sbin/sshd -D -f "$WORK/sshd/sshd_config" -E "$WORK/sshd/log" &
SSHD_PID=$!
PIDS="$PIDS $SSHD_PID"
sleep 0.5
note "device sshd up on :$PORT_SSHD"

# ---------- relay ----------
"$ROOT/relay" --listen-port "$PORT_RELAY" --ip 127.0.0.1 \
  --data-dir "$WORK/relay-data" --hostname 127.0.0.1 \
  --policy-file "$WORK/no-policy.json" --log-level info \
  > "$WORK/relay.log" 2>&1 &
RELAY_PID=$!
PIDS="$PIDS $RELAY_PID"
sleep 0.7
kill -0 "$RELAY_PID" 2>/dev/null || { cat "$WORK/relay.log"; fail "relay did not start"; }
note "relay up on :$PORT_RELAY"

SSH_OPTS=(-p "$PORT_RELAY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR)

# ---------- 1) register with auto deviceID ----------
timeout 25 ssh "${SSH_OPTS[@]}" -T -R 0:127.0.0.1:$PORT_SSHD ssh@127.0.0.1 > "$WORK/banner.txt" 2>/dev/null &
REG_PID=$!
for i in $(seq 1 50); do
  grep -q "Tunnel online:" "$WORK/banner.txt" 2>/dev/null && break
  sleep 0.1
done
ALIAS=$(grep -o 'Tunnel online: [^ ]*' "$WORK/banner.txt" | head -1 | awk '{print $3}')
[ -n "$ALIAS" ] || { cat "$WORK/banner.txt"; fail "no deviceID in banner"; }
note "registered auto alias: $ALIAS"
grep -q "ssh -p $PORT_RELAY $ALIAS@127.0.0.1" "$WORK/banner.txt" || fail "banner missing connect command"

# askpass helper for password prompts
cat > "$WORK/askpass" <<EOF
#!/bin/sh
echo "$PASS"
EOF
chmod +x "$WORK/askpass"
CLIENT_ENV=(SSH_ASKPASS="$WORK/askpass" SSH_ASKPASS_REQUIRE=force)

# ---------- 2) end user: root via alias, exec through the relay ----------
OUT=$(env "${CLIENT_ENV[@]}" setsid ssh "${SSH_OPTS[@]}" "root+$ALIAS@127.0.0.1" 'echo bridge-works-42; exit 0' 2>/dev/null)
echo "$OUT" | grep -q "bridge-works-42" || { echo "$OUT"; fail "bridge exec failed"; }
note "bridge exec (root+alias) OK"

# custom device user: run as the same root but address the user part
OUT=$(env "${CLIENT_ENV[@]}" setsid ssh "${SSH_OPTS[@]}" "$ALIAS@127.0.0.1" 'echo default-root-ok' 2>/dev/null)
echo "$OUT" | grep -q "default-root-ok" || { echo "$OUT"; fail "default-user bridge failed"; }
note "bridge exec (default root) OK"

# ---------- 3) status JSON endpoint ----------
OUT=$(env "${CLIENT_ENV[@]}" setsid ssh "${SSH_OPTS[@]}" "json@127.0.0.1" 'true' 2>/dev/null)
echo "$OUT" | grep -q "\"alias\": \"$ALIAS\"" || { echo "$OUT"; fail "status json missing binding"; }
echo "$OUT" | grep -q '"sessions"' || fail "status json missing sessions"
note "status endpoint OK"

# ---------- 4) TCP forwarding: allowed path + refusal path ----------
# 4a) client -L is ALLOWED: the relay mirrors direct-tcpip and the device
# dials. Reading from the forwarded port must yield the device sshd banner.
env "${CLIENT_ENV[@]}" setsid ssh "${SSH_OPTS[@]}" -L 12399:127.0.0.1:$PORT_SSHD "root+$ALIAS@127.0.0.1" -N > "$WORK/lfwd.log" 2>&1 &
LFWD_PID=$!
sleep 1.2
ss -tln 2>/dev/null | grep -q 12399 || fail "-L local listener missing"
BANNER=$(timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/12399 && head -c 32 <&3' 2>/dev/null || true)
case "$BANNER" in
  SSH-2.0-OpenSSH*) note "client -L through bridge OK (device sshd banner: $BANNER)" ;;
  "") fail "-L forward produced no data" ;;
  *) note "client -L through bridge OK (banner: $BANNER)" ;;
esac
kill "$LFWD_PID" 2>/dev/null
wait "$LFWD_PID" 2>/dev/null

# 4b) --allow-tcp-forwarding=false: same -L must be refused with the exact
# warning text.
PORT_RELAY2=$((PORT_RELAY + 1))
"$ROOT/relay" --listen-port "$PORT_RELAY2" --ip 127.0.0.1 \
  --data-dir "$WORK/relay-data2" --hostname 127.0.0.1 \
  --allow-tcp-forwarding=false \
  --policy-file "$WORK/no-policy.json" --log-level info \
  > "$WORK/relay2.log" 2>&1 &
RELAY2_PID=$!
PIDS="$PIDS $RELAY2_PID"
sleep 0.5
SSH_OPTS2=(-p "$PORT_RELAY2" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=DEBUG)
timeout 25 ssh "${SSH_OPTS2[@]}" -T -R 0:127.0.0.1:$PORT_SSHD ssh@127.0.0.1 > "$WORK/banner3.txt" 2>/dev/null &
REG3_PID=$!
for i in $(seq 1 50); do
  grep -q "Tunnel online:" "$WORK/banner3.txt" 2>/dev/null && break
  sleep 0.1
done
ALIAS2=$(grep -o 'Tunnel online: [^ ]*' "$WORK/banner3.txt" | head -1 | awk '{print $3}')
[ -n "$ALIAS2" ] || fail "no deviceID from gated relay"
env "${CLIENT_ENV[@]}" setsid ssh "${SSH_OPTS2[@]}" -L 12400:127.0.0.1:$PORT_SSHD "root+$ALIAS2@127.0.0.1" -N > "$WORK/lfwd2.log" 2>&1 &
LFWD2_PID=$!
sleep 1.2
( exec 3<>/dev/tcp/127.0.0.1/12400 ) 2>/dev/null
sleep 0.5
kill "$LFWD2_PID" "$REG3_PID" "$RELAY2_PID" 2>/dev/null
wait "$LFWD2_PID" 2>/dev/null
grep -qF '[WARNING] TCP forwarding is not supported.' "$WORK/lfwd2.log" \
  || { echo "---- lfwd2.log ----"; tail -5 "$WORK/lfwd2.log"; fail "TCP forwarding warning not shown"; }
note "TCP forwarding refusal warning OK (gated relay)"

# ---------- 5) custom alias registration ----------
timeout 25 ssh "${SSH_OPTS[@]}" -T -R myvps:0:127.0.0.1:$PORT_SSHD ssh@127.0.0.1 > "$WORK/banner2.txt" 2>/dev/null &
REG2_PID=$!
for i in $(seq 1 50); do
  grep -q "Tunnel online: myvps" "$WORK/banner2.txt" 2>/dev/null && break
  sleep 0.1
done
grep -q "Tunnel online: myvps" "$WORK/banner2.txt" || { cat "$WORK/banner2.txt"; fail "custom alias registration failed"; }
OUT=""
for i in 1 2 3; do
  OUT=$(env "${CLIENT_ENV[@]}" setsid ssh "${SSH_OPTS[@]}" "myvps@127.0.0.1" 'echo custom-alias-ok' 2>&1)
  echo "$OUT" | grep -q "custom-alias-ok" && break
  sleep 0.7
done
echo "$OUT" | grep -q "custom-alias-ok" || { echo "$OUT"; fail "custom alias bridge failed"; }
note "custom alias OK"

kill "$REG_PID" "$REG2_PID" 2>/dev/null
E2E_PASS=1
echo ""
echo "E2E PASS: all real-OpenSSH scenarios green."
