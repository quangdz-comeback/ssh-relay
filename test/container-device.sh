#!/usr/bin/env bash
# Container-device smoke test: linuxserver/openssh-server plays the device, so
# nothing on the host is touched (no authorized_keys edits, no system sshd).
# Requires podman or docker (DOCKER env overrides the binary).
#
# Covers: custom-alias registration banner, password bridge (user+alias),
# pubkey via agent (-A -o AddKeysToAgent=yes), the agent living INSIDE the
# device session (`ssh-add -l` executed on the device), and the JSON status
# endpoint. Any client-side chan_shutdown_read noise found in the output is
# reported but does not fail the run (it is an openssh client quirk).
set -u

cd "$(dirname "$0")/.."
ROOT="$PWD"
WORK="$(mktemp -d)"
DOCKER="${DOCKER:-docker}"
PASS=devpass
PORT_RELAY=21032
PORT_DEV=12232
PIDS=""
FAILS=0

cleanup() {
  [ -n "$PIDS" ] && kill $PIDS 2>/dev/null
  "$DOCKER" rm -f relay-dev-test >/dev/null 2>&1
  if [ "$FAILS" = 0 ]; then rm -rf "$WORK"; else echo "work dir kept: $WORK" >&2; fi
}
trap cleanup EXIT

fail() { echo "CONTAINER-E2E FAIL: $*" >&2; tail -20 "$WORK/relay.log" >&2; FAILS=1; exit 1; }
note() { echo "== $*"; }

export PATH="$PATH:/usr/local/go/bin"
make build >/dev/null 2>&1 || fail "build failed"

ssh-keygen -q -t ed25519 -N '' -f "$WORK/devkey" 2>/dev/null
"$DOCKER" rm -f relay-dev-test >/dev/null 2>&1
"$DOCKER" run -d --name relay-dev-test \
  -e PUID=1000 -e PGID=1000 -e TZ=UTC \
  -e PASSWORD_ACCESS=true -e USER_PASSWORD="$PASS" \
  -e USER_NAME=devuser \
  -e PUBLIC_KEY="$(cat "$WORK/devkey.pub")" \
  -p 127.0.0.1:$PORT_DEV:2222 \
  lscr.io/linuxserver/openssh-server:latest >/dev/null || fail "container failed to start"
for i in $(seq 1 40); do "$DOCKER" logs relay-dev-test 2>&1 | grep -q "Server listening" && break; sleep 0.5; done

printf '#!/bin/sh\necho %s\n' "$PASS" > "$WORK/askpass"
chmod +x "$WORK/askpass"
SSH_OPTS="-p $PORT_RELAY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR"

"$ROOT/relay" --listen-port $PORT_RELAY --ip 127.0.0.1 --hostname 127.0.0.1 \
  --data-dir "$WORK/relay-data" --log-level info > "$WORK/relay.log" 2>&1 &
PIDS="$!"
sleep 0.6

timeout 25 ssh $SSH_OPTS -T -R dockerbox:0:127.0.0.1:$PORT_DEV ssh@127.0.0.1 > "$WORK/banner.txt" 2>&1 &
PIDS="$PIDS $!"
sleep 1.5
grep -q "dockerbox" "$WORK/banner.txt" || fail "custom alias never registered"
note "custom alias registered"

OUT=$(env SSH_ASKPASS="$WORK/askpass" SSH_ASKPASS_REQUIRE=force setsid ssh $SSH_OPTS \
  "devuser+dockerbox@127.0.0.1" 'echo pw-bridge-ok; id -un' 2>/dev/null)
echo "$OUT" | grep -q "pw-bridge-ok" || { echo "$OUT"; fail "password bridge failed"; }
echo "$OUT" | grep -q "devuser" || fail "bridge landed on the wrong device user"
note "password bridge OK"

eval "$(ssh-agent -a "$WORK/agent.sock")" >/dev/null
PIDS="$PIDS $SSH_AGENT_PID"
OUT=$(env SSH_AUTH_SOCK="$WORK/agent.sock" ssh $SSH_OPTS -A -o AddKeysToAgent=yes \
  -o IdentitiesOnly=yes -i "$WORK/devkey" \
  "devuser+dockerbox@127.0.0.1" 'echo pubkey-agent-ok' 2>&1)
echo "$OUT" | grep -q "pubkey-agent-ok" || { echo "$OUT"; fail "pubkey via agent failed"; }
echo "$OUT" | grep "chan_shutdown_read" && note "client printed chan_shutdown_read noise (openssh client quirk, harmless)" || true
note "pubkey via agent OK"

FP=$(ssh-keygen -lf "$WORK/devkey.pub" | awk '{print $2}')
OUT=$(env SSH_AUTH_SOCK="$WORK/agent.sock" timeout 15 ssh $SSH_OPTS -A -o AddKeysToAgent=yes \
  -o IdentitiesOnly=yes -i "$WORK/devkey" \
  "devuser+dockerbox@127.0.0.1" 'echo "agent-sock:$SSH_AUTH_SOCK"; ssh-add -l' 2>&1)
echo "$OUT" | grep -q "agent-sock:" || { echo "$OUT"; fail "SSH_AUTH_SOCK missing inside device session"; }
echo "$OUT" | grep -q "$FP" || { echo "$OUT"; fail "agent inside device session does not list the key"; }
note "agent reachable inside device session OK"

OUT=$(env SSH_ASKPASS="$WORK/askpass" SSH_ASKPASS_REQUIRE=force setsid ssh $SSH_OPTS \
  "json@127.0.0.1" 'true' 2>/dev/null)
echo "$OUT" | grep -q '"alias": "dockerbox"' || { echo "$OUT"; fail "json status missing the tunnel"; }
echo "$OUT" | grep -q '"user+<alias>' || true
note "json status OK"

echo ""
echo "CONTAINER-E2E PASS: all scenarios green against linuxserver/openssh-server."
