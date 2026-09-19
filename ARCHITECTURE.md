# ARCHITECTURE.md — SSH Forwarding Relay (`relay`)

Companion to [PLAN.md](PLAN.md). This document fixes the technical design:
protocols, components, data flow, state, security model, and module layout.

---

## 1. System overview

```
                 Internet
                    │
   device dials out │ end user connects in
   (control conn)   │ (client conn)
        │           │
        ▼           ▼
┌────────────────────────────────────────────────────────────────┐
│                    relay  (single static binary)               │
│                                                                │
│   ┌──────────────────────────────────────────────────────┐     │
│   │ sshd front door (golang.org/x/crypto/ssh)            │     │
│   │   role router: username "ssh" → DEVICE               │     │
│   │                username [user"+"]alias → CLIENT      │     │
│   └───────────┬──────────────────────────┬───────────────┘     │
│               │                          │                     │
│   ┌───────────▼──────────┐    ┌──────────▼──────────────────┐  │
│   │ device plane         │    │ client plane                │  │
│   │  tcpip-forward hand. │    │  auth pass-through          │   │
│   │  registry claims     │    │  session mirroring          │  │
│   │  control shell       │    │  direct-tcpip · sftp/scp/x11│  │
│   └───────────┬──────────┘    └──────────┬──────────────────┘  │
│               │      ┌─────────┐         │                     │
│               └─────▶│registry │◀────────┘                     │
│                      └─────────┘                               │
│   ┌──────────────────────────────────────────────────────┐     │
│   │ cross-cutting: bw throttle · ip-session limiter ·    │     │
│   │ fail2ban · keepalives · slog                         │     │
│   └──────────────────────────────────────────────────────┘     │
└───────────────┬────────────────────────────────────────────────┘
                │  bridge channels ride INSIDE the control conn
                ▼
      device sshd @ 127.0.0.1:22
```

One listening port serves both roles. Everything is multiplexed over the two
SSH connection types; the relay never opens a data port per binding.

---

## 2. The core design decision: two-phase SSH

**Requirement:** `ssh user+alias@relay…` must work with a plain ssh client — no
`ProxyCommand`, no per-device TCP port.

**Why we cannot just splice bytes (transparent TCP proxy):**

1. SSH has no SNI. The username — our only routing key — lives *inside* the
   encrypted stream, after key exchange. A TCP-level splice cannot know which
   device a connection belongs to before the handshake has already committed
   to the relay as the peer.
2. Once the client has completed KEX with the relay, feeding the session bytes
   to the device's sshd fails: the device sshd expects an SSH version banner as
   the first bytes of a fresh TCP connection, not mid-session terminal data.

**Therefore the relay terminates SSH twice (two-phase SSH):**

- **Phase 1 — client ⇄ relay:** relay is the SSH *server*; owns the host key the
  client sees; accepts the user's credentials.
- **Phase 2 — relay ⇄ device:** relay is the SSH *client* toward the device's
  sshd, tunneled through a `forwarded-tcpip` channel on the control connection.
- The relay then mirrors session-level SSH requests between the two and splices
  channel data. It is an **SSH session bridge**, not a TCP proxy.

**Consequences (accepted, documented):**

- The client sees the relay's host key, never the device's. Fine for a public
  relay service; the device's host key is verified by the relay's client
  handshake in TOFU/log-only mode (§11).
- Public-key pass-through cannot replay the client's signature: a `publickey`
  signature binds the *session ID* of the connection it was made on, so a
  signature made against the relay is invalid at the device. The shipped
  solution is agent forwarding (§5.2): the user's own ssh-agent signs the
  **device's** challenge, so the device still verifies the user's real key and
  the private key never leaves the client. Password and keyboard-interactive
  credentials forward cleanly as before. This drives the auth model in §5.

**Rejected alternative:** allocate a real TCP port per device (frp/boringproxy
style) and document `ssh -p <port> root@relay…`. Works, trivially transparent,
but violates the required UX (`alias` as username, single port).

---

## 3. Connections and the username grammar

Both connection types arrive at the same listener and are classified purely by
the SSH username in `userauth-request`:

```
grammar:
  username := "ssh"                    → DEVICE role (control connection)
  username := [ device-user "+" ] alias → CLIENT role (session bridge)

  alias        := generated "d-" + 10 Crockford base32 chars
                | custom name matching ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$
                 (1–63 chars total, lowercase, no "d-" prefix)
  device-user  := ^[a-zA-Z0-9._][a-zA-Z0-9._-]{0,31}$   (default: "root")
```

Parsing: `strings.SplitN(username, "+", 2)` — user part before the first `+`
(alias charset excludes `+`, so this is unambiguous).

Reserved usernames: `ssh` (device role), `ssh+json` (device role with JSON
control output, §4.4 — still a full forwarding login), `json` (status endpoint,
§4.4 — bare, exact match only, so the alias `json` cannot be registered), plus
`help`, `keys`, `version` (reserved for M6 control commands; auth-fail in v1).
Anything that does not parse as a valid alias is an auth failure → fail2ban
counter (if enabled).

Bind-address → alias mapping when handling the device's `tcpip-forward`:

| `-R` listen address sent by ssh | Alias chosen |
|---|---|
| `""` (from `-R 0:host:port`), `0.0.0.0`, `*`, `localhost` | generate `d-XXXXXXXXXX` |
| `custom-name` (from `-R custom-name:0:host:port`) | `custom-name` (validated) |
| anything else invalid | `tcpip-forward` refused |

The listen **port** in `-R` is not a real port: `0` is the registration form;
asking for a real listening port is refused (§6.2) — the relay exposes no TCP
sockets.

---

## 4. Device plane (control connections)

### 4.1 Registration sequence

```
Device (ssh -R)                         relay                                    Device sshd
     │  TCP :2222                          │                                            │
     │  SSH transport+auth user="ssh"      │                                            │
     │  ─────────────────────────────────▶ │  (accept any method; mark conn DEVICE)     │
     │  global req "tcpip-forward"         │                                            │
     │   addr="", port=0                   │                                            │
     │  ─────────────────────────────────▶ │ generate alias d-7k2m9xq4tz                │
     │                                     │ registry.bind(alias, conn, "127.0.0.1:22") │
     │  ◀── reply: bound port = 0 ─────────│                                            │
     │  open session "shell"               │                                            │
     │  ─────────────────────────────────▶ │ control shell: print info, block           │
     │  keepalive@openssh.com every 30s …  │                                            │
```

Notes:

- `bound port = 0` in the reply is intentional: OpenSSH ignores the value for
  our purposes (we never open a TCP listener).
- Multiple `-R` flags on one control connection create multiple bindings; the
  control shell lists all of them.
- `cancel-tcpip-forward` (graceful ssh exit) or any connection teardown unbinds
  immediately and closes all live bridges for that alias.
- Alias conflict: `registry.bind` fails → the `tcpip-forward` request is refused
  (`ADMINISTRATIVELY_PROHIBITED`); control shell explains. v1 policy is
  last-writer-wins on reconnect *by the same key only if the old conn is dead*;
  a live binding is never silently stolen in v1.

### 4.2 Control shell

A fake session channel handler that writes the banner (§4 of PLAN), then blocks
on a `chan struct{}` closed at teardown. This is what keeps `ssh -R …` alive
without `-N`, and how the operator learns the `deviceID` (OpenSSH prints
nothing about assigned forwards by default; with `-N` the ID is only in relay
logs — custom aliases are the escape hatch, documented).

Input is watched from the moment the channel opens: with a PTY the client
terminal is in raw mode, so `Ctrl+C` (`0x03`) or `Ctrl+D` (`0x04`) close the
control connection — the tunnel tears down exactly like a network loss.
Output is LF→CRLF-converted when a PTY was allocated (raw-mode terminals
staircase on bare `\n`); piped `ssh+json` clients keep clean LF for `jq`.

### 4.3 Bridge channel opening (relay → device)

When a client session starts, the relay opens a `forwarded-tcpip` channel **on
the control connection** (server-initiated channel open — exactly the mechanism
OpenSSH itself uses to deliver remote-forward connections):

```
open "forwarded-tcpip"
  connected address = alias        (e.g. "myvps")
  connected port    = 22           (virtual; device sshd ignores)
  originator        = relay-side peer info
→ device sshd dials the binding's target (127.0.0.1:22)
→ ssh.Channel  ⇄  net.Conn adapter
```

The device's sshd needs no special config beyond a normal working sshd: this is
standard remote-forward delivery. (If the device set `DisableForwarding yes`,
registration would still succeed but every bridge fails — surfaced in logs.)

### 4.4 Machine-readable JSON: `ssh+json` (forward-capable) and `json` (status only)

Two usernames emit the same JSON status document; they differ in what else the
connection does:

| Username | Role | Forwarding | Behavior |
|---|---|---|---|
| `ssh+json` | DEVICE (variant of `ssh`) | **yes** — full `-R` registration | control shell prints the JSON document **after the `-R` requests are processed** (so the document already contains the new bindings, deviceID included), then blocks holding the tunnel like the normal control shell |
| `json` | STATUS (bare, exact match) | **no** — any `tcpip-forward` is refused with the standard warning text | prints the JSON document and closes; exit 0, no interactive dashboard |

```
Device: ssh -R 0:… ssh+json@relay                Status: ssh json@relay
   │ auth "ssh+json" (role=DEVICE)                  │ auth "json" (role=STATUS)
   │ tcpip-forward → bind (§4.1)                    │ policy snapshot + ip counters
   │ open session                                   │ open session (TTY optional)
   │ ◀── JSON document (incl. new bindings) ────────│ ◀── JSON document ─────│
   │ control shell blocks (tunnel held)             │ EOF, exit 0
```

Output schema — one JSON document plus newline, `jq`-friendly. It is an
envelope object (not a bare array) so an IP with zero tunnels still receives
its quota; `bindings` is the array:

```json
{
  "ip": "203.0.113.10",
  "relay_version": "0.1.0",
  "sessions": { "used": 1, "allowed": 3 },
  "bindings": [
    {
      "alias": "d-7k2m9xq4tz",
      "listen_address": "(auto)",
      "created_at": "2026-09-18T06:12:31Z",
      "ssh_command": "ssh d-7k2m9xq4tz@relay.example.com",
      "custom_user_template": "ssh <user>+d-7k2m9xq4tz@relay.example.com",
      "bridges_used": 0,
      "bridges_max": 10
    }
  ]
}
```

- `created_at` is RFC3339 UTC; `ssh_command` / `custom_user_template` are built
  from the display host (`--hostname` flag → policy.json `"hostname"` →
  auto-detected public IP at startup) and carry `-p <port>` when the listener
  is not on 22.
- `sessions.used` counts live authenticated connections from the requesting IP
  **excluding the querying connection itself** (it answers "how many of my
  slots are taken by real traffic"); `allowed` = the effective policy's
  `MaxSessionsPerIP` (§6.3).
- Device automation pattern: register with `ssh+json`, read the first JSON
  document from stdout to learn the `deviceID` / connect commands, then keep
  the process running (systemd) — the tunnel stays up.
- Session requests (shell/exec/pty) are accepted on both but ignored; on
  `json` the connection closes right after the document. No other channels and
  no global requests are honored on either.
- No credentials required for either: the document only exposes what the
  requesting IP already owns, and using a binding still requires the device's
  credentials.

---

## 5. Client plane (session bridging)

### 5.1 Sequence

```
Client ssh                            relay                            Device sshd (via tunnel)
   │ TCP; KEX with relay host key       │                                     │
   │ userauth "deploy+myvps"            │                                     │
   │ ─────────────────────────────────▶ │ parse: user="deploy" alias="myvps"  │
   │                                    │ registry.lookup → live binding      │
   │                                    │ open forwarded-tcpip ──────────────▶│ dial 127.0.0.1:22
   │                                    │ ssh.ClientConn (Phase-2 handshake)  │
   │                                    │ userauth: none → password(deploy) ─▶│
   │ ◀── USERAUTH_SUCCESS ──────────────│ ◀───────────── success ─────────────│
   │ open "session"                     │ open "session" (device conn)        │
   │ pty-req / env(TERM) / shell ──────▶ │ mirror pty-req / env / shell ─────▶│
   │ ═══════ data splice (bw-limited) ═══════════════════════════════════════│
   │ window-change / signal ──────────▶  │ mirror ───────────────────────────▶│
   │ ◀── exit-status / exit-signal ──────│ ◀──── exit-status ─────────────────│
```

### 5.2 Auth pass-through (per bridge attempt)

The relay's `KeyboardInteractiveCallback`/`PasswordCallback`/none-auth handler
does not make a relay-local decision; it *performs the device login*:

| Client offers | Relay action | On device failure |
|---|---|---|
| `none` | try device `none` (passwordless sshd) | respond auth-failure to client (client falls through to password) |
| `password` | try device `password` with the received password | respond auth-failure; count for fail2ban |
| `keyboard-interactive` | check the tunnel first: missing/saturated tunnels are named in the challenge instruction (`No live tunnel for …` / `session capacity`) and the answer is refused without dialing; a live tunnel collects answers and tries device `password` then `keyboard-interactive` | same |
| `publickey` | accept the key (x/crypto verifies the client's signature over the relay session ID) and **defer** the device login: at the first session/forwarding open, the relay opens `auth-agent@openssh.com` back to the client and the forwarded agent signs the device's challenge (§5.2) | session/forward open rejected with the reason; agentless key = `-A` hint (never counts for fail2ban), device refusal = fail2ban failure |
| `hostbased` | reject | — |

#### 5.2.1 Deferred publickey login (agent pass-through)

1. **Auth phase.** The relay's `PublicKeyCallback` records the verified client
   key and reserves a bridge slot; **no device dial happens** — the agent
   channel only exists once the client's session setup starts. A missing
   tunnel or full bridge slot still rejects here, so the client falls back to
   password auth exactly like before.
2. **Completion phase.** When the client opens a `session` channel, the relay
   accepts it and reads the setup requests first: `auth-agent-req@openssh.com`
   is the protocol's only `-A` signal, and the relay opens
   `auth-agent@openssh.com` toward the client **only after seeing it** — an
   unconditional open makes openssh print its "agent forwarding break-in
   attempt" warning. With the signal present the relay lists the agent's
   signers, orders the client-authenticated key first, and dials the device
   with those publickeys. The agent channel stays open until the handshake
   finishes: signature requests arrive mid-handshake. The buffered setup
   requests (pty-req, env, auth-agent-req) are replayed to the device session,
   so the bridge is indistinguishable from a direct one (the replayed
   pty-req's reply stays local — the client blocks on it). `direct-tcpip`
   logins have no session to carry the signal and probe the agent as before.
   The device applies its own `authorized_keys` policy — the relay adds no
   trust.
3. **Failure mapping.** A session that starts without the auth-agent-req
   signal is not probed at all: the relay answers the client's start request,
   prints the recovery hint on the live session's stderr (CRLF under a PTY),
   and closes with exit status 1 — no openssh warning noise, visible at every
   log level. Agent present but unreachable / empty keyring → the `-A` +
   `ssh-add` / `-o AddKeysToAgent=yes` hint (user setup mistake, never a
   fail2ban failure); the device refusing every offered key → the
   `authorized_keys` hint, counted as a credential failure. Every hint ends
   with the password escape `ssh -o PubkeyAuthentication=no <user>@<host>`:
   clients offer their default keys automatically, so a "password" user often
   reaches the pubkey path without knowing it (their key was accepted, and no
   password prompt ever appeared).
4. **Inside the session.** On a public-key login the relay also mirrors the
   client's `auth-agent-req@openssh.com` to the device session and pairs the
   device's `auth-agent@openssh.com` opens back to the client, so the agent is
   live *inside* the remote session (hop to further hosts, git over SSH, …).
   Password/none logins refuse the request with
   `agent forwarding requires public key auth` — auto-disabled, since the key
   plays no role there. There is no relay-side flag: the client's `-A` is the
   only switch, so nothing to enable or disable server-side. Standard SSH
   caveat applies: while the session lives, root on the device can use the
   forwarded agent — forward only to devices you trust.

Implementation notes:

- Each auth attempt dials the device **fresh** (one Phase-2 handshake per
  attempt); the successful connection is retained for the session. Device-side
  sshd never sees concurrent auth games on one connection.
- Passwords live only in flight (goroutine stack); never logged, never stored.
- Because auth success = device login success, relay-side auth and bridge
  establishment are the same step for none/password/keyboard-interactive —
  there is no window where an "authenticated" client has no device session.
  Publickey is the one deferred exception (§5.2.1): the login completes at the
  first session/forwarding open, where a failure surfaces as a channel-open
  rejection instead of an auth failure.

### 5.3 Session request mirroring

The relay accepts exactly one `session` channel per client connection (v1;
matches common `ssh` behavior, keeps pairing simple). Requests are mirrored
1:1 onto the device session:

| Client sends | Relay action |
|---|---|
| `pty-req` | mirror verbatim (term env, width/height, modes) |
| `env` | mirror only allow-list (`TERM`, `LANG`) — drop others (leak/clobber protection) |
| `shell` | mirror |
| `exec` `cmd` | if `cmd` starts with `"scp "` → gate on `--allow-scp`; else mirror |
| `subsystem` `sftp` | gate on effective `--allow-sftp`, then mirror |
| `x11-req` | gate on `--allow-x11-forwarding`, then mirror verbatim - the end user's openssh client owns the fake-cookie translation, so pairing device-side `x11` opens back to the client is plain splicing (drain loop, client.go) |
| `signal` | mirror (INT, TERM, HUP, KILL, QUIT, USR1, USR2) |
| `window-change` | mirror |
| `auth-agent-req@openssh.com` (`-A`) | public-key logins: mirror verbatim so the device's sshd wires `SSH_AUTH_SOCK`, and pair the device's agent channels back to the client (§5.2.1). password/none logins: refused with `agent forwarding requires public key auth` — the client disables forwarding instead of silently missing the agent. A device that refuses the mirrored request disables it on its side. No relay flag: the client's `-A` is the only switch |
| `break` | ignore + ok |
| unknown requests | reply `failure`, never forward |

Gate references above resolve through the connection's **effective policy**
(§6.3) — the CLI flags only seed the global default layer.

Shutdown mapping: device session EOF → close client channel; client EOF → close
device session; missing `exit-status` on close → send 255 (OpenSSH convention).

### 5.4 Data plane

Per bridge, two pump goroutines:

```
clientCh (x/crypto/ssh.Channel)  ⇄  [throttle.Reader/Writer]  ⇄  deviceCh
```

- Splice is `io.Copy` between the (buffered) channels; backpressure is native —
  SSH channel windows on both sides stop the writer when the reader stalls.
- `throttle.Reader`/`Writer` wrap a token bucket (§7.3) on each direction when
  `--bw-limit != unlimited`.
- Extended data (stderr) keeps its type: a third pump copies the device
  channel's stderr into the client channel's extended-data writer.
- Every pump exits on: channel close, connection teardown, ctx cancel, or
  60 s write-stall deadline. A per-bridge `sync.WaitGroup` guards leaks;
  `go test -race` + e2e soak cover it.

### 5.5 Client-side TCP forwarding (`-L` / `-D`)

Client connections may forward TCP through the bridge. The relay never dials
anything itself — each client `direct-tcpip` open is mirrored as a
`direct-tcpip` open on the Phase-2 device connection, so the device's sshd
performs the dial (and enforces its own `AllowTcpForwarding` policy):

```
Client (ssh -D 1080)              relay                         Device sshd
   │ SOCKS CONNECT target:port      │                               │
   │ open "direct-tcpip" t:p ──────▶│ open "direct-tcpip" t:p ─────▶│ dial t:p (device egress)
   │ ══════════ spliced, throttled both ways (same pumps as §5.4) ══│
   │ ◀── open failure (if device refuses) relayed verbatim ─────────│
```

- One upstream channel per forwarded connection; a `-D` session naturally
  opens many channels — capped per §7.4.
- Device-side refusal (target unreachable, `AllowTcpForwarding no`) is passed
  back to the client unchanged.
- Real-port `tcpip-forward` requests (client `-R`) remain refused: the relay
  exposes no listening sockets (§6.1).

---

## 6. Policy model & request matrix (enforcement points)

Connection classes: §6.1 covers **client** connections, §6.2 **device**
connections (`ssh` and its JSON-output variant `ssh+json`, which forwards
normally). The third class — **status** (bare `json`, §4.4) — accepts one
session, prints the JSON document, closes, and honors no channels or global
requests.

### 6.1 Client connection (`alias@…`, `user+alias@…`)

| Incoming | Gate | Behavior |
|---|---|---|
| channel open `session` | alias live + caps | bridge (§5); pubkey connections complete the deferred agent login after the client's `auth-agent-req` signal (§5.2.1) — failures are explained on the live session (reason on stderr, exit 1) |
| channel open `direct-tcpip` (`-L`, `-D`) | `--allow-tcp-forwarding` (effective, §6.3) + channel cap | mirror as `direct-tcpip` on the Phase-2 device connection (device dials); splice with throttle; device-side open failures relayed back verbatim; when gated off, refusal with `[WARNING] TCP forwarding is not supported.`; pubkey connections complete the deferred agent login here as well |
| global `tcpip-forward` (`-R <port>:…` from the client) | **denied** | request-failure, reason `[WARNING] TCP forwarding is not supported.` |
| global `cancel-tcpip-forward` | — | ack, no-op |
| channel open `x11` | `--allow-x11-forwarding` | client-initiated opens never occur; device-initiated x11 opens are paired back to the client when the gate allows (drain loop, client.go) |
| channel open `auth-agent@openssh.com` | — | client-initiated opens are drained (some clients open it themselves); pubkey connections open it toward the client for the deferred login (§5.2.1), and device-initiated agent opens (session forwarding) are paired back to the client on pubkey logins |

### 6.2 Device connection (control, `ssh@…`)

| Incoming | Gate | Behavior |
|---|---|---|
| global `tcpip-forward`, port 0 (form `[alias:]0:target`) | valid alias + free | bind + reply bound port 0 |
| global `tcpip-forward`, port > 0 (`-R <port>:…` — real port toward the relay) | **denied** | request-failure + `[WARNING] TCP forwarding is not supported.` |
| channel open `direct-tcpip` (`-L`/`-D` from the device operator) | **denied** | open-failure, reason `[WARNING] TCP forwarding is not supported.` |
| session open | one | control shell — a JSON document instead of the banner when the login was `ssh+json` (§4.4) |
| everything else | denied | failure |

The registration `-R` (port 0) is a *virtual* binding — no TCP socket is ever
opened on the relay. Anything that would require a real listening socket is a
refusal (FR-13 in PLAN.md).

### 6.3 Effective policy & `policy.json` (per-IP overrides)

All gate flags (`--allow-tcp-forwarding`, `--allow-sftp`, `--allow-scp`,
`--allow-x11-forwarding`), `--bw-limit` and `--allowed-sessions-per-ip` are just
the **global defaults**. A connection's effective policy is layered at accept
time:

```
builtin defaults  ⊕  policy.json .default  ⊕  explicitly set flags  ⊕  first custom_policies[i]
   (code)           (fields present only)      (conflict → flag wins,   whose cidrs contain the
                                                 unset flags defer)     connection source IP
                                                                       (fields present only)
```

File format — strict schema (unknown fields are a load error); first match in
`custom_policies` order wins; absent fields inherit from the previous layer:

```json
{
  "listen_ip": "",
  "hostname": "",
  "default": {
    "allow_tcp_forwarding": true,
    "allow_sftp": true,
    "allow_scp": true,
    "allow_x11_forwarding": false,
    "bw_limit": "unlimited",
    "max_sessions_per_ip": 3
  },
  "custom_policies": [
    {
      "name": "office",
      "cidrs": ["203.0.113.10/32", "198.18.0.0/15"],
      "policy": { "bw_limit": "100M", "max_sessions_per_ip": 10 }
    },
    {
      "name": "locked-down-guests",
      "cidrs": ["192.0.2.0/24"],
      "policy": { "allow_tcp_forwarding": false, "allow_sftp": false, "bw_limit": "1M" }
    },
    {
      "name": "banned",
      "cidrs": ["198.51.100.7/32"],
      "policy": { "blocked": true, "reason": "abuse — contact ops" }
    }
  ]
}
```

Semantics:

- **Evaluation point:** the source IP is known at TCP accept, before userauth.
  The effective policy is computed once per connection and snapshotted on the
  connection state; every gate (client `direct-tcpip`, sftp/scp/x11, per-IP
  session limit, per-connection bw limit) reads the snapshot. It applies to
  device and client connections alike — a `blocked` IP can neither register
  tunnels nor bridge sessions.
- **`blocked: true`** drops the connection pre-auth and logs `reason` — the
  cheapest possible rejection, and it never reaches fail2ban accounting.
- **Path & reload:** `--policy-file` (default `policy.json` in the working
  directory). A watcher goroutine stats the file every 5 s (plus SIGHUP). A new
  file is parsed and validated off-line, then swapped atomically
  (`atomic.Pointer[PolicySet]`); live connections keep their snapshot, new
  connections get the new policy.
- **Failure handling:** missing file = flags-only (normal); invalid file at
  startup = exit non-zero (fail-closed — a typo must not silently widen policy
  on a mass deploy); a reload that fails validation keeps the last good set and
  logs the error.
- **Flag precedence:** a knob passed explicitly on the command line overrides
  the same knob in the `default` block (tracked via flag-set detection);
  unpassed flags defer to the file. `custom_policies` always apply on top for
  matched IPs. `--fail2ban` is a global switch outside this layering, and
  `--ip`/`listen_ip` plus `hostname` only take effect at startup (never
  hot-reloaded) — `hostname` sets the display host for printed SSH commands
  unless `--hostname` was passed explicitly.

```go
type Policy struct {
    AllowTCPForwarding              bool
    AllowSFTP, AllowSCP, AllowX11   bool
    BWLimit                         string // "unlimited" | "10M" | … (same grammar as --bw-limit)
    MaxSessionsPerIP                int
    Blocked                         bool
    BlockReason                     string
}

type PolicySet struct {
    Default Policy
    Custom  []CustomPolicy // {Name string, CIDRs []netip.Prefix, Policy Policy}
}

// effective(ip netip.Addr) Policy — pure first-match overlay, cheap enough to
// run once per connection.
```

---

## 7. Limits & protection

### 7.1 Per-IP session limiter (`--allowed-sessions-per-ip`, default 3)

- Counted at *post-auth* per SSH connection (device and client connections count
  equally), keyed by source IP, released on disconnect (`sync.Map` of counters +
  `net.JoinHostPort` normalization; IPv4 only for v1 accounting, IPv6 /64
  prefix accounting noted as TODO).
- The effective per-IP limit comes from the connection's policy snapshot (§6.3);
  `--allowed-sessions-per-ip` seeds the global default.
- Over-limit: auth succeeds, then connection is closed with
  `Too many sessions from your IP; try again later.` (pre-auth close keeps it
  out of fail2ban counting).

### 7.2 Built-in fail2ban (`--fail2ban`, default true)

```
on auth failure(ip):      fails[ip] = append(window, now)
if count(ip, 10m) >= 5:   ban[ip] = now + 1h;  reset fails
on repeat while banned:   ban extends ×2, cap 24h
on auth success(ip):      clear window (legit user mistyping once is fine)
```

- In-memory only; checked before userauth is processed. Pre-auth protocol
  violations (garbage before banner, KEX timeout) count as failures too.
- All thresholds are package constants in v1 (documented here, tunable via
  constants; flags stay at the user-specified surface).

### 7.3 Bandwidth limiter (`--bw-limit`)

- Semantics: **bytes/second, per connection, per direction**; `10K` = 10 KiB/s
  (K=1024). `unlimited` disables wrapping entirely (zero overhead path). The
  per-connection limit comes from the effective policy (§6.3); `--bw-limit`
  seeds the global default.
- Implementation: `golang.org/x/time/rate.Limiter` with
  `burst = max(limit, 64 KiB)`, `WaitN` before each read/write chunk; placed as
  the `io.Reader`/`io.Writer` wrapper in both pump directions (§5.4).

### 7.4 Caps and timeouts

| Guard | Value (v1) |
|---|---|
| Handshake/auth grace (pre-auth) | 30 s, then drop |
| Keepalive (both conn types) | `keepalive@openssh.com` every 30 s, 3 misses → drop |
| Max bindings per control conn | 8 |
| Max concurrent bridges per alias | 10 |
| Max total authenticated conns | 1024 (reject new with "server busy") |
| Max channels per client connection | 64 (`-D`/SOCKS opens many) |
| Max channels per device connection | 16 |
| Device dial (bridge) timeout | 10 s |

---

## 8. State model

All state is in-memory, owned by `registry.Registry` (mutex-protected):

```go
type Registry struct {
    mu      sync.RWMutex
    byAlias map[string]*Binding
}

type Binding struct {
    Alias   string
    Device  *ssh.ServerConn // control connection; identity for teardown
    Target  string          // "127.0.0.1:22"
    Created time.Time
    Bridges atomic.Int32
}

// lifecycle: bind on tcpip-forward, unbind on conn close/cancel,
// lookup on every client auth. Bindings are never persisted in v1.
```

Disconnect handling is event-driven off the control connection's context: when
`ServerConn.Wait()` returns, every binding owned by that connection is removed
and each live bridge's context is cancelled (clients see immediate close).

Registry queries are read-mostly: alias lookup per client auth, plus an
owner-IP scan for the JSON endpoints (§4.4), both under `RLock` — binding
counts are small enough that a scan beats an index.

**Host key:** Ed25519 keypair generated on first boot, PEM at
`<data-dir>/host_ed25519` (0600). Fingerprint logged at startup. This is the
only durable state the relay has.

The active `PolicySet` (§6.3) is also memory-only — held behind an
`atomic.Pointer` and swapped atomically on reload; it is never persisted.

---

## 9. Repo layout

```
ssh-relay/
├── cmd/relay/main.go           # flags → config → server.Run; signal handling
├── internal/
│   ├── config/config.go        # flag defs, bw parser, validation, defaults
│   ├── server/server.go        # listener, ssh.ServerConfig, accept loop, caps
│   ├── server/role.go          # username grammar, role classification
│   ├── server/device.go        # control conn: tcpip-forward, control shell
│   ├── server/client.go        # client conn: auth pass-through, bridge setup
│   ├── server/bridge.go        # session mirroring + pumps
│   ├── server/policy.go        # sftp/scp/x11/tcp gates, refusal texts
│   ├── server/status.go        # ssh+json JSON control shell + json status endpoint
│   ├── registry/registry.go    # bindings (§8)
│   ├── guard/iplimit.go        # per-IP concurrent session gate
│   ├── guard/fail2ban.go       # ban manager
│   ├── throttle/throttle.go    # token-bucket Reader/Writer
│   ├── devconn/conn.go         # net.Conn adapter over ssh.Channel + device dial
│   ├── logging/logging.go      # slog setup
│   └── policy/policy.go        # policy.json: strict load, layer merge, CIDR match, hot reload
├── test/
│   ├── unit/                   # table-driven unit tests per package (co-located too)
│   └── e2e/                    # docker compose + expect-style scenarios (E1–E13)
├── Makefile                    # build / test / lint / e2e / release
├── .golangci.yml
└── PLAN.md, ARCHITECTURE.md
```

Dependencies: `golang.org/x/crypto`, `golang.org/x/time`. Build:
`CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=…" -o relay ./cmd/relay`.

---

## 10. Security model / threat notes

- **Credentials:** relay sees device passwords in memory during pass-through
  (unavoidable given §2). Never logged; never written; GC-cheap (used once).
  If that is unacceptable, M6's provisioned-relay-key mode removes password
  visibility (relay authenticates with its own key provisioned into the
  device's `authorized_keys`).
- **Client TCP forwarding (`-L`/`-D`):** available only after device-side auth
  has succeeded (pass-through), and egress happens on the device, under the
  device operator's existing sshd policy. The relay never opens outbound
  sockets itself; caps in §7.4 bound the fan-out.
- **Policy file:** `policy.json` is operator-controlled; parsed strictly
  (unknown fields = load error), validated fail-closed at startup, and swapped
  atomically on reload. Keep it root-owned 0600 in the service directory; the
  relay never writes it. Treat `custom_policies` as routing-of-trust input:
  whoever can write the file can un-gate any IP.
- **JSON endpoints (`ssh+json` / `json`):** expose only the requesting IP's own
  bindings and its session quota — information its owner already has; no
  credentials involved, and using a binding still requires the device's
  credentials. `json` honors no channels or forwards; `ssh+json` is a normal
  device connection in every other respect.
- **Device host key:** Phase-2 handshake uses an accept-any callback in v1 with
  the fingerprint logged (TOFU cache in M6). The end user cannot verify the
  device's host key through the relay — inherent to alias-as-username designs;
  the trust anchor is the relay operator.
- **Open relay surface:** anyone can register a tunnel or knock on aliases.
  Countermeasures: 50-bit random IDs (~10¹⁵ space, no enumeration), alias
  charset restricted, fail2ban, per-IP cap, per-alias bridge cap, total-conn
  cap, auth grace timeout. An operator wanting a private relay runs
  `--fail2ban=true` behind a firewall allow-list today; registration
  allow-list lands in M6.
- **User-agent isolation:** relay does not exec anything locally; no shell is
  ever run; control shell output is static text + values.
- **Resource exhaustion:** every loop has a cap (§7.4); every goroutine has an
  exit path; slog is rate-limited for repeated failures.

---

## 11. Performance expectations

- Throughput: x/crypto/ssh sustains several hundred Mb/s per spliced pair on
  commodity vCPU; the token bucket adds ~1 µs/chunk. Sizing: a 2-vCPU box
  comfortably handles a few hundred concurrent interactive sessions; the
  binding cap (per alias 10, per IP 3, total 1024) bounds worst case.
- Memory: ~O(open channels) — a few KB per idle session.

---

## 12. Testing architecture

```
┌────────────┐   fake device (in-process x/crypto/ssh server)   ┌────────────┐
│ unit tests │──────────────────────────────────────────────────│ relay pkgs │
└────────────┘                                                  └────────────┘
┌───────────────────────────── e2e (docker compose) ────────────────────────┐
│  client container ──ssh──▶ relay ─◀─ssh -R── device container (OpenSSH)   │
│  scenarios E1–E13 from PLAN §6 asserted via exit codes + captured output  │
└───────────────────────────────────────────────────────────────────────────┘
```

Protocol-level fakes (fake device sshd with scripted auth/results) live in
`internal/devconn` tests so M2 behavior is pinned before the e2e harness exists.

---

## 13. Deployment sketch

```ini
# /etc/systemd/system/relay.service
[Unit]
Description=SSH forwarding relay
After=network-online.target
Wants=network-online.target

[Service]
# Only pin what you must: unset flags defer to policy.json (§6.3 precedence).
# Set the bind address via "listen_ip" in policy.json instead of --ip here.
ExecStart=/usr/local/bin/relay --listen-port 22 --fail2ban=true
DynamicUser=yes
StateDirectory=relay          # host key at /var/lib/relay
WorkingDirectory=/var/lib/relay   # policy.json (if present) auto-loads from here
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=always
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
```

Pterodactyl / Wings: the binary handles both panel stop styles natively —
the default signal stop (`SIGTERM`: graceful drain of every live connection,
bounded at 5 s, exit 0, well before the wings SIGKILL) and eggs configured
with a stop *command* (a literal `stop` line on stdin triggers the same
shutdown). No wrapper script or exit-command hacks needed.

DNS: a single `A/AAAA` record for `relay.example.com`. No wildcard DNS is
needed (routing is by SSH username, not hostname).

Device side (keep the tunnel alive across reboots — device's responsibility):

```ini
# device: systemd unit running
ExecStart=/usr/bin/ssh -N -R myvps:0:127.0.0.1:22 -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes ssh@relay.example.com
Restart=always
```
