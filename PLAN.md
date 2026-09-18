# PLAN.md — SSH Forwarding Relay (`relay`)

> One static Go binary that lets a machine behind NAT publish its local SSH server
> through a public relay host, so end users connect with plain `ssh` — no VPN,
> no client config, no extra ports.

---

## 1. Goal

Build `relay`, a standalone SSH forwarding relay:

- A **device** (any server behind NAT/firewall) opens a reverse SSH tunnel to the
  relay and registers a **binding** (auto-generated `deviceID` or a custom name)
  that points to its local `sshd` (default target `127.0.0.1:22`).
- An **end user** connects to the relay with plain SSH using the binding as the
  SSH username. The relay bridges the session, end-to-end, to the device's sshd.
- The relay is a controlled data plane only: it never stores device credentials,
  never holds user accounts, and never opens a real TCP port. TCP forwards aimed
  at the relay itself are refused with a warning; client `-L`/`-D` forwards are
  bridged through to the device.

### Product UX contract (must hold exactly)

| Actor | Command | Result |
|---|---|---|
| Device (register, auto ID) | `ssh -R 0:127.0.0.1:22 ssh@relay.example.com` | Relay prints the connect command: `ssh d-XXXXXXXXXX@relay.example.com` |
| Device (register, custom name) | `ssh -R custom-name:0:127.0.0.1:22 ssh@relay.example.com` | Binding `custom-name` → `127.0.0.1:22` |
| User (default user is `root`) | `ssh d-XXXXXXXXXX@relay.example.com` | SSH session to the device as `root` |
| User (public key) | `ssh -A -i ~/.ssh/key deploy+d-XXXXXXXXXX@relay.example.com` | The relay forwards the user's ssh-agent; the device verifies the real key (agent forwarding required — signatures are session-bound) |
| User (custom device user) | `ssh <user>+d-XXXXXXXXXX@relay.example.com` | SSH session to the device as `<user>` |
| User (custom binding name) | `ssh <user>+custom-name@relay.example.com` | SSH session via the named binding |
| User (SOCKS / dynamic forward) | `ssh -D 1080 user+alias@relay.example.com` | Allowed — destinations are dialed by the device, not the relay |
| User (local forward) | `ssh -L 8080:intranet:80 user+alias@relay.example.com` | Allowed — `direct-tcpip` opens are mirrored to the device |
| Device (real TCP forward toward the relay) | `ssh -L/-D/-R <port>:… ssh@relay.example.com` | Refused with exactly: `[WARNING] TCP forwarding is not supported.` |
| Device automation | `ssh -R 0:127.0.0.1:22 ssh+json@relay.example.com` | Same tunnel registration as `ssh@…`, but the control shell emits one JSON document (deviceID, connect commands, sessions used/allowed) instead of the interactive banner |
| Status only | `ssh json@relay.example.com` | Prints the same JSON document for the current IP and exits 0 — no forwarding, no dashboard |

---

## 2. Requirements

### 2.1 Functional

| ID | Requirement |
|---|---|
| FR-1 | Single CLI: `./relay --listen-port <port> --bw-limit <10K/10M/10G/unlimited/...> --allowed-sessions-per-ip <N> --fail2ban <true/false> --allow-sftp <true/false> --allow-scp <true/false> --allow-x11-forwarding <true/false>` |
| FR-2 | `--allowed-sessions-per-ip` default **3**; the Nth+1 concurrent authenticated connection from one source IP is refused with a clear message. |
| FR-3 | `--bw-limit` accepts `unlimited`, plain bytes (`500`), `K`/`M`/`G` suffixes (`10K`, `10M`, `10G`); interpreted as **bytes per second, per connection, per direction**. Invalid values are rejected at startup. |
| FR-4 | `--fail2ban` enables the built-in ban manager (auth-failure counting + temporary IP bans, in-memory; no external fail2ban dependency). |
| FR-5 | `--allow-sftp` gates the `sftp` subsystem. When disabled, the subsystem request is denied with a clear message. |
| FR-6 | `--allow-scp` gates legacy `scp` (`exec "scp …"`). When disabled, such exec requests are denied. |
| FR-7 | `--allow-x11-forwarding` gates `x11-req` and the corresponding `x11` channels. |
| FR-8 | Device registration over `ssh -R … ssh@relay…`: empty/`localhost`/`0.0.0.0` bind address → generate a high-entropy `deviceID` (`d-` + 10 Crockford-base32 chars); named bind address → use it as the alias. |
| FR-9 | A control shell on the device connection prints the binding(s), the exact connect commands, and stays alive while the tunnel is up. |
| FR-10 | Client sessions are bridged to the device's sshd: PTY, shell, `exec`, environment (allow-listed), window resize, signals, exit status, stderr — all mirrored. |
| FR-11 | Default device user is `root`; `user+alias` selects a different device user. |
| FR-12 | Client connections may forward TCP through the bridge: `direct-tcpip` channel opens (`-L`, `-D`) are mirrored to the device, which performs the dial — gated by `--allow-tcp-forwarding` (default true). |
| FR-13 | Forwarding a real TCP port to the relay is unsupported: `-R <port>:…` on any connection, and `-L`/`-D` on the device role, are refused with `[WARNING] TCP forwarding is not supported.` Only the registration form `-R [alias:]0:target` is accepted. |
| FR-14 | Bindings disappear when the device disconnects; a custom alias may be re-bound on reconnect (last writer wins in v1). |
| FR-15 | Relay host key is generated once and persisted, so clients see a stable fingerprint. |
| FR-16 | `--allow-tcp-forwarding=false` refuses client `direct-tcpip` opens with the same warning text; the gate resolves through the effective policy (FR-17). |
| FR-17 | `policy.json` auto-loads when present (hot-reloaded): the `default` block overrides flag values globally; the ordered `custom_policies` list applies per-source-IP (CIDR, first match wins) per-field overrides — or full blocks — without affecting global policy. Invalid file = fail-closed startup; failed reload = keep last good policy. |
| FR-18 | `ssh+json` (device role) and `json` (status) emit the same machine-readable JSON document — requesting IP, sessions used/allowed for that IP, per-binding connect commands and bridge usage. `ssh+json` still registers forwards normally and prints the document after binding; `json` only prints and exits 0 (no forwarding accepted). Both work without a TTY; the alias `json` cannot be registered. |

### 2.2 Non-functional

- Single static binary (`CGO_ENABLED=0`), no runtime config files required.
- Only two dependencies beyond the stdlib: `golang.org/x/crypto` (SSH) and
  `golang.org/x/time` (token bucket). Nothing else without discussion.
- All state in memory (v1). A restart drops bindings; devices reconnect.
- Structured logging (`log/slog`), no credentials ever logged.
- Degrade gracefully under load: caps and timeouts everywhere (see ARCHITECTURE §7).

### 2.3 Non-goals (v1)

- No HTTP dashboard / API / metrics endpoint (later stretch).
- No multi-node clustering; one relay process owns all bindings.
- No relay-side user accounts or ACLs beyond the listed flags.
- No raw TCP exposure of bindings — the relay never opens listening sockets
  (see FR-13).
- No persistence of tunnels across relay restarts.

---

## 3. CLI contract

```
relay [flags]

Required/primary flags
  --listen-port int                 TCP port for the SSH listener (default 2222;
                                    use 22 with CAP_NET_BIND_SERVICE or systemd socket)
  --ip string                       listen IP (default: all interfaces); must be a valid IP if set;
                                    the same value can come from policy.json `listen_ip` (flag wins when set)
  --bw-limit string                 per-connection, per-direction throughput cap:
                                    "unlimited" (default), "500", "10K", "10M", "10G" (K/M/G = 1024-based)
  --allowed-sessions-per-ip int     max concurrent authenticated connections per source IP (default 3)
  --fail2ban bool                   enable built-in ban manager (default true; see §7 assumptions)
  --allow-tcp-forwarding bool       allow client TCP forwarding via -L/-D (default true)
  --allow-sftp bool                 allow the sftp subsystem (default true)
  --allow-scp bool                  allow legacy scp exec requests (default true)
  --allow-x11-forwarding bool       allow X11 forwarding (default false)

Ops flags (secondary, documented but not part of the core contract)
  --data-dir string                 host key storage (default /var/lib/relay or ~/.local/share/relay)
  --policy-file string              policy.json path (default "policy.json" in the working
                                    directory; auto-loaded when present, hot-reloaded on change)
  --hostname string                display host in printed SSH commands (default:
                                   auto-detect public IP via ifconfig.me; policy.json
                                   "hostname" entry also works; falls back to os hostname
                                   if the lookup fails)
  --log-level string                debug|info|warn|error (default info)
  --version                         print version and exit
```

Validation errors (startup fails, non-zero exit):

- `--listen-port` outside 1–65535.
- `--bw-limit` not matching `^unlimited$|^[0-9]+([KMG])?$` (case-insensitive) or ≤ 0 bytes.
- `--allowed-sessions-per-ip` < 1.
- `--ip` (or policy.json `listen_ip`) is not a valid IP address (empty/absent = all interfaces).
- `policy.json` (when present) fails strict validation.

### Policy file (`policy.json`)

When a `policy.json` is present (`--policy-file` or `policy.json` in the working
directory), it is loaded automatically and hot-reloaded. The file accepts a
top-level `listen_ip` (bind address, equivalent to `--ip`, startup-only) plus a
`default` policy block. The ordered `custom_policies` list layers per-source-IP
overrides (CIDR match, first match wins) on top — tightening or loosening
individual knobs (`allow_*`, `bw_limit`, `max_sessions_per_ip`) or blocking IPs
outright (`blocked: true`) — without touching global behavior.

Precedence: built-in defaults → `default` block → **explicitly passed flags**
(a flag set on the command line wins the conflict; unset flags defer to the
file, so file-driven mass deploys still work) → first matching per-IP policy.
`listen_ip` is applied at startup only and never hot-reloaded. Full format and
reload semantics: ARCHITECTURE §6.3.

---

## 4. User flows

### 4.1 Device registers with an auto-generated ID

```
$ ssh -R 0:127.0.0.1:22 ssh@relay.example.com

  ── relay ──────────────────────────────────────────────
  Tunnel online: d-7k2m9xq4tz

  Connect:            ssh d-7k2m9xq4tz@relay.example.com
  Custom device user: ssh <user>+d-7k2m9xq4tz@relay.example.com

  Keep this session open to keep the tunnel alive.
  ───────────────────────────────────────────────────────
```

The control shell blocks (like `sleep infinity`); `Ctrl+C` (or `Ctrl+D`) or
network loss tears the binding down immediately. When the client allocated a
PTY the output uses CRLF line endings (openssh puts the terminal in raw mode;
bare `\n` would staircase), and `ssh+json` clients that pipe into `jq` get
clean LF.

The printed connect commands reflect the listener: when `--listen-port` is not
22 they carry `-p <port>` (e.g. `ssh -p 2222 d-…@host`), and the host part is
resolved as `--hostname` flag → policy.json `"hostname"` → public IP (queried
once at startup from ifconfig.me, with api.ipify.org as fallback) → os
hostname if the lookup fails.

> Note: the device-side target (`127.0.0.1:22` in the `-R` command) never
> crosses the wire — the device's own ssh client dials it when the relay opens
> a `forwarded-tcpip` channel. The relay therefore shows only the alias; the
> target is client-local knowledge.

### 4.2 Device registers a custom alias

```
$ ssh -R myvps:0:127.0.0.1:22 ssh@relay.example.com

  ── relay ──────────────────────────────────────────────
  Tunnel online: myvps

  Connect:            ssh myvps@relay.example.com
  Custom device user: ssh <user>+myvps@relay.example.com

  Keep this session open to keep the tunnel alive.
  ───────────────────────────────────────────────────────
```

Alias conflicts (name already bound) are reported in the control shell and the
`tcpip-forward` request is refused; the connection stays up so the operator can
retry with another name.

### 4.3 End user connects

```
$ ssh d-7k2m9xq4tz@relay.example.com
(d-7k2m9xq4tz) root@device's password:      # relay passes the prompt through to the device
root@device:~#
```

```
$ ssh deploy+d-7k2m9xq4tz@relay.example.com 'uptime'
 14:02:11 up 9 days, 1:22, 1 user, load average: 0.08, 0.03, 0.01
```

### 4.4 Client-side TCP forwarding (allowed)

```
$ ssh -D 1080 d-7k2m9xq4tz@relay.example.com
# SOCKS proxy on :1080 — each destination is dialed by the device, not the relay
```

```
$ ssh -L 5432:db.internal:5432 deploy+d-7k2m9xq4tz@relay.example.com
# local forward; the relay mirrors each direct-tcpip open to the device
```

### 4.5 Refusals (TCP forwarding toward the relay)

```
$ ssh -D 1080 ssh@relay.example.com        # -L/-D on the device role
…
channel 2: open failed: administratively prohibited: [WARNING] TCP forwarding is not supported.

$ ssh -R 8080:localhost:80 d-7k2m9xq4tz@relay.example.com   # real port toward the relay
Warning: remote port forwarding failed for listen port 8080
```

The refusal reason string sent on the wire is exactly
`[WARNING] TCP forwarding is not supported.` (OpenSSH displays the reason for
channel-open failures; for global `tcpip-forward` failures it prints only its
generic "forwarding failed" line, but the reason still travels on the wire.)

With `--allow-tcp-forwarding=false` — or a per-IP `custom_policies` override
that disables it — client `-L`/`-D` attempts receive the same refusal.

### 4.6 Machine-readable JSON (`ssh+json` / `json`)

```
$ ssh -R 0:127.0.0.1:22 ssh+json@relay.example.com    # đăng ký tunnel, output JSON
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

```
$ ssh json@relay.example.com                          # chỉ lấy status, không forward
```

- `ssh+json` vẫn là device login **hỗ trợ forward đầy đủ**: đăng ký `-R` như
  bình thường, chỉ khác control shell in JSON document (in **sau khi** các
  binding đã tạo nên deviceID có sẵn trong output) rồi giữ tunnel như control
  shell thường. Script trên device đọc document đầu tiên từ stdout để lấy
  deviceID + connect command một cách programmatic, giữ process chạy (systemd).
- `json@` là **status thuần**: in cùng document đó rồi đóng connection
  (exit code 0), không nhận forward nào (`tcpip-forward` bị từ chối với warning
  text chuẩn). Cả hai chạy được không cần TTY (`ssh -T`) — pipe thẳng vào `jq`.
- `sessions.used` đếm các connection đang sống từ IP hiện tại **không tính
  chính connection đang hỏi**; `allowed` = per-IP limit hiệu lực
  (flags / `policy.json`).
- `bindings` liệt kê mọi binding thuộc sở hữu của IP hiện tại (gồm cả deviceID
  lẫn custom alias). Danh sách rỗng khi IP chưa có tunnel nào.

---

## 5. Milestones

Each milestone ends with its acceptance check green. M0–M5 = v0.1 (feature
complete), M6 = stretch.

### M0 — Skeleton & config
- Repo layout per ARCHITECTURE §10, `Makefile` (`build`, `test`, `lint`, `release`),
  flag parsing + validation with table-driven unit tests, static build.
- **Done when:** `make build && ./relay --help` prints every flag above;
  invalid `--bw-limit 10X` exits non-zero; `go vet` + `golangci-lint` clean.

### M1 — Device plane (tunnels in)
- SSH listener, role routing by username (`ssh` = device role), accept-any auth
  for that role, `tcpip-forward` handling (generate/claim aliases), registry,
  control shell, keepalives, disconnect cleanup.
- **Done when:** against a running relay, `ssh -p 2222 -R 0:127.0.0.1:22 ssh@localhost`
  prints a `d-…` ID and connect command; a second registration with the same
  custom alias is refused; killing the ssh process unbinds (verified via log).

### M2 — Client plane (bridging)
- Username grammar (`user+alias`), alias lookup, tunnel dial (`forwarded-tcpip`
  toward the device), relay-side SSH client handshake to the device sshd,
  pass-through auth (none → password), session mirroring (pty/shell/exec/env/
  window-change/signal/exit-status/stderr), `direct-tcpip` mirroring for client
  `-L`/`-D`, bandwidth limiter inline.
- **Done when:** e2e script logs into a Dockerized sshd via the relay with a
  password; `ssh relay-alias 'echo $?'` returns the device command's exit code;
  window resize propagates (`stty size` matches locally); `ssh -D` through the
  bridge reaches a host only the device can reach.

### M3 — Policy gates & refusals
- `--allow-sftp` / `--allow-scp` / `--allow-tcp-forwarding` /
  `--allow-x11-forwarding` enforced on mirrored requests; refusal rules with the
  exact warning text: `-L`/`-D` (and any `direct-tcpip`) on the device role,
  `tcpip-forward` with a real port on any connection, and client `direct-tcpip`
  when `--allow-tcp-forwarding=false`. Only `-R [alias:]0:target` is accepted on
  the device role.
- **Done when:** e2e asserts each gate both ways (on/off) and the warning string
  byte-for-byte.

### M4 — Limits & protection
- Per-IP concurrent session gate (default 3), built-in fail2ban (5 failures /
  10 min → ban 1 h, doubling to 24 h max), handshake timeout (30 s), idle
  keepalive policy, per-alias and global caps.
- JSON endpoints: `ssh+json` (device role, forward-capable, JSON control shell
  printed after binding) and `json` (status-only, closes after the document);
  shared document schema; no-TTY safe; `json` reserved as alias.
- **Done when:** scripted 4th connection from one IP is dropped with the limit
  message; unit tests prove ban arithmetic; bw-limit `10K` measured ≈ 10 KiB/s
  through a spliced session; `ssh json@…` output parses and its `sessions`
  numbers match limiter state, and `ssh+json -R` output contains the new
  binding (e2e E13).

### M5 — Ops hardening & release
- Host key persistence + fingerprint logging, `--data-dir`, systemd unit docs,
  DNS notes, e2e suite (Docker Compose: relay + device sshd + client) in CI,
  release binaries via GoReleaser (linux amd64/arm64, static).
- policy.json: auto-load + strict validation + hot reload (mtime poll / SIGHUP),
  `default` layer and per-IP `custom_policies` (CIDR, first match wins),
  effective-policy snapshot per connection.
- **Done when:** CI green on push; restart keeps host key fingerprint;
  release artifacts build with `CGO_ENABLED=0`; e2e proves a CIDR-scoped
  override changes behavior for that IP only; invalid policy file aborts
  startup; a failed reload keeps the last good policy.

### M6 — Stretch
- ~~Public-key pass-through via OpenSSH agent forwarding (`ssh -A`).~~
  **Shipped.** The relay verifies the client's key signature itself, defers
  the device login to the first session/forwarding open, and completes it
  through the forwarded agent (ARCHITECTURE §5.2.1). Covered by in-process
  integration tests and the real-OpenSSH e2e.
- X11 hardening beyond verbatim pairing (per-display policies, cookie audit).
- `ssh keys@relay…` admin listing of live bindings.
- Alias reclaim tokens (prove ownership to steal back a name), optional
  registration allow-list for the device role.
- Persistence of aliases across restart; Prometheus `/metrics`.

---

## 6. Testing & QA strategy

| Layer | What | How |
|---|---|---|
| Unit | bw parser, username grammar, registry concurrency, fail2ban arithmetic, IP limiter, policy gates, policy layer-merge + CIDR matching + hot-reload swap, JSON status document schema | `go test -race`, table-driven |
| Protocol | request mirroring, refusal texts, exit-status mapping | in-process fake device (x/crypto/ssh both ends) |
| E2E | real OpenSSH everywhere | `test/e2e` docker compose: `relay`, `device` (sshd, password auth), `client`; scenarios E1–E13: auto-ID, custom alias, `user+alias`, exec+exit code, client `-L`/`-D` through the bridge, refusal warning (device-role `-L`/`-D`, real-port `-R`), sftp gate, scp gate, x11 gate, IP limit, fail2ban ban, policy override (`--allow-tcp-forwarding=false`, `custom_policies` CIDR-scoped change + hot reload), JSON endpoints (`json@` status quota matches limiter; `ssh+json -R` output contains the new binding); E14–E15: pubkey via `ssh -A` + real ssh-agent (bridge exec) and agentless pubkey rejected with the `-A` hint |
| Perf | bw limiter overhead, 100 concurrent bridges | scripted throughput/run-time checks, not CI-gated |
| Static | vet, lint, `gofumpt`, staticcheck | golangci-lint in CI |

CI: GitHub Actions — lint + unit on every push; e2e job with Compose; release
job on tag.

---

## 7. Assumptions (confirm before/during M1)

1. **Auth model = pass-through.** The relay terminates the client's SSH and
   performs its own SSH handshake to the device through the tunnel, forwarding
   the user's credentials (none → password). Public-key signatures bind the
   session ID, so the client's signature cannot be replayed to the device;
   pubkey users go through agent forwarding instead (shipped — the user's own
   agent signs the device's challenge, ARCHITECTURE §5.2.1). This is the
   single biggest design commitment; if you wanted "relay must never see
   passwords", the alternative is a provisioned relay key
   (`authorized_keys` on the device) — flag it now if so.
2. **Flag defaults:** `fail2ban=true`, `allow-sftp=true`, `allow-scp=true`,
   `allow-x11-forwarding=false`, `listen-port=2222`. Trivial to flip.
3. **`--bw-limit` is per connection, per direction** (a global cap would let one
   session starve everyone). 
4. **Open relay by default** for device registration (serveo-style). Mitigated
   by fail2ban + per-IP caps + session caps; allow-list is M6.
5. **scp semantics:** modern OpenSSH `scp` speaks the SFTP subsystem, so
   `--allow-scp=false` alone cannot block it — only legacy scp (`exec "scp …"`)
   is gated by that flag. Blocking file transfer entirely = `--allow-sftp=false`.
   Documented in README; not a bug.
6. **Backend target should be an SSH server.** The bridge is generic byte
   plumbing, but the UX (password prompts, PTY) only makes sense against sshd.
7. **Client `-L`/`-D` egress dials from the device.** The relay itself never
   opens outbound TCP; the device's sshd does, so the device needs
   `AllowTcpForwarding yes` for that path.
8. **Explicit flags win over the file's `default` block; per-IP policies stay
   the top layer.** Layers: builtin → `policy.json` `default` → explicitly set
   flags → first matching `custom_policies` (CIDR, first match wins, per
   field). Unset flags defer to the file (file-driven mass deploys keep
   working); `listen_ip` applies at startup only.
9. **`ssh+json` / `json` return an object envelope, not a bare array** —
   `bindings` is the array, and the envelope carries `ip` + `sessions` so an IP
   with zero tunnels still gets its quota. `sessions.used` excludes the
   querying connection itself. `ssh+json` is a full device login (forwards
   work, tunnel held open); `json` is status-only and closes immediately.
10. **Display host auto-detection makes one outbound HTTPS request at startup**
   (ifconfig.me, api.ipify.org as fallback) when neither `--hostname` nor the
   policy.json `"hostname"` entry is set — air-gapped deployments should set one
   of them explicitly; otherwise the relay falls back to the os hostname.

---

## 8. Risks & mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Relay abused as free tunnel host by third parties | resource abuse, legal exposure | fail2ban, per-IP session cap (default 3), per-alias bridge cap, handshake timeouts; M6 allow-list |
| `deviceID` scanning | strangers knock on devices | 50-bit random IDs, constant-time lookup, no enumeration; device password still required |
| Client disconnects mid-session leak device-side sessions | fd/memory growth on relay & device | bridge janitor closes both channels on any exit path; WaitGroup per bridge |
| Device drops while users connected | confusing client hang | binding removed instantly; in-flight bridges closed; client sees "connection closed" |
| Host key regenerated on redeploy | scary client warnings | persisted key in `--data-dir` (M5) |
| x/crypto/ssh behavior gaps (e.g. server-side channel open to OpenSSH client) | rework in M2/M6 | M2 spike first: prove `forwarded-tcpip` server→device and session mirroring on a real OpenSSH device before building on |

---

## 9. Definitions

- **Device**: the machine that dials out with `ssh -R …`; hosts the real sshd.
- **Control connection**: the device's SSH connection to the relay; carries
  binding registration and the bridged channels.
- **Binding / alias**: `name → (device conn, target host:port)`; names are either
  generated (`d-XXXXXXXXXX`) or custom (`myvps`).
- **deviceID**: a generated binding name; `d-` + 10 Crockford-base32 chars (~50 bits).
- **Bridge**: one end-user SSH session spliced to the device's sshd through the tunnel.
- **Control shell**: the fake shell the relay runs on the control connection to
  print tunnel info and keep the session alive.
- **JSON endpoints**: `ssh+json` — device login with a JSON control shell
  (still forward-capable); `json` — status-only query returning the same JSON
  document (bindings of the requesting IP + session quota) and closing.
