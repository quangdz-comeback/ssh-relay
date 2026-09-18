# relay — SSH forwarding relay

One static Go binary: machines behind NAT publish their local sshd through a
public relay; end users connect with plain `ssh`.

```
device:   ssh -R 0:127.0.0.1:22 ssh@relay.example.com        # → prints ssh d-xxx@relay…
          ssh -R myvps:0:127.0.0.1:22 ssh@relay.example.com  # custom alias

user:     ssh d-xxx@relay.example.com            # root on the device
          ssh deploy+d-xxx@relay.example.com     # custom device user
          ssh -D 1080 myvps@relay.example.com    # SOCKS through the device
          ssh json@relay.example.com             # machine-readable status (JSON)
```

Design docs: [PLAN.md](PLAN.md) (requirements, milestones, testing) and
[ARCHITECTURE.md](ARCHITECTURE.md) (two-phase SSH design, policy model,
limits, security model).

## Build

```
make build        # static binary: ./relay
make test race    # unit + in-process integration tests (also with -race)
make e2e          # real-OpenSSH end-to-end smoke test (needs local sshd)
```

## Run

```
./relay --listen-port 22 \
  --bw-limit unlimited --allowed-sessions-per-ip 3 \
  --fail2ban=true --allow-tcp-forwarding=true \
  --allow-sftp=true --allow-scp=true --allow-x11-forwarding=false
```

Optional `policy.json` (auto-loaded from the working directory or
`--policy-file`, hot-reloaded): a `default` block plus per-IP
`custom_policies` overrides (CIDR, first match wins), e.g. bandwidth limits,
gates, or `blocked: true` for abusive ranges. Explicitly passed flags win over
the file's `default` block. See ARCHITECTURE §6.3 for the full schema.

Printed SSH commands use the display host resolved as `--hostname` flag →
policy.json `"hostname"` → auto-detected public IP (one HTTPS query to
ifconfig.me at startup; set `--hostname` on air-gapped hosts) → os hostname,
and carry `-p <port>` whenever `--listen-port` is not 22. The control shell
exits on `Ctrl+C`/`Ctrl+D`, which tears the tunnel down.

## Status

- M0–M5 implemented and covered by unit, protocol, in-process integration
  tests and a real-OpenSSH e2e (`test/e2e/run.sh`).
- M6 (stretch): agent-forwarding pubkey pass-through, X11 hardening, admin
  listing, alias reclaim tokens, metrics.
