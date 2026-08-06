# NetPath Lab Probe

Windows desktop tool for SOC teams to **probe every `.nplab.json` bypass method** against the lab sshocean server — without installing the Android app. It mirrors the Android front-door bytes (TLS ClientHello, HTTP inject, WebSocket, HTTP/2 preamble, Trojan camouflage, etc.), then attempts an SSH handshake and password auth over the same TCP socket.

## Security

- **Configs contain live lab credentials** (`sshocean-bbsharp` / password in JSON). Use only on **authorized networks** and machines you control.
- This tool is for **local lab testing** — it does not establish a VPN tunnel.
- **Rotate the lab password** after drills. Do not share reports outside your SOC ticket system without redacting secrets.

## Quick start (Windows)

1. Clone or open the repo.
2. Double-click **`tools/netpath-probe/run.bat`** (or run from a terminal).
3. First launch creates a Python venv and installs `paramiko` + `cryptography`.
4. Click **Test server only** to verify `fr1.sshweb.site` ports 22/80/143/443.
5. Click **Run all tests** to probe all 26 import configs.

No manual `pip install` required if Python 3.10+ is on PATH.

## CLI mode

```bat
cd tools\netpath-probe
run.bat --cli
run.bat --cli --health-only
```

## Interpreting results

| Status | Meaning |
|--------|---------|
| `AUTH_OK` | TCP connect, front bytes sent, SSH banner received, password auth succeeded — **best candidate for pack-SIM testing** |
| `SSH_BANNER` | Reached SSH but auth failed (wrong creds or server policy) |
| `FRONT_SENT` | Connected and sent front bytes; SSH did not respond — server returned TLS/binary garbage instead of an SSH banner |
| `CONNECT_FAIL` / `CONNECT_TIMEOUT` | Port blocked, refused, or host unreachable from your network |
| `SKIP` | UDP/QUIC doc drills (Hysteria, DNSTT) — not tested on Windows TCP probe |

After a full run, open:

- `tools/netpath-probe/reports/latest.json` — machine-readable summary
- `tools/netpath-probe/reports/latest.html` — table for SOC tickets

**Recommended** list = fastest `AUTH_OK` methods (try these first on pack APN).

### Latest lab server interpretation (`fr1.sshweb.site`, Aug 2026)

Use this when reading `latest.html` for the sshocean shared lab host:

| Observation | What it means | NetPath Lab action |
|-------------|---------------|-------------------|
| Port **22** health OK, banner `SSH-2.0-OpenSSH_9.9` | Real OpenSSH baseline — no front bytes | Import **`00-ssh-direct-22`** for control tests on Wi‑Fi/paid data |
| Method **06** on port **80** → `AUTH_OK`, dropbear banner | HTTP inject path works; SSH is behind HTTP front | **Only probe-verified hold path** — use **`06-http-host-inject`** on pack SIM first |
| Methods **01–05**, **07**, **13–17** on **443** → `FRONT_SENT` + UTF-8 decode errors | Port 443 speaks **TLS**, not SSH-after-ClientHello | Expected FAIL on this host — use for demonstrating SNI/TLS fronts that do not reach SSH |
| Method **07** (`DIRECT` on 443) → connection closed | Raw SSH to :443 rejected — not OpenSSH on that port | Do not expect method 7 to AUTH_OK on sshocean |
| Methods **09**, **11**, **26** → `CONNECT_TIMEOUT` / `CONNECT_FAIL` on **8080** | Proxy fallback port not open from probe network | Port-fallback drills need operator to open 8080 or use another VPS |
| Port **143** health **FAIL** (refused) | SSL alt port not listening | Skip 143-based drills until operator fixes |
| **21** (QUIC), **25** (DNSTT) → `SKIP` | UDP drills — out of scope for this TCP probe | Use separate Hysteria/DNSTT clients |

**Practical drill order:** baseline `00` on :22 → verified hold `06` on :80 → then any :443 method to score PASS/FAIL on pack (expect probe FAIL, app may still show charging behavior).

## Config source

Loads `docs/downloads/configs/*.nplab.json` (26 files) relative to the repo root.

## Lab server defaults

| Field | Value |
|-------|-------|
| Host | `fr1.sshweb.site` |
| User | `sshocean-bbsharp` |
| SSH ports | 22, 80 |
| TLS ports | 143, 443 |
| Proxy fallback | 8080, 3128, 8888 |

See [docs/LAB_SERVER.md](../../docs/LAB_SERVER.md) for port mapping and probe findings.

## Out of scope

- Full VPN/tunnel on Windows
- UDPGW / Hysteria / QUIC live tests (marked `SKIP`)
