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
5. Click **Run all tests** to probe all 25 import configs.

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
| `FRONT_SENT` | Connected and sent front bytes; SSH did not respond (common for WS/Trojan/h2 fronts if server lacks strip-proxy) |
| `CONNECT_FAIL` / `CONNECT_TIMEOUT` | Port blocked or host unreachable from your network |
| `SKIP` | UDP/QUIC doc drills (Hysteria, DNSTT) — not tested on Windows TCP probe |

After a full run, open:

- `tools/netpath-probe/reports/latest.json` — machine-readable summary
- `tools/netpath-probe/reports/latest.html` — table for SOC tickets

**Recommended** list = fastest `AUTH_OK` methods (try these first on pack APN).

## Config source

Loads `docs/downloads/configs/*.nplab.json` (25 files) relative to the repo root.

## Lab server defaults

| Field | Value |
|-------|-------|
| Host | `fr1.sshweb.site` |
| User | `sshocean-bbsharp` |
| SSH ports | 22, 80 |
| TLS ports | 143, 443 |
| Proxy fallback | 8080, 3128, 8888 |

See [docs/LAB_SERVER.md](../../docs/LAB_SERVER.md) for port mapping.

## Out of scope

- Full VPN/tunnel on Windows
- UDPGW / Hysteria / QUIC live tests (marked `SKIP`)
