# Lab SSH server (sshocean / operator-owned)

Use a server you control for authorized drills. The bundled **sshocean** lab account is for team training only — credentials are in downloadable configs (public repo).

## sshocean lab account

| Field | Value |
|-------|-------|
| Hostname | `fr1.sshweb.site` |
| Username | `sshocean-bbsharp` |
| SSH ports | `22`, `80` |
| SSL/TLS ports | `143`, `443` |
| Proxy ports | `8080`, `3128`, `8888` (used by port-fallback hold stack) |
| UDPGW | `7200`, `7300` — **drill-only**; NetPath Lab is TCP/SSH focused |
| Account created | 6 Aug 2026 |
| Account expires | **13 Aug 2026** |

**Security:** configs contain the live password. Rotate after drills. Authorized testing only.

## Port mapping for methods

| Port | Typical use in NetPath Lab |
|------|----------------------------|
| `443` | SNI mismatch, TLS fronts, WS/h2/Trojan/JA3 drills (methods 1–5, 7–11, 13–17, 18–24, 26) |
| `80` | HTTP CONNECT inject (method 6); port-fallback retry |
| `22` | Raw SSH direct (no TLS front) |
| `143` | SSL/TLS alt port (same ClientHello-only drills as 443) |
| `8080` | Port-fallback hold stack retry (method 9, 11) |
| `53` | Doc-only DNSTT drill (method 25 — separate client) |
| `7200`/`7300` | UDPGW — document in SOC tickets; not wired in app |

## Import flow (no manual entry)

1. Download a `.nplab.json` from [Import configs](https://bbscalton.github.io/netpath-lab/methods.html#import-configs) (or the zip of all configs).
2. Open **NetPath Lab** → **Import config** → select the file.
3. Tap **Connect**.

Each config pre-fills host, user, password, port, front mode, and method-specific toggles.

## Minimal OpenSSH on port 443 (your own VPS)

```bash
# Ubuntu example
sudo apt update && sudo apt install -y openssh-server
sudo mkdir -p /etc/ssh/sshd_config.d
echo 'Port 443
PasswordAuthentication yes
PubkeyAuthentication yes
AllowTcpForwarding yes
PermitTunnel no
' | sudo tee /etc/ssh/sshd_config.d/netpath-lab.conf
sudo systemctl restart ssh
```

Create a dedicated lab user with a strong password or key-only auth.

```bash
sudo adduser netpath
sudo ufw allow 443/tcp
```

## App settings (manual or imported)

- **SSH server host:** `fr1.sshweb.site` (or your VPS public IP)
- **Port:** per method — see downloadable configs or `docs/downloads/configs/manifest.json`
- **Username / password:** from imported config or lab operator
- For **SNI mismatch**: Custom SNI = pack-like hostname (e.g. `www.example.com`); dial host stays `fr1.sshweb.site`

## Optional later: stunnel

For scenario `TLS_FULL_SNI`, terminate TLS on the server (stunnel/sslh) and forward to sshd. ClientHello-only mode does **not** need stunnel.

For scenarios `WS_TLS_FRONT`, `HTTP2_PREAMBLE_SNI`, `TROJAN_HTTP_CAMOUFLAGE`: sshd must tolerate injected bytes before SSH, or run a lab proxy that strips the front and forwards to sshd on localhost:22.

For doc-only drills (Reality, VMess, Shadowsocks, Hysteria, obfs4/DNSTT): deploy matching server software on the operator VPS; use sing-box or Xray — never public free nodes.

## Safety

- Restrict SSH to your SOC source IPs when possible.
- Rotate lab credentials after exercises (especially after publishing configs).
- Monitor auth logs during drills (`/var/log/auth.log`).
