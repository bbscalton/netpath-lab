# NetPath Lab

Authorized **ISP / SOC red-team** Android client that reproduces how consumer tunnel apps front **SSH** with:

- Direct TCP
- HTTP inject
- TLS ClientHello-only Custom SNI (classic mismatch)
- Full TLS + Custom SNI
- Preserve SNI / Realm Host (v2) / TCP Payload toggles
- VpnService device traffic via local SOCKS over SSH

**No public free/premium servers are bundled.** Point the app at **your** lab VPS only.

## Rules of engagement

Use only on networks you **own** or have **written authorization** to test. This project exists to educate defender teams and validate pack/zero-rate controls — not to steal service.

## Quick start

1. **Download the lab APK:** https://bbscalton.github.io/netpath-lab/
2. Or open this project in Android Studio (`hatunnelplus`) and run the `app` module.
3. Deploy OpenSSH on your VPS — see [docs/LAB_SERVER.md](docs/LAB_SERVER.md).
4. Enter your VPS host/port/credentials in the app.
5. Apply training scenario **SNI mismatch** or **Custom Setup hold stack** and Connect on pack vs paid APNs.
6. Read [docs/SOC_PLAYBOOK.md](docs/SOC_PLAYBOOK.md) and the in-app **Learn / SOC** screen.

## Package

- Application ID: `com.netpath.lab`
- Min SDK 26 / Target 35

## Team drill (short)

| Step | Action | Expected on hardened pack |
|---|---|---|
| 1 | Direct SSH on paid data | Connect OK |
| 2 | SNI_MISMATCH to VPS on pack | Fail or full-rate |
| 3 | If step 2 is free/success | Finding: allowlist gap |

## Disclaimer

You are responsible for lawful use. Authors intend this as a defensive training aid.
