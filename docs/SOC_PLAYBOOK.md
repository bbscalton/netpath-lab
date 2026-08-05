# SOC Playbook — NetPath Lab

## Goal

Validate that **pack / zero-rate** enforcement is based on **destination identity (IP/prefix)**, not on attacker-controlled strings (SNI, Host header, payloads).

## Attacker path (what the app does)

```text
Apps → VpnService TUN
  → FrontDoor (Direct | HTTP inject | TLS ClientHello SNI | full TLS)
  → SSH2 auth to operator VPS
  → SOCKS direct-tcpip multiplex
  → Internet exit on VPS
```

### Technique notes

| Technique | On the wire | Weak defender mistake |
|---|---|---|
| Custom SNI ClientHello-only | TCP to VPS:443 + TLS ClientHello SNI=pack name, then SSH | Trusting SNI alone for zero-rate |
| Preserve SNI | SNI never rewritten to VPS hostname | Same |
| Realm Host v2 | Alternate realm/dial logging/order | Believing toggle changes policy need |
| TCP Payload | Extra bytes before hello | Signature-only filters |
| HTTP inject | ASCII HTTP before SSH | Allowing CONNECT to arbitrary IPs |
| SSH on 443 | SSH banner on HTTPS port | No probe / no hosting-ASN policy |

## Detection / prevention checklist

1. **Allowlist prefixes** for each pack product (CDN/API ranges), auto-refresh.
2. **Default deny** off-list destinations on pack bearer (rate or drop).
3. **SNI≠IP mismatch**: if SNI ∈ pack domains and IP ∉ ranges → deny/rate.
4. **Parity**: IPv6 and all APNs same rules.
5. **Fingerprint**: SSH/OpenVPN/WG on pack → probe + deny list.
6. **Behavior**: long single flow to hosting ASN + high bytes → score/shunt.
7. **Quotas** on “unlimited social” products.
8. **Do not** MITM all TLS unless legal/product requires it — IP policy is enough for classic SNI bypass.

## Lab correlation

1. Note phone time sync (NTP).
2. Start scenario; watch in-app Session log timestamps.
3. Pull UPF/DPI/flow logs for IMSI/MSISDN around those times.
4. Confirm whether charging rating group was pack or general internet.
5. Record PASS/FAIL in ticket with pcap or flow IDs.

## Residual risk (still possible after hardening)

- Abuse **inside** real allowlisted CDN/app IPs (volume/behavior controls).
- Over-broad allowlists (entire cloud ASN).
- Paid APN VPN (usually by design).
- APN/IPv6 policy holes.

## Escalation

If SNI_MISMATCH succeeds unmetered: treat as **P1** control failure on pack enforcement.
