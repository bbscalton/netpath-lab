#!/usr/bin/env python3
"""Generate NetPath Lab .nplab.json configs for each TrainingScenarios method."""

import json
import os
import zipfile

HOST = "fr1.sshweb.site"
USER = "sshocean-bbsharp"
PASSWORD = "players12xx"
DEFAULT_HTTP = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "docs", "downloads", "configs")


def base(**kwargs):
    p = {
        "name": "Lab profile",
        "serverHost": HOST,
        "serverPort": 443,
        "username": USER,
        "password": PASSWORD,
        "privateKeyPem": "",
        "frontMode": "TLS_SNI_CLIENTHELLO_ONLY",
        "customSni": "www.example.com",
        "httpPayload": DEFAULT_HTTP,
        "tcpPayloadHex": "",
        "useRealmHostV2": False,
        "preserveSni": True,
        "useTcpPayload": False,
        "connectTimeoutMs": 15000,
        "customSetup": True,
        "pathType": "DIRECT_CONNECTION",
        "transportProtocol": "TCP",
        "wwwSniToggle": False,
        "portFallback": False,
        "preferNearbyServer": True,
        "keepVpnAlive": True,
        "useFrontPadding": False,
        "frontPaddingMaxBytes": 64,
    }
    p.update(kwargs)
    return p


SCENARIOS = [
    {
        "num": "00",
        "slug": "ssh-direct-22",
        "id": "SSH_DIRECT_22",
        "title": "0. SSH on 22 Direct (baseline)",
        "port": 22,
        "front": "DIRECT",
        "profile": lambda: base(
            name="00-ssh-direct-22",
            serverPort=22,
            frontMode="DIRECT",
            preserveSni=False,
            portFallback=False,
        ),
    },
    {
        "num": "01",
        "slug": "sni-mismatch",
        "id": "SNI_MISMATCH",
        "title": "1. SNI mismatch / Custom SNI (ClientHello-only)",
        "port": 443,
        "front": "TLS_SNI_CLIENTHELLO_ONLY",
        "profile": lambda: base(
            name="01-sni-mismatch-443",
            serverPort=443,
            frontMode="TLS_SNI_CLIENTHELLO_ONLY",
            customSni="www.example.com",
            preserveSni=True,
            portFallback=False,
        ),
    },
    {
        "num": "02",
        "slug": "preserve-sni",
        "id": "PRESERVE_SNI_ON",
        "title": "2. Preserve SNI",
        "port": 443,
        "front": "TLS_SNI_CLIENTHELLO_ONLY",
        "profile": lambda: base(
            name="02-preserve-sni-443",
            serverPort=443,
            preserveSni=True,
            useRealmHostV2=False,
        ),
    },
    {
        "num": "03",
        "slug": "realm-host-v2",
        "id": "REALM_HOST_V2",
        "title": "3. Realm Host v2",
        "port": 443,
        "front": "TLS_SNI_CLIENTHELLO_ONLY",
        "profile": lambda: base(
            name="03-realm-host-v2-443",
            preserveSni=False,
            useRealmHostV2=True,
        ),
    },
    {
        "num": "04",
        "slug": "realm-preserve-sni",
        "id": "REALM_PLUS_PRESERVE",
        "title": "4. Realm Host v2 + Preserve SNI",
        "port": 443,
        "front": "TLS_SNI_CLIENTHELLO_ONLY",
        "profile": lambda: base(
            name="04-realm-preserve-sni-443",
            preserveSni=True,
            useRealmHostV2=True,
        ),
    },
    {
        "num": "05",
        "slug": "tcp-payload-sni",
        "id": "TCP_PAYLOAD_FRONT",
        "title": "5. TCP Payload + Preserve SNI",
        "port": 443,
        "front": "TLS_SNI_CLIENTHELLO_ONLY",
        "profile": lambda: base(
            name="05-tcp-payload-sni-443",
            useTcpPayload=True,
            tcpPayloadHex="160301",
        ),
    },
    {
        "num": "06",
        "slug": "http-host-inject",
        "id": "HTTP_HOST_INJECT",
        "title": "6. HTTP Host / CONNECT inject",
        "port": 80,
        "front": "HTTP_INJECT",
        "profile": lambda: base(
            name="06-http-host-inject-80",
            serverPort=80,
            frontMode="HTTP_INJECT",
            customSni="example.com",
            preserveSni=False,
            httpPayload=DEFAULT_HTTP.replace("example.com", "example.com"),
        ),
    },
    {
        "num": "07",
        "slug": "ssh-443-direct",
        "id": "SSH_ON_443_DIRECT",
        "title": "7. SSH on 443 Direct (no inject)",
        "port": 443,
        "front": "DIRECT",
        "profile": lambda: base(
            name="07-ssh-443-direct",
            serverPort=443,
            frontMode="DIRECT",
            preserveSni=False,
            portFallback=False,
        ),
    },
    {
        "num": "08",
        "slug": "tls-full-sni",
        "id": "TLS_FULL_SNI",
        "title": "8. Full TLS wrap + Custom SNI (stunnel)",
        "port": 443,
        "front": "TLS_SNI_FULL",
        "profile": lambda: base(
            name="08-tls-full-sni-443",
            frontMode="TLS_SNI_FULL",
            preserveSni=True,
        ),
    },
    {
        "num": "09",
        "slug": "port-fallback-hold",
        "id": "PORT_FALLBACK_HOLD",
        "title": "9. Port fallback hold stack (443→80→8080)",
        "port": 443,
        "front": "TLS_SNI_CLIENTHELLO_ONLY",
        "profile": lambda: base(
            name="09-port-fallback-hold-443",
            serverPort=443,
            portFallback=True,
        ),
    },
    {
        "num": "10",
        "slug": "www-sni-toggle",
        "id": "WWW_SNI_TOGGLE",
        "title": "10. www. SNI toggle",
        "port": 443,
        "front": "TLS_SNI_CLIENTHELLO_ONLY",
        "profile": lambda: base(
            name="10-www-sni-toggle-443",
            customSni="example.com",
            wwwSniToggle=True,
        ),
    },
    {
        "num": "11",
        "slug": "custom-setup-hold",
        "id": "CUSTOM_SETUP_HOLD",
        "title": "11. Custom Setup full hold stack",
        "port": 443,
        "front": "TLS_SNI_CLIENTHELLO_ONLY",
        "profile": lambda: base(
            name="11-custom-setup-hold-443",
            serverPort=443,
            portFallback=True,
            customSni="example.com",
            keepVpnAlive=True,
        ),
    },
    {
        "num": "13",
        "slug": "ws-tls-front",
        "id": "WS_TLS_FRONT",
        "title": "13. WebSocket upgrade + TLS SNI",
        "port": 443,
        "front": "HTTP_WEBSOCKET_TLS",
        "profile": lambda: base(
            name="13-ws-tls-front-443",
            frontMode="HTTP_WEBSOCKET_TLS",
            preserveSni=True,
        ),
    },
    {
        "num": "14",
        "slug": "http2-preamble-sni",
        "id": "HTTP2_PREAMBLE_SNI",
        "title": "14. HTTP/2 preface + TLS SNI",
        "port": 443,
        "front": "HTTP2_PREAMBLE_TLS",
        "profile": lambda: base(
            name="14-http2-preamble-sni-443",
            frontMode="HTTP2_PREAMBLE_TLS",
            preserveSni=True,
        ),
    },
    {
        "num": "15",
        "slug": "chrome-ja3-mimic",
        "id": "CHROME_JA3_MIMIC",
        "title": "15. Chrome JA3/JA4 mimic ClientHello",
        "port": 443,
        "front": "TLS_CHROME_JA3_MIMIC",
        "profile": lambda: base(
            name="15-chrome-ja3-mimic-443",
            frontMode="TLS_CHROME_JA3_MIMIC",
            preserveSni=True,
        ),
    },
    {
        "num": "16",
        "slug": "trojan-http-camouflage",
        "id": "TROJAN_HTTP_CAMOUFLAGE",
        "title": "16. Trojan-style HTTP camouflage",
        "port": 443,
        "front": "TROJAN_HTTP_CAMOUFLAGE",
        "profile": lambda: base(
            name="16-trojan-http-camouflage-443",
            frontMode="TROJAN_HTTP_CAMOUFLAGE",
            preserveSni=True,
        ),
    },
    {
        "num": "17",
        "slug": "random-padding-sni",
        "id": "RANDOM_PADDING_SNI",
        "title": "17. Random padding + TLS SNI",
        "port": 443,
        "front": "TLS_SNI_CLIENTHELLO_ONLY",
        "profile": lambda: base(
            name="17-random-padding-sni-443",
            useFrontPadding=True,
            frontPaddingMaxBytes=64,
        ),
    },
    {
        "num": "18",
        "slug": "doc-reality-xtls",
        "id": "DOC_REALITY_XTLS",
        "title": "18. [SOC drill] XTLS-Reality / TLS hijack",
        "port": 443,
        "front": "TLS_CHROME_JA3_MIMIC",
        "profile": lambda: base(
            name="18-doc-reality-xtls-443",
            frontMode="TLS_CHROME_JA3_MIMIC",
            customSni="www.microsoft.com",
            preserveSni=True,
        ),
    },
    {
        "num": "19",
        "slug": "doc-vmess-vless",
        "id": "DOC_VMESS_VLESS",
        "title": "19. [SOC drill] VMess / VLESS + WebSocket + TLS",
        "port": 443,
        "front": "HTTP_WEBSOCKET_TLS",
        "profile": lambda: base(
            name="19-doc-vmess-vless-443",
            frontMode="HTTP_WEBSOCKET_TLS",
            customSni="cdn.example.com",
            preserveSni=True,
        ),
    },
    {
        "num": "20",
        "slug": "doc-shadowsocks",
        "id": "DOC_SHADOWSOCKS",
        "title": "20. [SOC drill] Shadowsocks / plugins obfuscation",
        "port": 443,
        "front": "TLS_SNI_CLIENTHELLO_ONLY",
        "profile": lambda: base(
            name="20-doc-shadowsocks-443",
            useFrontPadding=True,
            frontPaddingMaxBytes=128,
            preserveSni=True,
        ),
    },
    {
        "num": "21",
        "slug": "doc-hysteria-quic",
        "id": "DOC_HYSTERIA_QUIC",
        "title": "21. [SOC drill] Hysteria / QUIC UDP tunnel",
        "port": 443,
        "front": "DIRECT",
        "profile": lambda: base(
            name="21-doc-hysteria-quic-443-udp",
            transportProtocol="UDP",
            frontMode="DIRECT",
            serverPort=443,
        ),
    },
    {
        "num": "22",
        "slug": "doc-cdn-fronting",
        "id": "DOC_CDN_FRONTING",
        "title": "22. [SOC drill] CDN domain fronting",
        "port": 443,
        "front": "TLS_SNI_FULL",
        "profile": lambda: base(
            name="22-doc-cdn-fronting-443",
            frontMode="TLS_SNI_FULL",
            customSni="cdn.example.com",
            preserveSni=True,
        ),
    },
    {
        "num": "23",
        "slug": "doc-mux-streams",
        "id": "DOC_MUX_STREAMS",
        "title": "23. [SOC drill] Multiplexed streams (MUX)",
        "port": 443,
        "front": "TLS_SNI_CLIENTHELLO_ONLY",
        "profile": lambda: base(
            name="23-doc-mux-streams-443",
            keepVpnAlive=True,
        ),
    },
    {
        "num": "24",
        "slug": "doc-encapsulated-tls",
        "id": "DOC_ENCAPSULATED_TLS",
        "title": "24. [SOC drill] Encapsulated TLS-in-TLS fingerprint",
        "port": 443,
        "front": "TLS_SNI_CLIENTHELLO_ONLY",
        "profile": lambda: base(
            name="24-doc-encapsulated-tls-443",
            keepVpnAlive=True,
        ),
    },
    {
        "num": "25",
        "slug": "doc-obfs4-dnstt",
        "id": "DOC_OBFS4_DNSTT",
        "title": "25. [SOC drill] obfs4 / DNSTT (HA Tunnel DNS mode)",
        "port": 53,
        "front": "DIRECT",
        "profile": lambda: base(
            name="25-doc-obfs4-dnstt-53-udp",
            serverPort=53,
            transportProtocol="UDP",
            frontMode="DIRECT",
        ),
    },
    {
        "num": "26",
        "slug": "billing-zero-rate-drill",
        "id": "BILLING_ZERO_RATE_DRILL",
        "title": "26. Billing / zero-rate miss drill (framing)",
        "port": 443,
        "front": "TLS_SNI_CLIENTHELLO_ONLY",
        "profile": lambda: base(
            name="26-billing-zero-rate-drill-443",
            portFallback=True,
            keepVpnAlive=True,
        ),
    },
]

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    manifest_entries = []
    all_scenarios = SCENARIOS  # user asked one per method; skip bonus in manifest primary list

    for s in SCENARIOS:
        filename = f"{s['num']}-{s['slug']}.nplab.json"
        path = os.path.join(OUT_DIR, filename)
        profile = s["profile"]()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2)
            f.write("\n")
        manifest_entries.append(
            {
                "methodId": s["id"],
                "methodNum": s["num"],
                "title": s["title"],
                "configFile": f"configs/{filename}",
                "port": s["port"],
                "frontMode": s["front"],
                "serverHost": HOST,
            }
        )
        print(f"Wrote {filename}")

    manifest = {
        "version": 1,
        "labServer": {
            "hostname": HOST,
            "username": USER,
            "sshPorts": [22, 80],
            "sslTlsPorts": [143, 443],
            "proxyPorts": [8080, 3128, 8888],
            "udpgwPorts": [7200, 7300],
            "accountCreated": "2026-08-06",
            "accountExpires": "2026-08-13",
            "notes": "UDPGW ports are drill-only; NetPath Lab is TCP/SSH focused. Proxy ports used by port-fallback hold stack (443→80→8080).",
        },
        "securityWarning": "Configs contain live credentials. This is a public repo — rotate the lab password after drills. Authorized testing only.",
        "importSteps": [
            "Download a .nplab.json config from this site",
            "Open NetPath Lab → Import config",
            "Select the downloaded file",
            "Tap Connect (grant VPN permission if prompted)",
        ],
        "configs": manifest_entries,
    }

    manifest_path = os.path.join(OUT_DIR, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print(f"Wrote manifest.json ({len(manifest_entries)} configs)")

    zip_path = os.path.join(os.path.dirname(OUT_DIR), "netpath-lab-configs.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for s in SCENARIOS:
            filename = f"{s['num']}-{s['slug']}.nplab.json"
            zf.write(os.path.join(OUT_DIR, filename), f"configs/{filename}")
        zf.write(manifest_path, "configs/manifest.json")
    print(f"Wrote {zip_path}")


if __name__ == "__main__":
    main()
