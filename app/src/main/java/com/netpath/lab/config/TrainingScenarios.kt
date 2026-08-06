package com.netpath.lab.config

/**
 * Discrete billing-evasion / hold-stack methods for authorized ISP lab drills.
 * Each method maps to TunnelProfile knobs and PASS/FAIL defender hints.
 */
object TrainingScenarios {

    data class Scenario(
        val id: String,
        val title: String,
        val description: String,
        val defenderHint: String,
        /** On-screen configuration steps shown when the method is applied. */
        val steps: List<String>,
        val apply: (TunnelProfile) -> TunnelProfile
    )

    private const val PASS_FAIL_FRAMING =
        "PASS = charged or blocked on pack while dialing operator VPS. " +
            "FAIL = unmetered success while real data reaches the VPS."

    val all: List<Scenario> = listOf(
        Scenario(
            id = "SSH_DIRECT_22",
            title = "0. SSH on 22 Direct (baseline)",
            description = "Raw SSH to lab host:22 with no HTTP/TLS inject — OpenSSH baseline before any hold-stack fronts.",
            defenderHint = "$PASS_FAIL_FRAMING SSH on :22 to hosting ASN is trivially visible; pack should rate or block off-list dest IPs.",
            steps = listOf(
                "Host = fr1.sshweb.site (or your VPS); Port = 22.",
                "Front = Direct (no SNI front).",
                "All inject toggles OFF; port fallback OFF.",
                "Probe baseline: expect OpenSSH banner (e.g. SSH-2.0-OpenSSH_9.9).",
                "On pack: compare charging to method 6 (HTTP inject on :80) and method 1 (SNI on :443)."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.DIRECT,
                    preserveSni = false,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    wwwSniToggle = false,
                    portFallback = false,
                    serverPort = 22,
                    transportProtocol = TransportProtocol.TCP
                )
            }
        ),
        Scenario(
            id = "SNI_MISMATCH",
            title = "1. SNI mismatch / Custom SNI (ClientHello-only)",
            description = "Dial your lab VPS IP on :443 but put a pack-like hostname in the TLS ClientHello SNI. " +
                "Mirrors HA Tunnel–style Custom SNI SSL/TLS (ClientHello-only, then SSH).",
            defenderHint = "$PASS_FAIL_FRAMING PASS if pack drops/rates when dest IP is outside allowlist.",
            steps = listOf(
                "Set SSH host = your operator VPS public IPv4 (not a free server).",
                "Port = 443 (or enable port fallback later).",
                "Front = Custom SNI (SSL/TLS Mode) / TLS_SNI_CLIENTHELLO_ONLY.",
                "Custom SNI = pack-like hostname (training only); dial host stays VPS IP.",
                "Preserve SNI ON; Realm Host v2 OFF; TCP Payload OFF.",
                "Connect on pack SIM → score PASS/FAIL against charging/DPI."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    pathType = PathType.DIRECT_CONNECTION,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    wwwSniToggle = false,
                    portFallback = false,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort,
                    transportProtocol = TransportProtocol.TCP
                )
            }
        ),
        Scenario(
            id = "PRESERVE_SNI_ON",
            title = "2. Preserve SNI",
            description = "Keep Custom SNI for the entire front path; do not rewrite to the SSH hostname.",
            defenderHint = "$PASS_FAIL_FRAMING Same IP allowlist should catch VPS destinations regardless of preserved SNI string.",
            steps = listOf(
                "Host = VPS IP; Custom SNI = pack-like name.",
                "Front = Custom SNI (SSL/TLS Mode).",
                "Turn Preserve SNI ON.",
                "Realm Host v2 OFF; www. toggle OFF.",
                "Connect and confirm Session log shows preserveSni=true and effective SNI unchanged."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    wwwSniToggle = false,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort
                )
            }
        ),
        Scenario(
            id = "REALM_HOST_V2",
            title = "3. Realm Host v2",
            description = "Alternate realm/dial ordering used by consumer tunnel apps. Lab still dials the VPS IP; realm hostname is resolved for logging/identity only.",
            defenderHint = "$PASS_FAIL_FRAMING Realm toggle must not bypass destination-IP policy.",
            steps = listOf(
                "Host = VPS IP; Custom SNI = realm/pack-like hostname.",
                "Front = Custom SNI (SSL/TLS Mode).",
                "Turn Use Realm Host (v2) ON.",
                "Preserve SNI OFF for this isolated drill.",
                "Watch Session log for RealmV2 resolve lines; dial must remain serverHost."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = false,
                    useRealmHostV2 = true,
                    useTcpPayload = false,
                    wwwSniToggle = false,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort
                )
            }
        ),
        Scenario(
            id = "REALM_PLUS_PRESERVE",
            title = "4. Realm Host v2 + Preserve SNI",
            description = "Combine realm ordering with preserved Custom SNI — common consumer hold path.",
            defenderHint = "$PASS_FAIL_FRAMING Toggle order must not matter if enforcement is destination-IP based.",
            steps = listOf(
                "Host = VPS IP; Custom SNI = pack-like hostname.",
                "Front = Custom SNI (SSL/TLS Mode).",
                "Realm Host v2 ON + Preserve SNI ON.",
                "TCP Payload OFF; www. OFF.",
                "Compare charging outcome to method 1 and method 3 alone."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    useRealmHostV2 = true,
                    useTcpPayload = false,
                    wwwSniToggle = false,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort
                )
            }
        ),
        Scenario(
            id = "TCP_PAYLOAD_FRONT",
            title = "5. TCP Payload + Preserve SNI",
            description = "Prepend optional TCP bytes then ClientHello-only SNI front (cosmetic hold bytes).",
            defenderHint = "$PASS_FAIL_FRAMING Payload cosmetics should not bypass IP allowlists.",
            steps = listOf(
                "Host = VPS IP; port = 443.",
                "Front = Custom SNI (SSL/TLS Mode); Preserve SNI ON.",
                "Use TCP Payload ON; hex default 160301 (or operator lab value).",
                "Realm Host v2 OFF.",
                "Confirm Session log: TCP payload sent, then ClientHello SNI."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = true,
                    tcpPayloadHex = p.tcpPayloadHex.ifBlank { "160301" },
                    wwwSniToggle = false,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort
                )
            }
        ),
        Scenario(
            id = "HTTP_HOST_INJECT",
            title = "6. HTTP Host / CONNECT inject",
            description = "Send crafted HTTP CONNECT/Host text before SSH bytes on the TCP session.",
            defenderHint = "$PASS_FAIL_FRAMING Validate HTTP on pack ports; do not forward arbitrary CONNECT to off-list IPs.",
            steps = listOf(
                "Host = VPS IP; port typically 80 or 443.",
                "Front = HTTP Inject.",
                "HTTP payload Host/CONNECT target = pack-like name (form fills from Custom SNI).",
                "Preserve/Realm/TCP payload irrelevant for this front — leave off.",
                "Correlate UPF/DPI: injected Host vs true dest IP."
            ),
            apply = { p ->
                val host = p.customSni.ifBlank { "example.com" }
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.HTTP_INJECT,
                    preserveSni = false,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    wwwSniToggle = false,
                    customSni = host,
                    httpPayload = TunnelProfile.DEFAULT_HTTP_PAYLOAD.replace("example.com", host)
                )
            }
        ),
        Scenario(
            id = "SSH_ON_443_DIRECT",
            title = "7. SSH on 443 Direct (no inject)",
            description = "Raw SSH to lab host:443 with no HTTP/TLS inject — fingerprint / probe target.",
            defenderHint = "$PASS_FAIL_FRAMING SSH banner on pack bearer to hosting ASN should be probed and denied/rated.",
            steps = listOf(
                "Ensure OpenSSH listens on VPS :443 (see lab server docs).",
                "Host = VPS IP; Port = 443.",
                "Front = Direct (no SNI front).",
                "All inject toggles OFF.",
                "On pack: expect SSH banner visibility to SOC probes."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.DIRECT,
                    preserveSni = false,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    wwwSniToggle = false,
                    portFallback = false,
                    serverPort = 443,
                    transportProtocol = TransportProtocol.TCP
                )
            }
        ),
        Scenario(
            id = "TLS_FULL_SNI",
            title = "8. Full TLS wrap + Custom SNI (stunnel)",
            description = "Complete TLS handshake with custom SNI for stunnel/sslh lab backends. Trusts lab certs.",
            defenderHint = "$PASS_FAIL_FRAMING Still enforce dest IP allowlists; full TLS to a VPS is not a pack CDN.",
            steps = listOf(
                "On VPS: terminate TLS (stunnel/sslh) and forward to sshd.",
                "Host = VPS IP; Port = 443 (or stunnel listen port).",
                "Front = Custom SNI full TLS.",
                "Custom SNI = pack-like name; Preserve SNI ON.",
                "ClientHello-only drills do NOT need stunnel — this method does."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_FULL,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    wwwSniToggle = false,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort
                )
            }
        ),
        Scenario(
            id = "PORT_FALLBACK_HOLD",
            title = "9. Port fallback hold stack (443→80→8080)",
            description = "On connect failure, retry hold ports 443 → 80 → 8080 — consumer apps do this to find an open path.",
            defenderHint = "$PASS_FAIL_FRAMING Pack policy must cover all hold ports, not only 443.",
            steps = listOf(
                "Host = VPS IP; open sshd (or front) on at least one of 443/80/8080.",
                "Front = Custom SNI (SSL/TLS Mode); Preserve SNI ON.",
                "Enable Port fallback (try 443 → 80 → 8080).",
                "Primary port spinner can start at 443.",
                "Session log should show which port succeeded."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    wwwSniToggle = false,
                    portFallback = true,
                    serverPort = 443,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    transportProtocol = TransportProtocol.TCP
                )
            }
        ),
        Scenario(
            id = "WWW_SNI_TOGGLE",
            title = "10. www. SNI toggle",
            description = "Flip www. prefix on Custom SNI to probe exact-host ISP match games.",
            defenderHint = "$PASS_FAIL_FRAMING Exact hostname games must still lose to dest-IP allowlists.",
            steps = listOf(
                "Host = VPS IP; Custom SNI = example.com (or pack-like bare host).",
                "Front = Custom SNI (SSL/TLS Mode); Preserve SNI ON.",
                "Turn Fresh SNI / www. toggle ON — effective SNI becomes www.example.com (or strips www.).",
                "Compare to same drill with toggle OFF.",
                "Check Effective SNI label before Connect."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    wwwSniToggle = true,
                    customSni = p.customSni.ifBlank { "example.com" },
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort
                )
            }
        ),
        Scenario(
            id = "CUSTOM_SETUP_HOLD",
            title = "11. Custom Setup full hold stack",
            description = "Full consumer-style hold path: Direct Connection → Custom SNI SSL/TLS → Preserve SNI → " +
                "port 443 + fallback → TCP → www. toggle → keep-alive (Realm/TCP payload available in panel).",
            defenderHint = "$PASS_FAIL_FRAMING PASS if pack still blocks VPS dest despite full hold stack.",
            steps = listOf(
                "Enable Custom Setup master switch.",
                "Path = Direct Connection; Front = Custom SNI (SSL/TLS Mode).",
                "Custom SNI = pack-like host; Preserve SNI ON.",
                "Optional: Realm Host v2 / TCP Payload as needed for parity with consumer app.",
                "Port 443 + Port fallback ON; Protocol TCP; Nearby hint ON.",
                "www. toggle as needed; Keep VPN alive ON (+ battery unrestricted).",
                "Connect on pack SIM and score PASS/FAIL."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    pathType = PathType.DIRECT_CONNECTION,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    serverPort = 443,
                    portFallback = true,
                    transportProtocol = TransportProtocol.TCP,
                    wwwSniToggle = false,
                    preferNearbyServer = true,
                    keepVpnAlive = true,
                    customSni = p.customSni.ifBlank { "example.com" }
                )
            }
        ),
        // --- Advanced circumvention-ecosystem drills (DPI research / ISP billing) ---
        Scenario(
            id = "WS_TLS_FRONT",
            title = "13. WebSocket upgrade + TLS SNI",
            description = "HTTP WebSocket upgrade (Host = pack-like SNI) then ClientHello-only TLS — models VMess/Trojan WS+TLS transport seen in Chinese ecosystem proxies.",
            defenderHint = "$PASS_FAIL_FRAMING WS camouflage must not bypass dest-IP allowlists; score WS+TLS to hosting ASN on pack.",
            steps = listOf(
                "Host = VPS IP; Port = 443.",
                "Front = WebSocket upgrade + TLS SNI.",
                "Custom SNI = pack-like hostname; Preserve SNI ON.",
                "Lab server: sshd on 443 tolerates inject-then-SSH (same as HTTP inject drills).",
                "Capture: ASCII upgrade → TLS ClientHello → SSH; correlate DPI Host/SNI vs dial IP."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.HTTP_WEBSOCKET_TLS,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    useFrontPadding = false,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort
                )
            }
        ),
        Scenario(
            id = "HTTP2_PREAMBLE_SNI",
            title = "14. HTTP/2 preface + TLS SNI",
            description = "Send HTTP/2 connection preface (PRI * HTTP/2.0) before ClientHello SNI — h2 camouflage used with CDN and reverse-proxy fronts.",
            defenderHint = "$PASS_FAIL_FRAMING h2 preface to non-CDN VPS IP should not inherit zero-rate; probe ALPN/h2 on pack.",
            steps = listOf(
                "Host = VPS IP; Port = 443.",
                "Front = HTTP/2 preface + TLS SNI.",
                "Custom SNI = pack-like host; Preserve SNI ON.",
                "Session log should show PRI * HTTP/2.0 then ClientHello.",
                "Defender: h2 to off-list IP ≠ legitimate CDN edge."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.HTTP2_PREAMBLE_TLS,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    useFrontPadding = false,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort
                )
            }
        ),
        Scenario(
            id = "CHROME_JA3_MIMIC",
            title = "15. Chrome JA3/JA4 mimic ClientHello",
            description = "Static Chrome-like TLS ClientHello (ALPN h2, key_share, extension order) before SSH — uTLS-style mimic without third-party binaries.",
            defenderHint = "$PASS_FAIL_FRAMING JA3 mimic does not change dest IP; SNI≠IP + hosting ASN rules still apply.",
            steps = listOf(
                "Host = VPS IP; Port = 443.",
                "Front = Chrome JA3 mimic ClientHello.",
                "Custom SNI = pack-like host; Preserve SNI ON.",
                "Export Session log; compare JA3/JA4 hash in SOC Zeek/Suricata to browser baseline.",
                "PASS if pack still rates VPS dest despite browser-like fingerprint."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_CHROME_JA3_MIMIC,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    useFrontPadding = false,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort
                )
            }
        ),
        Scenario(
            id = "TROJAN_HTTP_CAMOUFLAGE",
            title = "16. Trojan-style HTTP camouflage",
            description = "Fake Trojan password hash + HTTP GET before SSH bytes — wire pattern drill for Trojan-gfw class proxies (no Trojan server in app).",
            defenderHint = "$PASS_FAIL_FRAMING Regex on trojan token irrelevant if dest IP ∉ allowlist; active probe off-list hosts.",
            steps = listOf(
                "Host = VPS IP; Port = 443.",
                "Front = Trojan HTTP camouflage.",
                "Custom SNI fills Host header in fake GET.",
                "sshd must accept non-SSH leading bytes or use a strip-and-forward lab proxy.",
                "SOC: look for 56-byte hex + CRLF + GET pattern to hosting IPs on pack."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TROJAN_HTTP_CAMOUFLAGE,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    useFrontPadding = false,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort
                )
            }
        ),
        Scenario(
            id = "RANDOM_PADDING_SNI",
            title = "17. Random padding + TLS SNI",
            description = "Prepends random-length zero-byte padding before ClientHello SNI — length obfuscation used in Shadowsocks/VMess padding strategies.",
            defenderHint = "$PASS_FAIL_FRAMING Padding must not defeat IP allowlists; burst-size heuristics are secondary to dest IP.",
            steps = listOf(
                "Host = VPS IP; Port = 443.",
                "Front = Custom SNI (SSL/TLS Mode); Preserve SNI ON.",
                "Apply this method — enables front random padding (up to 64 B) automatically.",
                "Session log: 'Front random padding sent (N zero bytes)' then ClientHello.",
                "Compare charging to method 1 without padding."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    useFrontPadding = true,
                    frontPaddingMaxBytes = 64,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort
                )
            }
        ),
        Scenario(
            id = "DOC_REALITY_XTLS",
            title = "18. [SOC drill] XTLS-Reality / TLS hijack",
            description = "Document-only: Reality hijacks a real site's TLS handshake (ephemeral cert, shortId steganography, fallback to real dest on probe). Requires Xray/sing-box — not bundled.",
            defenderHint = "$PASS_FAIL_FRAMING Drill with separate Xray lab: PASS if pack still blocks non-allowlist VPS; watch TLS-in-TLS + post-handshake ticket anomalies.",
            steps = listOf(
                "Deploy operator Xray/sing-box Reality inbound on YOUR VPS (not public free nodes).",
                "Client: VLESS+Reality with uTLS Chrome fingerprint; dest = high-traffic cover site.",
                "Pack test: confirm whether zero-rate triggers on SNI alone vs true edge IP.",
                "Defender: encapsulated TLS fingerprinting; active probe; JA4 + NewSessionTicket behavior.",
                "NetPath Lab logs this checklist in Session log when applied — no Reality wire in app."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_CHROME_JA3_MIMIC,
                    preserveSni = true,
                    customSni = p.customSni.ifBlank { "www.microsoft.com" },
                    serverPort = 443
                )
            }
        ),
        Scenario(
            id = "DOC_VMESS_VLESS",
            title = "19. [SOC drill] VMess / VLESS + WebSocket + TLS",
            description = "Document-only: V2Ray-family stacks (VMess AEAD, VLESS over WS/TLS/gRPC). Full protocol not ported — use method 13 for WS+TLS front analogue.",
            defenderHint = "$PASS_FAIL_FRAMING Test with separate v2ray/xray client to operator VPS; FAIL if CDN SNI masks non-CDN dest IP on pack.",
            steps = listOf(
                "Stand up VMess or VLESS inbound (WS+TLS) on operator VPS behind nginx/caddy.",
                "Transport path: TCP → TLS → WS → VMess/VLESS → inner traffic.",
                "Pack drill: SNI may show CDN host while dial IP is your VPS — score dest IP.",
                "Defender: TLS-in-TLS encapsulated handshake detection; WS path normalization.",
                "App method 13 models only the WS+ClientHello front slice."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.HTTP_WEBSOCKET_TLS,
                    preserveSni = true,
                    customSni = p.customSni.ifBlank { "cdn.example.com" },
                    serverPort = 443
                )
            }
        ),
        Scenario(
            id = "DOC_SHADOWSOCKS",
            title = "20. [SOC drill] Shadowsocks / plugins obfuscation",
            description = "Document-only: Shadowsocks with v2ray-plugin, simple-obfs, or TLS camouflage. Custom AEAD protocol — test with shadowsocks-libev/go on operator VPS.",
            defenderHint = "$PASS_FAIL_FRAMING Active probing + entropy analysis; pack policy must not allow arbitrary UDP/TCP to hosting ASNs.",
            steps = listOf(
                "Deploy Shadowsocks server on operator VPS (plugin optional: obfs-local, v2ray-plugin).",
                "Client: official SS app or sing-box — never public free SS lists.",
                "Pack test: compare detection vs SSH+SNI hold (methods 1–17).",
                "Defender: ML traffic-shape classifiers; modified active probing for TLS-disguised SS.",
                "App method 17 models padding only — not SS crypto."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    useFrontPadding = true,
                    frontPaddingMaxBytes = 128,
                    preserveSni = true,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = 443
                )
            }
        ),
        Scenario(
            id = "DOC_HYSTERIA_QUIC",
            title = "21. [SOC drill] Hysteria / QUIC UDP tunnel",
            description = "Document-only: QUIC-based Hysteria/Hysteria2 evades TCP-only DPI paths. App is TCP/SSH-focused; drill UDP separately.",
            defenderHint = "$PASS_FAIL_FRAMING Enforce identical allowlists on UDP/QUIC to pack CDN edges; FAIL if QUIC to VPS is unmetered.",
            steps = listOf(
                "Deploy Hysteria2 server on operator VPS (UDP port, TLS 1.3 + QUIC).",
                "Client: hysteria or sing-box — authorized lab handset only.",
                "Pack test: many zero-rate products ignore UDP — explicit FAIL finding.",
                "Defender: QUIC Initial DCID/SNI inspection; rate-limit UDP to non-CDN prefixes.",
                "NetPath Lab Protocol spinner logs UDP as flakier — no QUIC wire in app."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    transportProtocol = TransportProtocol.UDP,
                    frontMode = FrontMode.DIRECT,
                    serverPort = 443
                )
            }
        ),
        Scenario(
            id = "DOC_CDN_FRONTING",
            title = "22. [SOC drill] CDN domain fronting",
            description = "Document-only: TLS SNI points to CDN edge while Host/inner route targets operator origin — classic meek/Cloudflare fronting pattern.",
            defenderHint = "$PASS_FAIL_FRAMING Tight CDN IP allowlists per service prefix; deny CONNECT to off-list origins behind CDN SNI.",
            steps = listOf(
                "Configure CDN (operator-owned zone) → origin = your VPS.",
                "Client SNI = cdn.customer.com; inner HTTP Host or routing header selects origin.",
                "Pack test: zero-rate on CDN ASN must not cover arbitrary customer origins.",
                "Defender: correlate CDN edge IP allowlist with authorized service prefixes only.",
                "App methods 1/8/13–15 model partial wire slices without CDN dependency."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_FULL,
                    preserveSni = true,
                    customSni = p.customSni.ifBlank { "cdn.example.com" },
                    serverPort = 443
                )
            }
        ),
        Scenario(
            id = "DOC_MUX_STREAMS",
            title = "23. [SOC drill] Multiplexed streams (MUX)",
            description = "Document-only: smux/MUX merges many inner TLS sessions on one outer TCP — reduces encapsulated-TLS visibility but not dest IP.",
            defenderHint = "$PASS_FAIL_FRAMING Long-lived multiplex to hosting ASN + byte quotas; MUX does not fix SNI≠IP billing gaps.",
            steps = listOf(
                "Enable MUX in Xray/sing-box client/server on operator VPS.",
                "Generate multiple parallel HTTPS sessions inside one outer tunnel.",
                "Pack test: billing on outer flow dest IP must still apply.",
                "Defender: outer-connection burst/RTT analysis (USENIX 2024 fingerprint caveat).",
                "SSH VPN in NetPath Lab is inherently multiplexed — compare flow duration scoring."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    keepVpnAlive = true,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = 443
                )
            }
        ),
        Scenario(
            id = "DOC_ENCAPSULATED_TLS",
            title = "24. [SOC drill] Encapsulated TLS-in-TLS fingerprint",
            description = "Document-only: ISP/GFW-class detection of inner TLS ClientHello inside outer tunnel (protocol-agnostic). Relevant when pack users nest HTTPS in SSH/VPN.",
            defenderHint = "$PASS_FAIL_FRAMING Billing on outer dest IP first; add encapsulated-TLS classifier as defense-in-depth on pack bearer.",
            steps = listOf(
                "Baseline: method 1 SSH+SNI to VPS — outer dest IP = VPS.",
                "Advanced: browse HTTPS sites through NetPath VPN — inner TLS handshakes appear in tunnel payload.",
                "SOC: tri-gram / burst similarity classifier on mirrored traffic (see USENIX 2024 Xue et al.).",
                "PASS if pack charges outer VPS flow regardless of inner TLS volume.",
                "Document finding if only inner SNI is used for zero-rate (policy error)."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    keepVpnAlive = true,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = 443
                )
            }
        ),
        Scenario(
            id = "DOC_OBFS4_DNSTT",
            title = "25. [SOC drill] obfs4 / DNSTT (HA Tunnel DNS mode)",
            description = "Document-only: Tor obfs4 bridges and DNSTT DNS tunneling (HA Tunnel DNS mode). Requires bridge software — not in NetPath Lab.",
            defenderHint = "$PASS_FAIL_FRAMING Default-deny DNS tunneling and obfs4-like entropy on pack; charge/quota DNS to non-resolver IPs.",
            steps = listOf(
                "obfs4: deploy bridge on operator VPS; client = Tor/obfs4proxy (authorized lab only).",
                "DNSTT: encode stream in DNS queries to operator authoritative zone.",
                "Pack test: DNS zero-rate must not cover arbitrary QNAME tunnels to VPS.",
                "Defender: entropy + query-rate limits; block non-ISP resolvers on pack APN.",
                "HA Tunnel DNS mode is consumer analogue — document parity in SOC ticket."
            ),
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.DIRECT,
                    transportProtocol = TransportProtocol.UDP,
                    serverPort = 53
                )
            }
        ),
        Scenario(
            id = "BILLING_ZERO_RATE_DRILL",
            title = "26. Billing / zero-rate miss drill (framing)",
            description = "Scoring frame for every method above: you are testing whether pack/zero-rate controls miss " +
                "real data usage to an operator-owned VPS. Apply after configuring any method 1–25.",
            defenderHint = PASS_FAIL_FRAMING +
                " Also check APN/bearer, IPv4 vs IPv6 parity, over-broad CDN ASN allowlists, UDP/QUIC gaps.",
            steps = listOf(
                "Control: on Wi‑Fi or paid data, confirm SSH to YOUR VPS works.",
                "Switch to pack/zero-rate SIM/APN only (authorized lab).",
                "Apply any method 1–25; host must remain operator VPS IP (doc-only: separate client to same VPS).",
                "Generate real traffic through the tunnel (not idle TCP only).",
                "PASS: session blocked/stalled OR fully charged on general rating group.",
                "FAIL: unmetered success while bytes reach the VPS = allowlist/policy gap.",
                "Advanced notes (SOC checklist): wrong APN/bearer; IPv6≠IPv4; CDN ASN; UDP/QUIC; encapsulated TLS.",
                "Export Session log + correlate UPF/PCRF/DPI timestamps."
            ),
            apply = { p ->
                // Framing-only: leave operator credentials; nudge toward a clear SNI-mismatch baseline.
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    portFallback = true,
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    transportProtocol = TransportProtocol.TCP,
                    keepVpnAlive = true
                )
            }
        )
    )

    fun byId(id: String): Scenario? = all.find { it.id == id }

    fun formatSteps(scenario: Scenario): String =
        buildString {
            appendLine(scenario.title)
            appendLine(scenario.description)
            appendLine()
            appendLine("Config steps:")
            scenario.steps.forEachIndexed { i, step -> appendLine("  ${i + 1}. $step") }
            appendLine()
            appendLine("Defender: ${scenario.defenderHint}")
        }
}
