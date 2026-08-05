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
        Scenario(
            id = "BILLING_ZERO_RATE_DRILL",
            title = "12. Billing / zero-rate miss drill (framing)",
            description = "Scoring frame for every method above: you are testing whether pack/zero-rate controls miss " +
                "real data usage to an operator-owned VPS. Apply after configuring any method 1–11.",
            defenderHint = PASS_FAIL_FRAMING +
                " Also check APN/bearer, IPv4 vs IPv6 parity, and over-broad CDN ASN allowlists.",
            steps = listOf(
                "Control: on Wi‑Fi or paid data, confirm SSH to YOUR VPS works.",
                "Switch to pack/zero-rate SIM/APN only (authorized lab).",
                "Apply any method 1–11; host must remain operator VPS IP.",
                "Generate real traffic through the tunnel (not idle TCP only).",
                "PASS: session blocked/stalled OR fully charged on general rating group.",
                "FAIL: unmetered success while bytes reach the VPS = allowlist/policy gap.",
                "Advanced notes (SOC checklist): wrong APN/bearer confusion; IPv6≠IPv4 policy; entire CDN ASN allowlisted.",
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
