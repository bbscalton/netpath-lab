package com.netpath.lab.config

object TrainingScenarios {

    data class Scenario(
        val id: String,
        val title: String,
        val description: String,
        val defenderHint: String,
        val apply: (TunnelProfile) -> TunnelProfile
    )

    val all: List<Scenario> = listOf(
        Scenario(
            id = "CUSTOM_SETUP_HOLD",
            title = "Custom Setup hold stack (default)",
            description = "Full hold path: Direct Connection → Custom SNI SSL/TLS → Preserve SNI → port 443 + fallback → TCP → keep-alive.",
            defenderHint = "PASS if pack still blocks VPS dest despite full consumer-style hold stack. FAIL if unmetered success.",
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
            id = "SNI_MISMATCH",
            title = "SNI mismatch (ClientHello-only)",
            description = "Dial your lab VPS IP on :443 but put an allowlisted-looking hostname in TLS SNI. Mimics HA Tunnel Custom SNI SSL/TLS.",
            defenderHint = "PASS if pack bearer drops/rates when dest IP is outside allowlist. FAIL if unmetered success.",
            apply = { p ->
                p.copy(
                    customSetup = true,
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    customSni = p.customSni.ifBlank { "www.example.com" },
                    serverPort = if (p.serverPort == 22) 443 else p.serverPort
                )
            }
        ),
        Scenario(
            id = "PRESERVE_SNI_ON",
            title = "Preserve SNI",
            description = "Keep Custom SNI for the entire front path; do not rewrite to SSH hostname.",
            defenderHint = "Same IP allowlist should still catch VPS destinations regardless of preserved SNI string.",
            apply = { p ->
                p.copy(
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    useRealmHostV2 = false
                )
            }
        ),
        Scenario(
            id = "REALM_PLUS_PRESERVE",
            title = "Realm Host v2 + Preserve SNI",
            description = "Alternate dial/realm ordering used by consumer tunnel apps, with SNI preserved.",
            defenderHint = "Toggle order must not matter if enforcement is destination-IP based.",
            apply = { p ->
                p.copy(
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    useRealmHostV2 = true
                )
            }
        ),
        Scenario(
            id = "HTTP_HOST_INJECT",
            title = "HTTP Host / CONNECT inject",
            description = "Send crafted HTTP text before SSH bytes on the TCP session.",
            defenderHint = "Validate HTTP on pack ports; do not forward arbitrary CONNECT to off-list IPs.",
            apply = { p ->
                p.copy(
                    frontMode = FrontMode.HTTP_INJECT,
                    httpPayload = TunnelProfile.DEFAULT_HTTP_PAYLOAD.replace(
                        "example.com",
                        p.customSni.ifBlank { "example.com" }
                    )
                )
            }
        ),
        Scenario(
            id = "SSH_ON_443_DIRECT",
            title = "SSH on 443 direct",
            description = "Raw SSH to lab host:443 with no inject (fingerprint / probe target).",
            defenderHint = "SSH banner on pack bearer to hosting ASN should be probed and denied/rated.",
            apply = { p ->
                p.copy(
                    frontMode = FrontMode.DIRECT,
                    preserveSni = false,
                    useRealmHostV2 = false,
                    useTcpPayload = false,
                    serverPort = 443
                )
            }
        ),
        Scenario(
            id = "TCP_PAYLOAD_FRONT",
            title = "TCP payload + Preserve SNI",
            description = "Prepend optional TCP bytes then ClientHello-only SNI front.",
            defenderHint = "Payload cosmetics should not bypass IP allowlists.",
            apply = { p ->
                p.copy(
                    frontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
                    preserveSni = true,
                    useTcpPayload = true,
                    tcpPayloadHex = p.tcpPayloadHex.ifBlank { "160301" }
                )
            }
        ),
        Scenario(
            id = "TLS_FULL_SNI",
            title = "Full TLS wrap + Custom SNI",
            description = "Complete TLS handshake with custom SNI (for stunnel/sslh lab backends). Trusts lab certs.",
            defenderHint = "Still enforce dest IP allowlists; full TLS to a VPS is not a pack CDN.",
            apply = { p ->
                p.copy(
                    frontMode = FrontMode.TLS_SNI_FULL,
                    preserveSni = true,
                    useRealmHostV2 = false
                )
            }
        )
    )

    fun byId(id: String): Scenario? = all.find { it.id == id }
}
