package com.netpath.lab.config

import java.io.Serializable

enum class FrontMode {
    DIRECT,
    HTTP_INJECT,
    TLS_SNI_CLIENTHELLO_ONLY,
    TLS_SNI_FULL
}

/** Path type under Custom Setup (HA Tunnel–style Direct Connection). */
enum class PathType {
    DIRECT_CONNECTION
}

/** Transport preference for hold-stack drills. SSH front uses TCP; UDP is logged as flakier. */
enum class TransportProtocol {
    TCP,
    UDP
}

data class TunnelProfile(
    val id: String = java.util.UUID.randomUUID().toString(),
    val name: String = "Lab profile",
    val serverHost: String = "",
    val serverPort: Int = 443,
    val username: String = "",
    val password: String = "",
    val privateKeyPem: String = "",
    val frontMode: FrontMode = FrontMode.TLS_SNI_CLIENTHELLO_ONLY,
    val customSni: String = "",
    val httpPayload: String = DEFAULT_HTTP_PAYLOAD,
    val tcpPayloadHex: String = "",
    val useRealmHostV2: Boolean = false,
    val preserveSni: Boolean = true,
    val useTcpPayload: Boolean = false,
    val connectTimeoutMs: Int = 15_000,
    /** Master switch for the Custom Setup hold stack. */
    val customSetup: Boolean = true,
    val pathType: PathType = PathType.DIRECT_CONNECTION,
    val transportProtocol: TransportProtocol = TransportProtocol.TCP,
    /** Toggle www. prefix on Custom SNI (exact-host ISP match drills). */
    val wwwSniToggle: Boolean = false,
    /** On connect failure, try 443 → 80 → 8080. */
    val portFallback: Boolean = true,
    /** Prefer nearby/low-RTT lab server (hint logged; operator picks host). */
    val preferNearbyServer: Boolean = true,
    /** Request battery unrestricted + avoid spam reconnects while VPN is up. */
    val keepVpnAlive: Boolean = true
) : Serializable {
    companion object {
        const val DEFAULT_HTTP_PAYLOAD =
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"

        val HOLD_PORTS = listOf(443, 80, 8080)

        fun resolveSni(profile: TunnelProfile): String {
            var sni = profile.customSni.trim()
            if (sni.isEmpty()) {
                sni = if (profile.preserveSni) profile.serverHost else profile.serverHost
            }
            if (!profile.wwwSniToggle) return sni
            val bare = sni.removePrefix("www.")
            return if (sni.startsWith("www.", ignoreCase = true)) bare else "www.$bare"
        }
    }
}
