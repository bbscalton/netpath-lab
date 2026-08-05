package com.netpath.lab.front

import com.netpath.lab.config.FrontMode
import com.netpath.lab.config.TunnelProfile
import com.netpath.lab.log.SessionLog
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Builds the TCP (and optional TLS/HTTP) front path to the SSH server,
 * mirroring consumer tunnel-app injection techniques for lab testing.
 */
class FrontDoorFactory(
    private val protectSocket: (Socket) -> Unit
) {
    fun open(profile: TunnelProfile): Socket {
        val dialHost = resolveDialHost(profile)
        val dialPort = profile.serverPort
        SessionLog.append(
            "Front mode=${profile.frontMode} dial=$dialHost:$dialPort " +
                "sni='${profile.customSni}' realmV2=${profile.useRealmHostV2} " +
                "preserveSni=${profile.preserveSni} tcpPayload=${profile.useTcpPayload}"
        )

        val tcp = Socket()
        protectSocket(tcp)
        tcp.tcpNoDelay = true
        tcp.soTimeout = 0
        tcp.connect(InetSocketAddress(dialHost, dialPort), profile.connectTimeoutMs)
        SessionLog.append("TCP connected to ${tcp.remoteSocketAddress}")

        if (profile.useTcpPayload && profile.tcpPayloadHex.isNotBlank()) {
            val bytes = hexToBytes(profile.tcpPayloadHex)
            tcp.getOutputStream().write(bytes)
            tcp.getOutputStream().flush()
            SessionLog.append("TCP payload sent (${bytes.size} bytes)")
        }

        return when (profile.frontMode) {
            FrontMode.DIRECT -> DirectFront.apply(tcp)
            FrontMode.HTTP_INJECT -> HttpInjectFront.apply(tcp, profile)
            FrontMode.TLS_SNI_CLIENTHELLO_ONLY -> TlsSniFront.clientHelloOnly(tcp, profile)
            FrontMode.TLS_SNI_FULL -> TlsSniFront.fullHandshake(tcp, profile)
        }
    }

    /**
     * Realm Host v2 analogue:
     * - ON: resolve realm hostname for logging / handshake identity path.
     * - OFF: always dial serverHost (typical SNI-mismatch: VPS IP + foreign SNI).
     * Dial target remains [TunnelProfile.serverHost] so lab VPS stays reachable.
     */
    private fun resolveDialHost(profile: TunnelProfile): String {
        if (!profile.useRealmHostV2) return profile.serverHost
        val realm = profile.customSni.trim()
        if (realm.isEmpty() || looksLikeIp(realm)) {
            SessionLog.append("RealmV2: SNI empty/IP — dialing serverHost=${profile.serverHost}")
            return profile.serverHost
        }
        return try {
            val ip = InetAddress.getByName(realm).hostAddress ?: profile.serverHost
            SessionLog.append("RealmV2: resolved realm '$realm' -> $ip (dial remains serverHost for lab VPS)")
            profile.serverHost
        } catch (e: Exception) {
            SessionLog.append("RealmV2: resolve failed (${e.message}) — dialing serverHost")
            profile.serverHost
        }
    }

    private fun looksLikeIp(value: String): Boolean =
        value.matches(Regex("""\d{1,3}(\.\d{1,3}){3}""")) || value.contains(':')

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "").replace(":", "")
        require(clean.length % 2 == 0) { "tcpPayloadHex must be even length" }
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
