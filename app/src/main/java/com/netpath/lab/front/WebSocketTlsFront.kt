package com.netpath.lab.front

import android.util.Base64
import com.netpath.lab.config.TunnelProfile
import com.netpath.lab.log.SessionLog
import java.net.Socket
import java.security.SecureRandom

/**
 * WebSocket HTTP upgrade preamble before TLS ClientHello — models VMess/Trojan WS+TLS transport.
 * Lab path: TCP → WS upgrade text → ClientHello SNI → SSH on same socket.
 */
object WebSocketTlsFront {
    private val random = SecureRandom()

    fun apply(socket: Socket, profile: TunnelProfile): Socket {
        val host = TlsSniFront.sniName(profile)
        val wsKey = Base64.encodeToString(ByteArray(16).also { random.nextBytes(it) }, Base64.NO_WRAP)
        val upgrade = buildString {
            append("GET / HTTP/1.1\r\n")
            append("Host: $host\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: $wsKey\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            append("User-Agent: Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile\r\n")
            append("\r\n")
        }
        val out = socket.getOutputStream()
        out.write(upgrade.toByteArray(Charsets.US_ASCII))
        out.flush()
        SessionLog.append("WebSocket upgrade sent Host=$host (${upgrade.length} chars)")
        return TlsSniFront.clientHelloOnly(socket, profile)
    }
}
