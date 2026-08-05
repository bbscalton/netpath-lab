package com.netpath.lab.front

import com.netpath.lab.config.TunnelProfile
import com.netpath.lab.log.SessionLog
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Trojan-protocol camouflage drill: fake HTTP GET with password-shaped hex token before SSH.
 * Does not implement Trojan routing — only the visible wire pattern for DPI/billing labs.
 */
object TrojanCamouflageFront {
    private val random = SecureRandom()

    fun apply(socket: Socket, profile: TunnelProfile): Socket {
        val host = TlsSniFront.sniName(profile)
        val token = ByteArray(56).also { random.nextBytes(it) }
        val hex = token.joinToString("") { "%02x".format(it) }
        val sha56 = MessageDigest.getInstance("SHA-224").digest(hex.toByteArray(Charsets.US_ASCII))
        val passwordHash = sha56.joinToString("") { "%02x".format(it) }
        val request = buildString {
            append(passwordHash)
            append("\r\n")
            append("GET / HTTP/1.1\r\n")
            append("Host: $host\r\n")
            append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n")
            append("Accept: text/html,application/xhtml+xml\r\n")
            append("Connection: keep-alive\r\n")
            append("\r\n")
        }
        val out = socket.getOutputStream()
        out.write(request.toByteArray(Charsets.US_ASCII))
        out.flush()
        SessionLog.append("Trojan-style HTTP camouflage sent Host=$host (lab token only, SSH follows)")
        return socket
    }
}
