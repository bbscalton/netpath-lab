package com.netpath.lab.front

import com.netpath.lab.config.TunnelProfile
import com.netpath.lab.log.SessionLog
import java.net.Socket

/**
 * HTTP/2 connection preface before TLS ClientHello — models h2 camouflage used with CDN fronts.
 */
object Http2PreambleFront {
    private val H2_PREFACE = "PRI * HTTP/2.0\r\n\r\n\r\n".toByteArray(Charsets.US_ASCII)

    fun apply(socket: Socket, profile: TunnelProfile): Socket {
        val out = socket.getOutputStream()
        out.write(H2_PREFACE)
        out.flush()
        SessionLog.append("HTTP/2 connection preface sent (PRI * HTTP/2.0) before ClientHello")
        return TlsSniFront.clientHelloOnly(socket, profile)
    }
}
