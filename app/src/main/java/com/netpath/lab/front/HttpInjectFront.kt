package com.netpath.lab.front

import com.netpath.lab.config.TunnelProfile
import com.netpath.lab.log.SessionLog
import java.net.Socket

/** HTTP inject front — writes crafted HTTP text before SSH on the same TCP session. */
object HttpInjectFront {
    fun apply(socket: Socket, profile: TunnelProfile): Socket {
        val payload = profile.httpPayload.ifBlank { TunnelProfile.DEFAULT_HTTP_PAYLOAD }
        val out = socket.getOutputStream()
        out.write(payload.toByteArray(Charsets.US_ASCII))
        out.flush()
        SessionLog.append("HTTP inject sent (${payload.length} chars)")
        return socket
    }
}
