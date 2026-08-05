package com.netpath.lab.front

import com.netpath.lab.log.SessionLog
import java.net.Socket

/** Direct TCP front — SSH bytes follow immediately after connect (+ optional TCP payload). */
object DirectFront {
    fun apply(socket: Socket): Socket {
        SessionLog.append("Direct front: no inject / no TLS wrapper")
        return socket
    }
}
