package com.netpath.lab.front

import com.netpath.lab.config.TunnelProfile
import com.netpath.lab.log.SessionLog
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * TLS / Custom SNI fronts used by consumer tunnel apps.
 *
 * - [clientHelloOnly]: DPI often only inspects ClientHello; SSH continues on same TCP.
 * - [fullHandshake]: completes TLS (lab stunnel/sslh); trusts operator certs.
 */
object TlsSniFront {
    fun sniName(profile: TunnelProfile): String {
        val configured = TunnelProfile.resolveSni(profile)
        if (profile.preserveSni && configured.isNotEmpty()) return configured
        if (configured.isNotEmpty()) return configured
        return profile.serverHost
    }

    fun clientHelloOnly(socket: Socket, profile: TunnelProfile): Socket {
        val name = sniName(profile)
        val hello = TlsClientHelloBuilder.build(name)
        val out = socket.getOutputStream()
        out.write(hello)
        out.flush()
        SessionLog.append(
            "TLS ClientHello-only SNI=$name preserve=${profile.preserveSni} " +
                "wwwToggle=${profile.wwwSniToggle} (SSH follows on same TCP)"
        )
        return socket
    }

    fun chromeJa3Mimic(socket: Socket, profile: TunnelProfile): Socket {
        val name = sniName(profile)
        val hello = TlsClientHelloBuilder.buildChromeLike(name)
        val out = socket.getOutputStream()
        out.write(hello)
        out.flush()
        SessionLog.append(
            "TLS Chrome-like ClientHello (JA3 mimic) SNI=$name — compare JA3/JA4 in SOC capture"
        )
        return socket
    }

    fun fullHandshake(socket: Socket, profile: TunnelProfile): SSLSocket {
        val name = sniName(profile)
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, trustAll, SecureRandom())
        val ssl = ctx.socketFactory.createSocket(socket, name, socket.port, true) as SSLSocket
        val params = ssl.sslParameters
        params.serverNames = listOf(SNIHostName(name))
        ssl.sslParameters = params
        ssl.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")
        SessionLog.append("Starting full TLS handshake SNI=$name")
        ssl.startHandshake()
        SessionLog.append("Full TLS handshake complete")
        return ssl
    }
}
