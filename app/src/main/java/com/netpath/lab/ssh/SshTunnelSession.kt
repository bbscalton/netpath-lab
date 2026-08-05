package com.netpath.lab.ssh

import com.netpath.lab.config.TunnelProfile
import com.netpath.lab.front.FrontDoorFactory
import com.netpath.lab.log.SessionLog
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.connection.channel.direct.DirectConnection
import net.schmizz.sshj.transport.verification.PromiscuousVerifier
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.SocketFactory

/**
 * Opens SSH over a fronted socket (via custom SocketFactory) and exposes local SOCKS5
 * using SSH direct-tcpip channels ([DirectConnection]).
 */
class SshTunnelSession(
    private val profile: TunnelProfile,
    private val protectSocket: (Socket) -> Unit
) : Closeable {
    private val ssh = SSHClient()
    private var socksServer: ServerSocket? = null
    private val executor = Executors.newCachedThreadPool()
    private val running = AtomicBoolean(false)

    var localSocksPort: Int = 0
        private set

    fun start() {
        SessionLog.append("Opening fronted path to SSH…")
        ssh.addHostKeyVerifier(PromiscuousVerifier())
        ssh.connectTimeout = profile.connectTimeoutMs
        ssh.socketFactory = FrontedSocketFactory(profile, protectSocket)
        ssh.connect(profile.serverHost, profile.serverPort)
        SessionLog.append("SSH transport connected, authenticating as ${profile.username}")

        when {
            profile.privateKeyPem.isNotBlank() -> {
                val kp = ssh.loadKeys(profile.privateKeyPem, null, null)
                ssh.authPublickey(profile.username, kp)
            }
            profile.password.isNotBlank() -> ssh.authPassword(profile.username, profile.password)
            else -> error("Provide password or private key PEM for lab SSH server")
        }
        SessionLog.append("SSH authentication OK")

        socksServer = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        localSocksPort = socksServer!!.localPort
        running.set(true)
        executor.execute { socksAcceptLoop() }
        SessionLog.append("Local SOCKS5 listening on 127.0.0.1:$localSocksPort")
    }

    private fun socksAcceptLoop() {
        val server = socksServer ?: return
        while (running.get()) {
            try {
                val client = server.accept()
                executor.execute { handleSocksClient(client) }
            } catch (_: Exception) {
                if (!running.get()) break
            }
        }
    }

    private fun handleSocksClient(client: Socket) {
        var channel: DirectConnection? = null
        try {
            client.tcpNoDelay = true
            val input = client.getInputStream()
            val output = client.getOutputStream()

            if (input.read() != 0x05) {
                client.close()
                return
            }
            val nMethods = input.read()
            if (nMethods > 0) input.skip(nMethods.toLong())
            output.write(byteArrayOf(0x05, 0x00))
            output.flush()

            val header = ByteArray(4)
            readFully(input, header)
            if (header[0].toInt() != 0x05 || header[1].toInt() != 0x01) {
                output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                client.close()
                return
            }

            val destHost: String = when (header[3].toInt() and 0xff) {
                0x01 -> {
                    val ip = ByteArray(4)
                    readFully(input, ip)
                    ip.joinToString(".") { (it.toInt() and 0xff).toString() }
                }
                0x03 -> {
                    val len = input.read()
                    val name = ByteArray(len)
                    readFully(input, name)
                    String(name, Charsets.US_ASCII)
                }
                else -> {
                    output.write(byteArrayOf(0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    client.close()
                    return
                }
            }
            val destPort = (input.read() shl 8) or input.read()

            channel = ssh.newDirectConnection(destHost, destPort)
            channel.open()

            output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            output.flush()

            val c2s = executor.submit { pipe(input, channel.outputStream) }
            val s2c = executor.submit { pipe(channel.inputStream, output) }
            c2s.get()
            s2c.get()
        } catch (e: Exception) {
            SessionLog.append("SOCKS error: ${e.message}")
        } finally {
            try {
                channel?.close()
            } catch (_: Exception) {
            }
            try {
                client.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun pipe(input: InputStream, output: OutputStream) {
        val buf = ByteArray(16 * 1024)
        try {
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                output.write(buf, 0, n)
                output.flush()
            }
        } catch (_: Exception) {
        }
        try {
            output.close()
        } catch (_: Exception) {
        }
    }

    private fun readFully(input: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) error("Unexpected EOF in SOCKS handshake")
            off += n
        }
    }

    override fun close() {
        running.set(false)
        try {
            socksServer?.close()
        } catch (_: Exception) {
        }
        try {
            if (ssh.isConnected) ssh.disconnect()
        } catch (_: Exception) {
        }
        executor.shutdownNow()
        SessionLog.append("SSH session closed")
    }
}

private class FrontedSocketFactory(
    private val profile: TunnelProfile,
    private val protectSocket: (Socket) -> Unit
) : SocketFactory() {
    private val front = FrontDoorFactory(protectSocket)

    override fun createSocket(): Socket = error("FrontedSocketFactory requires host/port")

    override fun createSocket(host: String, port: Int): Socket =
        front.open(profile.copy(serverHost = host, serverPort = port))

    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
        createSocket(host, port)

    override fun createSocket(host: InetAddress, port: Int): Socket =
        createSocket(host.hostAddress ?: host.hostName, port)

    override fun createSocket(
        address: InetAddress,
        port: Int,
        localAddress: InetAddress,
        localPort: Int
    ): Socket = createSocket(address, port)
}
