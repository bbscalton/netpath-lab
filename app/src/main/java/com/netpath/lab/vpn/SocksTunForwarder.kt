package com.netpath.lab.vpn

import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

import com.netpath.lab.log.SessionLog

/**
 * Minimal userspace IPv4 TCP (+ DNS UDP) forwarder: TUN packets <-> local SOCKS5.
 * Sufficient for lab traffic (browsing/API) while studying front-door bypass techniques.
 */
class SocksTunForwarder(
    private val tunIn: InputStream,
    private val tunOut: OutputStream,
    private val socksHost: String,
    private val socksPort: Int,
    private val protect: (Socket) -> Unit
) : Closeable {
    private val running = AtomicBoolean(true)
    private val pool = Executors.newCachedThreadPool()
    private val connections = ConcurrentHashMap<TcpKey, TcpBridge>()
    private val ipId = AtomicInteger(Random.nextInt(0x1000, 0x7fff))

    fun run() {
        val packet = ByteArray(32767)
        while (running.get()) {
            val n = try {
                tunIn.read(packet)
            } catch (_: Exception) {
                break
            }
            if (n <= 0) break
            try {
                handlePacket(packet, n)
            } catch (e: Exception) {
                SessionLog.append("TUN packet error: ${e.message}")
            }
        }
    }

    private fun handlePacket(buf: ByteArray, len: Int) {
        if (len < 20) return
        val version = (buf[0].toInt() shr 4) and 0x0f
        if (version != 4) return
        val ihl = (buf[0].toInt() and 0x0f) * 4
        if (len < ihl) return
        val protocol = buf[9].toInt() and 0xff
        val src = ipv4(buf, 12)
        val dst = ipv4(buf, 16)

        when (protocol) {
            17 -> handleUdp(buf, len, ihl, src, dst) // DNS
            6 -> handleTcp(buf, len, ihl, src, dst)
        }
    }

    private fun handleUdp(buf: ByteArray, len: Int, ihl: Int, src: String, dst: String) {
        if (len < ihl + 8) return
        val srcPort = u16(buf, ihl)
        val dstPort = u16(buf, ihl + 2)
        if (dstPort != 53) return
        val dnsPayload = buf.copyOfRange(ihl + 8, len)
        pool.execute {
            try {
                val answer = resolveDns(dnsPayload) ?: return@execute
                val packet = buildUdpPacket(
                    srcIp = dst,
                    dstIp = src,
                    srcPort = 53,
                    dstPort = srcPort,
                    payload = answer
                )
                synchronized(tunOut) {
                    tunOut.write(packet)
                    tunOut.flush()
                }
            } catch (e: Exception) {
                SessionLog.append("DNS handle error: ${e.message}")
            }
        }
    }

    private fun resolveDns(query: ByteArray): ByteArray? {
        if (query.size < 12) return null
        // Parse first question name
        var idx = 12
        val name = StringBuilder()
        while (idx < query.size) {
            val lab = query[idx].toInt() and 0xff
            idx++
            if (lab == 0) break
            if (lab and 0xc0 == 0xc0) return null
            if (name.isNotEmpty()) name.append('.')
            if (idx + lab > query.size) return null
            name.append(String(query, idx, lab, Charsets.US_ASCII))
            idx += lab
        }
        if (idx + 4 > query.size) return null
        val qtype = u16(query, idx)
        // Only A records
        if (qtype != 1) return buildDnsNxOrEmpty(query)

        val host = name.toString()
        val addrs = try {
            InetAddress.getAllByName(host)
        } catch (_: Exception) {
            return buildDnsNxOrEmpty(query)
        }
        val a = addrs.firstOrNull { it.address.size == 4 } ?: return buildDnsNxOrEmpty(query)
        return buildDnsAResponse(query, a.address)
    }

    private fun buildDnsNxOrEmpty(query: ByteArray): ByteArray {
        val out = query.copyOf(query.size)
        // flags: response + recursive
        out[2] = (0x81).toByte()
        out[3] = 0x80.toByte()
        // ancount = 0
        out[6] = 0
        out[7] = 0
        return out
    }

    private fun buildDnsAResponse(query: ByteArray, ip: ByteArray): ByteArray {
        val out = ByteArrayOutputGrow(query.size + 16)
        out.write(query)
        // fix header flags / counts on the copy
        val bytes = out.toByteArray()
        bytes[2] = 0x81.toByte()
        bytes[3] = 0x80.toByte()
        bytes[6] = 0
        bytes[7] = 1 // ancount
        // answer: pointer to name at 0x0c, type A, class IN, ttl, rdlength 4, rdata
        val answer = byteArrayOf(
            0xc0.toByte(), 0x0c,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x3c,
            0x00, 0x04,
            ip[0], ip[1], ip[2], ip[3]
        )
        return bytes + answer
    }

    private fun handleTcp(buf: ByteArray, len: Int, ihl: Int, src: String, dst: String) {
        if (len < ihl + 20) return
        val srcPort = u16(buf, ihl)
        val dstPort = u16(buf, ihl + 2)
        val seq = u32(buf, ihl + 4)
        val ack = u32(buf, ihl + 8)
        val dataOff = ((buf[ihl + 12].toInt() shr 4) and 0x0f) * 4
        val flags = buf[ihl + 13].toInt() and 0xff
        val syn = flags and 0x02 != 0
        val ackFlag = flags and 0x10 != 0
        val fin = flags and 0x01 != 0
        val rst = flags and 0x04 != 0
        val payloadStart = ihl + dataOff
        val payload = if (payloadStart < len) buf.copyOfRange(payloadStart, len) else ByteArray(0)

        val key = TcpKey(src, srcPort, dst, dstPort)

        if (rst) {
            connections.remove(key)?.close()
            return
        }

        if (syn && !ackFlag) {
            val bridge = TcpBridge(key, seq)
            connections[key] = bridge
            pool.execute { bridge.connectAndRelay() }
            // SYN-ACK
            writeTcp(
                srcIp = dst,
                dstIp = src,
                srcPort = dstPort,
                dstPort = srcPort,
                seq = bridge.serverSeq,
                ack = seq + 1,
                flags = 0x12, // SYN+ACK
                payload = ByteArray(0)
            )
            bridge.serverSeq++
            bridge.clientNextSeq = seq + 1
            return
        }

        val bridge = connections[key] ?: return
        if (ackFlag) {
            bridge.clientNextSeq = maxOf(bridge.clientNextSeq, seq + payload.size.toLong() + if (fin) 1 else 0)
        }
        if (payload.isNotEmpty()) {
            bridge.fromTun(payload)
            // ACK payload
            writeTcp(
                srcIp = dst,
                dstIp = src,
                srcPort = dstPort,
                dstPort = srcPort,
                seq = bridge.serverSeq,
                ack = seq + payload.size,
                flags = 0x10,
                payload = ByteArray(0)
            )
        }
        if (fin) {
            writeTcp(
                srcIp = dst,
                dstIp = src,
                srcPort = dstPort,
                dstPort = srcPort,
                seq = bridge.serverSeq,
                ack = seq + 1,
                flags = 0x11, // FIN+ACK
                payload = ByteArray(0)
            )
            connections.remove(key)
            bridge.close()
        }
    }

    private inner class TcpBridge(
        val key: TcpKey,
        initialClientSeq: Long
    ) {
        var serverSeq: Long = Random.nextInt().toLong() and 0xffffffffL
        var clientNextSeq: Long = initialClientSeq + 1
        private var sock: Socket? = null
        private var out: OutputStream? = null
        private val open = AtomicBoolean(false)
        private val pending = ArrayList<ByteArray>()

        fun connectAndRelay() {
            try {
                val s = Socket()
                protect(s)
                s.tcpNoDelay = true
                s.connect(InetSocketAddress(socksHost, socksPort), 10_000)
                socksConnect(s, key.dstIp, key.dstPort)
                sock = s
                out = s.getOutputStream()
                open.set(true)
                synchronized(pending) {
                    pending.forEach { data -> out?.write(data) }
                    pending.clear()
                    out?.flush()
                }
                val input = s.getInputStream()
                val buf = ByteArray(16 * 1024)
                while (running.get()) {
                    val n = input.read(buf)
                    if (n < 0) break
                    val chunk = buf.copyOf(n)
                    writeTcp(
                        srcIp = key.dstIp,
                        dstIp = key.srcIp,
                        srcPort = key.dstPort,
                        dstPort = key.srcPort,
                        seq = serverSeq,
                        ack = clientNextSeq,
                        flags = 0x18, // PSH+ACK
                        payload = chunk
                    )
                    serverSeq = (serverSeq + n) and 0xffffffffL
                }
            } catch (e: Exception) {
                SessionLog.append("TCP bridge ${key.dstIp}:${key.dstPort} error: ${e.message}")
            } finally {
                close()
                connections.remove(key)
            }
        }

        fun fromTun(data: ByteArray) {
            if (open.get()) {
                try {
                    out?.write(data)
                    out?.flush()
                } catch (_: Exception) {
                }
            } else {
                synchronized(pending) { pending.add(data) }
            }
        }

        fun close() {
            try {
                sock?.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun socksConnect(s: Socket, host: String, port: Int) {
        val inp = s.getInputStream()
        val o = s.getOutputStream()
        o.write(byteArrayOf(0x05, 0x01, 0x00))
        o.flush()
        val greet = ByteArray(2)
        readFully(inp, greet)
        if (greet[0].toInt() != 0x05 || greet[1].toInt() != 0x00) error("SOCKS auth rejected")

        val hostBytes = host.toByteArray(Charsets.US_ASCII)
        val req = ByteArrayOutputGrow(7 + hostBytes.size)
        req.write(0x05)
        req.write(0x01)
        req.write(0x00)
        req.write(0x03)
        req.write(hostBytes.size)
        req.write(hostBytes)
        req.write((port shr 8) and 0xff)
        req.write(port and 0xff)
        o.write(req.toByteArray())
        o.flush()

        val hdr = ByteArray(4)
        readFully(inp, hdr)
        if (hdr[1].toInt() != 0x00) error("SOCKS connect failed code=${hdr[1]}")
        when (hdr[3].toInt() and 0xff) {
            0x01 -> inp.skip(4 + 2)
            0x03 -> {
                val l = inp.read()
                inp.skip(l.toLong() + 2)
            }
            0x04 -> inp.skip(16 + 2)
        }
    }

    private fun writeTcp(
        srcIp: String,
        dstIp: String,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray
    ) {
        val tcpLen = 20 + payload.size
        val total = 20 + tcpLen
        val pkt = ByteArray(total)
        // IP header
        pkt[0] = 0x45
        pkt[1] = 0
        pkt[2] = ((total shr 8) and 0xff).toByte()
        pkt[3] = (total and 0xff).toByte()
        val id = ipId.getAndIncrement() and 0xffff
        pkt[4] = ((id shr 8) and 0xff).toByte()
        pkt[5] = (id and 0xff).toByte()
        pkt[6] = 0x40.toByte() // DF
        pkt[8] = 64
        pkt[9] = 6
        writeIpv4(pkt, 12, srcIp)
        writeIpv4(pkt, 16, dstIp)
        val ipCsum = checksum(pkt, 0, 20)
        pkt[10] = ((ipCsum shr 8) and 0xff).toByte()
        pkt[11] = (ipCsum and 0xff).toByte()

        // TCP header
        val off = 20
        pkt[off] = ((srcPort shr 8) and 0xff).toByte()
        pkt[off + 1] = (srcPort and 0xff).toByte()
        pkt[off + 2] = ((dstPort shr 8) and 0xff).toByte()
        pkt[off + 3] = (dstPort and 0xff).toByte()
        writeU32(pkt, off + 4, seq)
        writeU32(pkt, off + 8, ack)
        pkt[off + 12] = 0x50.toByte() // data offset 5
        pkt[off + 13] = flags.toByte()
        pkt[off + 14] = 0xff.toByte()
        pkt[off + 15] = 0xff.toByte()
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, pkt, off + 20, payload.size)
        }
        val tcpCsum = tcpChecksum(pkt, off, tcpLen, srcIp, dstIp)
        pkt[off + 16] = ((tcpCsum shr 8) and 0xff).toByte()
        pkt[off + 17] = (tcpCsum and 0xff).toByte()

        synchronized(tunOut) {
            tunOut.write(pkt)
            tunOut.flush()
        }
    }

    private fun buildUdpPacket(
        srcIp: String,
        dstIp: String,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLen = 8 + payload.size
        val total = 20 + udpLen
        val pkt = ByteArray(total)
        pkt[0] = 0x45
        pkt[2] = ((total shr 8) and 0xff).toByte()
        pkt[3] = (total and 0xff).toByte()
        val id = ipId.getAndIncrement() and 0xffff
        pkt[4] = ((id shr 8) and 0xff).toByte()
        pkt[5] = (id and 0xff).toByte()
        pkt[8] = 64
        pkt[9] = 17
        writeIpv4(pkt, 12, srcIp)
        writeIpv4(pkt, 16, dstIp)
        val ipCsum = checksum(pkt, 0, 20)
        pkt[10] = ((ipCsum shr 8) and 0xff).toByte()
        pkt[11] = (ipCsum and 0xff).toByte()
        val off = 20
        pkt[off] = ((srcPort shr 8) and 0xff).toByte()
        pkt[off + 1] = (srcPort and 0xff).toByte()
        pkt[off + 2] = ((dstPort shr 8) and 0xff).toByte()
        pkt[off + 3] = (dstPort and 0xff).toByte()
        pkt[off + 4] = ((udpLen shr 8) and 0xff).toByte()
        pkt[off + 5] = (udpLen and 0xff).toByte()
        System.arraycopy(payload, 0, pkt, off + 8, payload.size)
        return pkt
    }

    private fun tcpChecksum(pkt: ByteArray, tcpOff: Int, tcpLen: Int, srcIp: String, dstIp: String): Int {
        val pseudo = ByteArray(12 + tcpLen)
        writeIpv4(pseudo, 0, srcIp)
        writeIpv4(pseudo, 4, dstIp)
        pseudo[8] = 0
        pseudo[9] = 6
        pseudo[10] = ((tcpLen shr 8) and 0xff).toByte()
        pseudo[11] = (tcpLen and 0xff).toByte()
        System.arraycopy(pkt, tcpOff, pseudo, 12, tcpLen)
        // zero checksum field already 0
        return checksum(pseudo, 0, pseudo.size)
    }

    private fun checksum(buf: ByteArray, off: Int, len: Int): Int {
        var sum = 0
        var i = off
        val end = off + len
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xff) shl 8) or (buf[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (buf[i].toInt() and 0xff) shl 8
        while (sum ushr 16 != 0) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv() and 0xffff
    }

    private fun ipv4(buf: ByteArray, off: Int): String =
        "${buf[off].toInt() and 0xff}.${buf[off + 1].toInt() and 0xff}." +
            "${buf[off + 2].toInt() and 0xff}.${buf[off + 3].toInt() and 0xff}"

    private fun writeIpv4(buf: ByteArray, off: Int, ip: String) {
        val p = ip.split('.')
        for (i in 0 until 4) buf[off + i] = p[i].toInt().toByte()
    }

    private fun writeU32(buf: ByteArray, off: Int, v: Long) {
        buf[off] = ((v shr 24) and 0xff).toByte()
        buf[off + 1] = ((v shr 16) and 0xff).toByte()
        buf[off + 2] = ((v shr 8) and 0xff).toByte()
        buf[off + 3] = (v and 0xff).toByte()
    }

    private fun u16(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xff) shl 8) or (buf[off + 1].toInt() and 0xff)

    private fun u32(buf: ByteArray, off: Int): Long =
        ((buf[off].toInt() and 0xff).toLong() shl 24) or
            ((buf[off + 1].toInt() and 0xff).toLong() shl 16) or
            ((buf[off + 2].toInt() and 0xff).toLong() shl 8) or
            (buf[off + 3].toInt() and 0xff).toLong()

    private fun readFully(input: InputStream, buf: ByteArray) {
        var o = 0
        while (o < buf.size) {
            val n = input.read(buf, o, buf.size - o)
            if (n < 0) error("EOF")
            o += n
        }
    }

    override fun close() {
        running.set(false)
        connections.values.forEach { it.close() }
        connections.clear()
        pool.shutdownNow()
        try {
            tunIn.close()
        } catch (_: Exception) {
        }
        try {
            tunOut.close()
        } catch (_: Exception) {
        }
    }

    data class TcpKey(val srcIp: String, val srcPort: Int, val dstIp: String, val dstPort: Int)

    private class ByteArrayOutputGrow(cap: Int = 32) {
        private var buf = ByteArray(cap)
        private var size = 0
        fun write(b: Int) {
            ensure(1)
            buf[size++] = b.toByte()
        }
        fun write(bytes: ByteArray) {
            ensure(bytes.size)
            System.arraycopy(bytes, 0, buf, size, bytes.size)
            size += bytes.size
        }
        fun toByteArray() = buf.copyOf(size)
        private fun ensure(n: Int) {
            if (size + n <= buf.size) return
            buf = buf.copyOf(maxOf(buf.size * 2, size + n))
        }
    }
}
