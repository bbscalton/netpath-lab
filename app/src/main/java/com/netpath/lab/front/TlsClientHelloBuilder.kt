package com.netpath.lab.front

import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/**
 * Builds a plausible TLS 1.2 ClientHello including the server_name (SNI) extension.
 */
object TlsClientHelloBuilder {
    private val random = SecureRandom()

    fun build(serverName: String): ByteArray = buildWithProfile(serverName, chromeLike = false)

    /** Chrome 120–style extension set/order for JA3/JA4 mimic drills (static template, no uTLS dep). */
    fun buildChromeLike(serverName: String): ByteArray = buildWithProfile(serverName, chromeLike = true)

    private fun buildWithProfile(serverName: String, chromeLike: Boolean): ByteArray {
        val hostname = serverName.toByteArray(Charsets.US_ASCII)
        val extensions = ByteArrayOutputStream()

        // server_name extension (0x0000)
        val sniBody = ByteArrayOutputStream()
        sniBody.writeShort(hostname.size + 3)
        sniBody.write(0) // host_name
        sniBody.writeShort(hostname.size)
        sniBody.write(hostname)
        val sniBytes = sniBody.toByteArray()
        extensions.writeShort(0x0000)
        extensions.writeShort(sniBytes.size)
        extensions.write(sniBytes)

        // supported_versions placeholder via renegotiation_info empty + ec_point_formats + supported_groups
        // ec_point_formats
        extensions.writeShort(0x000b)
        extensions.writeShort(2)
        extensions.write(1)
        extensions.write(0) // uncompressed

        // supported_groups
        val groups = if (chromeLike) {
            byteArrayOf(
                0x00, 0x2d, // P-256
                0x00, 0x1d, // x25519
                0x00, 0x1e, // P-384
                0x00, 0x17  // secp256r1 legacy
            )
        } else {
            byteArrayOf(
                0x00, 0x1d, // x25519
                0x00, 0x17, // secp256r1
                0x00, 0x18  // secp384r1
            )
        }
        extensions.writeShort(0x000a)
        extensions.writeShort(groups.size + 2)
        extensions.writeShort(groups.size)
        extensions.write(groups)

        // signature_algorithms
        val sigs = byteArrayOf(
            0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x01, 0x02, 0x01
        )
        extensions.writeShort(0x000d)
        extensions.writeShort(sigs.size + 2)
        extensions.writeShort(sigs.size)
        extensions.write(sigs)

        if (chromeLike) {
            // application_layer_protocol_negotiation — h2, http/1.1 (Chrome order)
            val alpn = byteArrayOf(
                0x00, 0x02, 'h'.code.toByte(), '2'.code.toByte(),
                0x00, 0x08,
                'h'.code.toByte(), 't'.code.toByte(), 't'.code.toByte(), 'p'.code.toByte(),
                '/'.code.toByte(), '1'.code.toByte(), '.'.code.toByte(), '1'.code.toByte()
            )
            extensions.writeShort(0x0010)
            extensions.writeShort(alpn.size + 2)
            extensions.writeShort(alpn.size)
            extensions.write(alpn)

            // supported_versions TLS 1.3 + 1.2
            val versions = byteArrayOf(0x02, 0x03, 0x04, 0x03, 0x03)
            extensions.writeShort(0x002b)
            extensions.writeShort(versions.size + 1)
            extensions.write(versions.size)
            extensions.write(versions)

            // psk_key_exchange_modes
            extensions.writeShort(0x002d)
            extensions.writeShort(2)
            extensions.write(1)
            extensions.write(1) // psk_dhe_ke

            // key_share x25519 placeholder
            val keyShare = byteArrayOf(
                0x00, 0x1d, 0x00, 0x20
            ) + ByteArray(32).also { random.nextBytes(it) }
            extensions.writeShort(0x0033)
            extensions.writeShort(keyShare.size + 2)
            extensions.writeShort(keyShare.size)
            extensions.write(keyShare)

            // compress_certificate (brotli) — seen on modern Chrome
            extensions.writeShort(0x001b)
            extensions.writeShort(3)
            extensions.write(2)
            extensions.write(0x01) // brotli
            extensions.write(0x02) // zlib
        }

        val extBytes = extensions.toByteArray()

        val cipherSuites = if (chromeLike) {
            byteArrayOf(
                0x13, 0x01, // TLS_AES_128_GCM_SHA256
                0x13, 0x02, // TLS_AES_256_GCM_SHA384
                0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
                0xc0.toByte(), 0x2b, // ECDHE_ECDSA_AES_128_GCM
                0xc0.toByte(), 0x2f, // ECDHE_RSA_AES_128_GCM
                0xc0.toByte(), 0x2c, // ECDHE_ECDSA_AES_256_GCM
                0xc0.toByte(), 0x30, // ECDHE_RSA_AES_256_GCM
                0x00, 0x9e.toByte(), // DHE_RSA_AES_128_GCM
                0x00, 0x33, // DHE_RSA_AES_128_CBC_SHA
                0x00, 0x3d  // TLS_RSA_AES_128_CBC_SHA (legacy Chrome list tail)
            )
        } else {
            byteArrayOf(
                0x13, 0x01, // TLS_AES_128_GCM_SHA256
                0x13, 0x02, // TLS_AES_256_GCM_SHA384
                0xc0.toByte(), 0x2b, // ECDHE_ECDSA_AES_128_GCM
                0xc0.toByte(), 0x2f, // ECDHE_RSA_AES_128_GCM
                0xc0.toByte(), 0x2c, // ECDHE_ECDSA_AES_256_GCM
                0xc0.toByte(), 0x30, // ECDHE_RSA_AES_256_GCM
                0x00, 0x9e.toByte(), // DHE_RSA_AES_128_GCM
                0x00, 0x33  // DHE_RSA_AES_128_CBC_SHA
            )
        }

        val sessionId = ByteArray(32).also { random.nextBytes(it) }
        val clientRandom = ByteArray(32).also { random.nextBytes(it) }

        val body = ByteArrayOutputStream()
        body.writeShort(0x0303) // TLS 1.2
        body.write(clientRandom)
        body.write(sessionId.size)
        body.write(sessionId)
        body.writeShort(cipherSuites.size)
        body.write(cipherSuites)
        body.write(1) // compression methods length
        body.write(0) // null
        body.writeShort(extBytes.size)
        body.write(extBytes)
        val bodyBytes = body.toByteArray()

        val handshake = ByteArrayOutputStream()
        handshake.write(0x01) // ClientHello
        handshake.write((bodyBytes.size shr 16) and 0xff)
        handshake.write((bodyBytes.size shr 8) and 0xff)
        handshake.write(bodyBytes.size and 0xff)
        handshake.write(bodyBytes)
        val hs = handshake.toByteArray()

        val record = ByteArrayOutputStream()
        record.write(0x16) // handshake
        record.writeShort(0x0301) // record version TLS 1.0 for compat
        record.writeShort(hs.size)
        record.write(hs)
        return record.toByteArray()
    }

    private fun ByteArrayOutputStream.writeShort(value: Int) {
        write((value shr 8) and 0xff)
        write(value and 0xff)
    }
}
