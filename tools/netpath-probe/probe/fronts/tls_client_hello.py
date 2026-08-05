"""TLS ClientHello builder — mirrors Android TlsClientHelloBuilder.kt."""

from __future__ import annotations

import os
import struct
from io import BytesIO


def _write_short(stream: BytesIO, value: int) -> None:
    stream.write(struct.pack(">H", value & 0xFFFF))


def build(server_name: str, *, chrome_like: bool = False) -> bytes:
    hostname = server_name.encode("ascii")
    extensions = BytesIO()

    # server_name (0x0000)
    sni_body = BytesIO()
    _write_short(sni_body, len(hostname) + 3)
    sni_body.write(b"\x00")
    _write_short(sni_body, len(hostname))
    sni_body.write(hostname)
    sni_bytes = sni_body.getvalue()
    _write_short(extensions, 0x0000)
    _write_short(extensions, len(sni_bytes))
    extensions.write(sni_bytes)

    # ec_point_formats (0x000b)
    _write_short(extensions, 0x000B)
    _write_short(extensions, 2)
    extensions.write(b"\x01\x00")

    # supported_groups (0x000a)
    if chrome_like:
        groups = bytes([0x00, 0x2D, 0x00, 0x1D, 0x00, 0x1E, 0x00, 0x17])
    else:
        groups = bytes([0x00, 0x1D, 0x00, 0x17, 0x00, 0x18])
    _write_short(extensions, 0x000A)
    _write_short(extensions, len(groups) + 2)
    _write_short(extensions, len(groups))
    extensions.write(groups)

    # signature_algorithms (0x000d)
    sigs = bytes([0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x01, 0x02, 0x01])
    _write_short(extensions, 0x000D)
    _write_short(extensions, len(sigs) + 2)
    _write_short(extensions, len(sigs))
    extensions.write(sigs)

    if chrome_like:
        alpn = (
            b"\x00\x02h2"
            b"\x00\x08"
            b"http/1.1"
        )
        _write_short(extensions, 0x0010)
        _write_short(extensions, len(alpn) + 2)
        _write_short(extensions, len(alpn))
        extensions.write(alpn)

        versions = bytes([0x02, 0x03, 0x04, 0x03, 0x03])
        _write_short(extensions, 0x002B)
        _write_short(extensions, len(versions) + 1)
        extensions.write(bytes([len(versions)]))
        extensions.write(versions)

        _write_short(extensions, 0x002D)
        _write_short(extensions, 2)
        extensions.write(b"\x01\x01")

        key_share = bytes([0x00, 0x1D, 0x00, 0x20]) + os.urandom(32)
        _write_short(extensions, 0x0033)
        _write_short(extensions, len(key_share) + 2)
        _write_short(extensions, len(key_share))
        extensions.write(key_share)

        _write_short(extensions, 0x001B)
        _write_short(extensions, 3)
        extensions.write(b"\x02\x01\x02")

    ext_bytes = extensions.getvalue()

    if chrome_like:
        cipher_suites = bytes([
            0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
            0xC0, 0x2B, 0xC0, 0x2F, 0xC0, 0x2C, 0xC0, 0x30,
            0x00, 0x9E, 0x00, 0x33, 0x00, 0x3D,
        ])
    else:
        cipher_suites = bytes([
            0x13, 0x01, 0x13, 0x02,
            0xC0, 0x2B, 0xC0, 0x2F, 0xC0, 0x2C, 0xC0, 0x30,
            0x00, 0x9E, 0x00, 0x33,
        ])

    session_id = os.urandom(32)
    client_random = os.urandom(32)

    body = BytesIO()
    _write_short(body, 0x0303)
    body.write(client_random)
    body.write(bytes([len(session_id)]))
    body.write(session_id)
    _write_short(body, len(cipher_suites))
    body.write(cipher_suites)
    body.write(b"\x01\x00")
    _write_short(body, len(ext_bytes))
    body.write(ext_bytes)
    body_bytes = body.getvalue()

    handshake = BytesIO()
    handshake.write(b"\x01")
    handshake.write(struct.pack(">I", len(body_bytes))[1:])
    handshake.write(body_bytes)
    hs = handshake.getvalue()

    record = BytesIO()
    record.write(b"\x16")
    _write_short(record, 0x0301)
    _write_short(record, len(hs))
    record.write(hs)
    return record.getvalue()


def build_chrome_like(server_name: str) -> bytes:
    return build(server_name, chrome_like=True)
