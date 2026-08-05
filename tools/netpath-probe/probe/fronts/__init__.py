"""Front-door bytes — mirrors Android com.netpath.lab.front package."""

from __future__ import annotations

import base64
import hashlib
import os
import random
import socket
import ssl
from typing import TYPE_CHECKING

from probe.fronts.tls_client_hello import build, build_chrome_like

if TYPE_CHECKING:
    from probe.config_loader import TunnelConfig

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\n\r\n"


def sni_name(cfg: TunnelConfig) -> str:
    configured = cfg.resolve_sni()
    if cfg.preserve_sni and configured:
        return configured
    if configured:
        return configured
    return cfg.server_host


def hex_to_bytes(hex_str: str) -> bytes:
    clean = hex_str.replace(" ", "").replace(":", "")
    if len(clean) % 2:
        raise ValueError("tcpPayloadHex must be even length")
    return bytes(int(clean[i : i + 2], 16) for i in range(0, len(clean), 2))


def apply_tcp_extras(sock: socket.socket, cfg: TunnelConfig) -> None:
    if cfg.use_tcp_payload and cfg.tcp_payload_hex.strip():
        data = hex_to_bytes(cfg.tcp_payload_hex)
        sock.sendall(data)
    if cfg.use_front_padding and cfg.front_padding_max_bytes > 0:
        pad_len = random.randint(1, min(cfg.front_padding_max_bytes, 512))
        sock.sendall(bytes(pad_len))


def apply_direct(sock: socket.socket, _cfg: TunnelConfig) -> socket.socket:
    return sock


def apply_http_inject(sock: socket.socket, cfg: TunnelConfig) -> socket.socket:
    payload = cfg.http_payload or ""
    sock.sendall(payload.encode("ascii"))
    return sock


def apply_tls_client_hello(sock: socket.socket, cfg: TunnelConfig) -> socket.socket:
    name = sni_name(cfg)
    sock.sendall(build(name))
    return sock


def apply_chrome_ja3(sock: socket.socket, cfg: TunnelConfig) -> socket.socket:
    name = sni_name(cfg)
    sock.sendall(build_chrome_like(name))
    return sock


def apply_tls_full(sock: socket.socket, cfg: TunnelConfig) -> socket.socket:
    name = sni_name(cfg)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock, server_hostname=name)


def apply_websocket_tls(sock: socket.socket, cfg: TunnelConfig) -> socket.socket:
    host = sni_name(cfg)
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    upgrade = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"User-Agent: Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile\r\n"
        f"\r\n"
    )
    sock.sendall(upgrade.encode("ascii"))
    return apply_tls_client_hello(sock, cfg)


def apply_http2_preamble(sock: socket.socket, cfg: TunnelConfig) -> socket.socket:
    sock.sendall(H2_PREFACE)
    return apply_tls_client_hello(sock, cfg)


def apply_trojan_camouflage(sock: socket.socket, cfg: TunnelConfig) -> socket.socket:
    host = sni_name(cfg)
    token = os.urandom(56)
    hex_token = token.hex()
    password_hash = hashlib.sha224(hex_token.encode("ascii")).hexdigest()
    request = (
        f"{password_hash}\r\n"
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        f"Accept: text/html,application/xhtml+xml\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    )
    sock.sendall(request.encode("ascii"))
    return sock


_FRONT_HANDLERS = {
    "DIRECT": apply_direct,
    "HTTP_INJECT": apply_http_inject,
    "TLS_SNI_CLIENTHELLO_ONLY": apply_tls_client_hello,
    "TLS_SNI_FULL": apply_tls_full,
    "HTTP_WEBSOCKET_TLS": apply_websocket_tls,
    "HTTP2_PREAMBLE_TLS": apply_http2_preamble,
    "TLS_CHROME_JA3_MIMIC": apply_chrome_ja3,
    "TROJAN_HTTP_CAMOUFLAGE": apply_trojan_camouflage,
}


def apply_front(sock: socket.socket, cfg: TunnelConfig) -> socket.socket:
    apply_tcp_extras(sock, cfg)
    handler = _FRONT_HANDLERS.get(cfg.front_mode)
    if handler is None:
        raise ValueError(f"Unknown frontMode: {cfg.front_mode}")
    return handler(sock, cfg)
