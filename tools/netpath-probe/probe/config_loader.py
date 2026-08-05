"""Load .nplab.json configs from docs/downloads/configs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_HTTP_PAYLOAD = (
    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
)
HOLD_PORTS = [443, 80, 8080]

PROBE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_DIR = (PROBE_ROOT / ".." / ".." / "docs" / "downloads" / "configs").resolve()


@dataclass
class TunnelConfig:
    name: str
    server_host: str
    server_port: int
    username: str
    password: str
    front_mode: str
    custom_sni: str = ""
    http_payload: str = DEFAULT_HTTP_PAYLOAD
    tcp_payload_hex: str = ""
    use_realm_host_v2: bool = False
    preserve_sni: bool = True
    use_tcp_payload: bool = False
    connect_timeout_ms: int = 15_000
    custom_setup: bool = True
    transport_protocol: str = "TCP"
    www_sni_toggle: bool = False
    port_fallback: bool = True
    use_front_padding: bool = False
    front_padding_max_bytes: int = 64
    source_file: str = ""

    @property
    def connect_timeout_s(self) -> float:
        return self.connect_timeout_ms / 1000.0

    def resolve_sni(self) -> str:
        sni = (self.custom_sni or "").strip()
        if not sni:
            sni = self.server_host
        if not self.www_sni_toggle:
            return sni
        bare = sni[4:] if sni.lower().startswith("www.") else sni
        if sni.lower().startswith("www."):
            return bare
        return f"www.{bare}"

    def iter_ports(self) -> list[int]:
        if self.custom_setup and self.port_fallback:
            ordered: list[int] = []
            seen: set[int] = set()
            for p in [self.server_port, *HOLD_PORTS]:
                if p not in seen:
                    ordered.append(p)
                    seen.add(p)
            return ordered
        return [self.server_port]

    def is_udp_skip(self) -> bool:
        return self.transport_protocol.upper() == "UDP"

    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str = "") -> TunnelConfig:
        return cls(
            name=str(data.get("name", "unnamed")),
            server_host=str(data.get("serverHost", "")),
            server_port=int(data.get("serverPort", 443)),
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
            front_mode=str(data.get("frontMode", "DIRECT")),
            custom_sni=str(data.get("customSni", "")),
            http_payload=str(data.get("httpPayload") or DEFAULT_HTTP_PAYLOAD),
            tcp_payload_hex=str(data.get("tcpPayloadHex", "")),
            use_realm_host_v2=bool(data.get("useRealmHostV2", False)),
            preserve_sni=bool(data.get("preserveSni", True)),
            use_tcp_payload=bool(data.get("useTcpPayload", False)),
            connect_timeout_ms=int(data.get("connectTimeoutMs", 15_000)),
            custom_setup=bool(data.get("customSetup", True)),
            transport_protocol=str(data.get("transportProtocol", "TCP")),
            www_sni_toggle=bool(data.get("wwwSniToggle", False)),
            port_fallback=bool(data.get("portFallback", True)),
            use_front_padding=bool(data.get("useFrontPadding", False)),
            front_padding_max_bytes=int(data.get("frontPaddingMaxBytes", 64)),
            source_file=source,
        )


def load_configs(config_dir: Path | None = None) -> list[TunnelConfig]:
    root = config_dir or DEFAULT_CONFIG_DIR
    if not root.is_dir():
        raise FileNotFoundError(f"Config directory not found: {root}")
    configs: list[TunnelConfig] = []
    for path in sorted(root.glob("*.nplab.json")):
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        configs.append(TunnelConfig.from_dict(data, source=path.name))
    return configs
