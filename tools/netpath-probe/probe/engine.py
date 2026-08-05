"""Connection test engine — TCP front + SSH auth probe."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Callable

import paramiko

from probe.config_loader import TunnelConfig
from probe.fronts import apply_front

LogFn = Callable[[str], None]


@dataclass
class ProbeResult:
    method: str
    port: int
    front: str
    status: str
    latency_ms: float | None = None
    notes: str = ""
    config_file: str = ""
    host: str = ""

    def as_row(self) -> tuple:
        lat = f"{self.latency_ms:.0f}" if self.latency_ms is not None else ""
        return (self.method, str(self.port), self.front, self.status, lat, self.notes)


@dataclass
class RunSummary:
    results: list[ProbeResult] = field(default_factory=list)
    recommended: list[str] = field(default_factory=list)
    server_reachable: bool = False
    health_notes: str = ""


def _noop_log(_: str) -> None:
    pass


def probe_config(cfg: TunnelConfig, log: LogFn = _noop_log) -> ProbeResult:
    if cfg.is_udp_skip():
        log(f"[SKIP] {cfg.name} — UDP transport (Hysteria/DNSTT/UDPGW not probed on Windows)")
        return ProbeResult(
            method=cfg.name,
            port=cfg.server_port,
            front=cfg.front_mode,
            status="SKIP",
            notes="UDP/QUIC drill — TCP probe N/A on this tool",
            config_file=cfg.source_file,
            host=cfg.server_host,
        )

    last_result: ProbeResult | None = None
    for port in cfg.iter_ports():
        result = _probe_single_port(cfg, port, log)
        if result.status == "AUTH_OK":
            if port != cfg.server_port:
                result.notes = f"Port fallback succeeded on {port} (config port {cfg.server_port}). {result.notes}".strip()
            return result
        last_result = result
        if len(cfg.iter_ports()) > 1:
            log(f"  Port {port} failed ({result.status}): {result.notes}")

    assert last_result is not None
    return last_result


def _probe_single_port(cfg: TunnelConfig, port: int, log: LogFn) -> ProbeResult:
    method = cfg.name
    front = cfg.front_mode
    host = cfg.server_host
    t0 = time.perf_counter()
    sock: socket.socket | None = None
    transport: paramiko.Transport | None = None
    stage = "CONNECT_FAIL"

    try:
        log(f"Connecting {host}:{port} [{method}] front={front}")
        sock = socket.create_connection((host, port), timeout=cfg.connect_timeout_s)
        sock.settimeout(cfg.connect_timeout_s)
        latency_connect = (time.perf_counter() - t0) * 1000
        stage = "CONNECT_OK"
        log(f"  CONNECT_OK ({latency_connect:.0f} ms)")

        apply_front(sock, cfg)
        stage = "FRONT_SENT"
        log("  FRONT_SENT")

        transport = paramiko.Transport(sock)
        transport.banner_timeout = cfg.connect_timeout_s
        transport.auth_timeout = cfg.connect_timeout_s
        transport.start_client(timeout=cfg.connect_timeout_s)
        banner = transport.remote_version or ""
        stage = "SSH_BANNER"
        log(f"  SSH_BANNER: {banner}")

        transport.auth_password(cfg.username, cfg.password)
        log("  AUTH_OK")
        latency_total = (time.perf_counter() - t0) * 1000
        return ProbeResult(
            method=method,
            port=port,
            front=front,
            status="AUTH_OK",
            latency_ms=latency_total,
            notes=f"SSH {banner.strip()}",
            config_file=cfg.source_file,
            host=host,
        )
    except paramiko.AuthenticationException as exc:
        latency = (time.perf_counter() - t0) * 1000
        return ProbeResult(
            method=method,
            port=port,
            front=front,
            status="SSH_BANNER",
            latency_ms=latency,
            notes=f"Auth failed: {exc}",
            config_file=cfg.source_file,
            host=host,
        )
    except (socket.timeout, TimeoutError) as exc:
        return ProbeResult(
            method=method,
            port=port,
            front=front,
            status="CONNECT_TIMEOUT" if stage == "CONNECT_FAIL" else stage,
            notes=str(exc) or "timeout",
            config_file=cfg.source_file,
            host=host,
        )
    except OSError as exc:
        return ProbeResult(
            method=method,
            port=port,
            front=front,
            status=stage,
            notes=str(exc),
            config_file=cfg.source_file,
            host=host,
        )
    except Exception as exc:
        return ProbeResult(
            method=method,
            port=port,
            front=front,
            status=stage,
            notes=str(exc),
            config_file=cfg.source_file,
            host=host,
        )
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        elif sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def run_all_configs(
    configs: list[TunnelConfig],
    log: LogFn = _noop_log,
    cancel_check: Callable[[], bool] | None = None,
    server_reachable: bool | None = None,
) -> RunSummary:
    results: list[ProbeResult] = []
    for i, cfg in enumerate(configs):
        if cancel_check and cancel_check():
            log("Run cancelled.")
            break
        log(f"--- Test {i + 1}/{len(configs)}: {cfg.name} ---")
        results.append(probe_config(cfg, log))

    auth_ok = [r for r in results if r.status == "AUTH_OK"]
    auth_ok.sort(key=lambda r: r.latency_ms or 99999)
    recommended = [
        f"{r.method} (port {r.port}, {r.latency_ms:.0f} ms)" if r.latency_ms else r.method
        for r in auth_ok[:5]
    ]

    return RunSummary(
        results=results,
        recommended=recommended,
        server_reachable=server_reachable if server_reachable is not None else bool(auth_ok),
    )
