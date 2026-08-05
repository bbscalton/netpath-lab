"""Quick server reachability probe for lab SSH host."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Callable

LogFn = Callable[[str], None]

DEFAULT_HOST = "fr1.sshweb.site"
PROBE_PORTS = [22, 80, 143, 443]
SSH_BANNER_PORTS = {22, 443}


@dataclass
class PortHealth:
    port: int
    tcp_ok: bool
    latency_ms: float | None = None
    ssh_banner: str | None = None
    error: str | None = None


@dataclass
class HealthReport:
    host: str
    ports: list[PortHealth] = field(default_factory=list)

    @property
    def reachable(self) -> bool:
        return any(p.tcp_ok for p in self.ports)

    def summary_line(self) -> str:
        parts = []
        for p in self.ports:
            if p.tcp_ok:
                extra = f" banner={p.ssh_banner!r}" if p.ssh_banner else ""
                lat = f"{p.latency_ms:.0f}ms" if p.latency_ms else "?"
                parts.append(f"{p.port}:OK({lat}{extra})")
            else:
                parts.append(f"{p.port}:FAIL({p.error or 'closed'})")
        return f"{self.host} — " + ", ".join(parts)


def _peek_ssh_banner(sock: socket.socket, timeout: float) -> str | None:
    sock.settimeout(timeout)
    try:
        data = sock.recv(256)
        if data.startswith(b"SSH-"):
            return data.decode("ascii", errors="replace").strip()
    except OSError:
        return None
    return None


def check_server(
    host: str = DEFAULT_HOST,
    ports: list[int] | None = None,
    timeout_s: float = 5.0,
    log: LogFn | None = None,
) -> HealthReport:
    ports = ports or PROBE_PORTS
    report = HealthReport(host=host)
    emit = log or (lambda _: None)

    emit(f"Server health check: {host}")
    for port in ports:
        t0 = time.perf_counter()
        entry = PortHealth(port=port, tcp_ok=False)
        try:
            with socket.create_connection((host, port), timeout=timeout_s) as sock:
                entry.tcp_ok = True
                entry.latency_ms = (time.perf_counter() - t0) * 1000
                if port in SSH_BANNER_PORTS:
                    entry.ssh_banner = _peek_ssh_banner(sock, timeout_s)
                emit(
                    f"  Port {port}: TCP OK ({entry.latency_ms:.0f} ms)"
                    + (f" — {entry.ssh_banner}" if entry.ssh_banner else "")
                )
        except OSError as exc:
            entry.error = str(exc)
            emit(f"  Port {port}: FAIL — {exc}")
        report.ports.append(entry)

    emit(report.summary_line())
    return report
