"""Write JSON and HTML reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from probe.engine import ProbeResult, RunSummary
from probe.health import HealthReport

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def _result_dict(r: ProbeResult) -> dict:
    return {
        "method": r.method,
        "port": r.port,
        "front": r.front,
        "status": r.status,
        "latency_ms": r.latency_ms,
        "notes": r.notes,
        "config_file": r.config_file,
        "host": r.host,
    }


def _health_dict(h: HealthReport | None) -> dict | None:
    if h is None:
        return None
    return {
        "host": h.host,
        "reachable": h.reachable,
        "summary": h.summary_line(),
        "ports": [
            {
                "port": p.port,
                "tcp_ok": p.tcp_ok,
                "latency_ms": p.latency_ms,
                "ssh_banner": p.ssh_banner,
                "error": p.error,
            }
            for p in h.ports
        ],
    }


def _build_recommended(summary: RunSummary, health: HealthReport | None) -> list[str]:
    auth_ok = [r for r in summary.results if r.status == "AUTH_OK"]
    auth_ok.sort(key=lambda r: r.latency_ms or 99999)
    recommended = [
        f"{r.method} (port {r.port}, {r.latency_ms:.0f} ms)" if r.latency_ms else r.method
        for r in auth_ok[:5]
    ]
    if recommended:
        return recommended
    if health:
        for p in health.ports:
            if p.tcp_ok and p.ssh_banner:
                return [
                    f"Baseline: port {p.port} speaks SSH ({p.ssh_banner}) — "
                    "use DIRECT front; TLS/WS fronts on 443 may need strip-proxy on server"
                ]
        if health.reachable:
            return ["Server TCP reachable but no AUTH_OK — check credentials or HTTP inject on port 80"]
    return []


def write_reports(
    summary: RunSummary,
    health: HealthReport | None = None,
) -> tuple[Path, Path]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    recommended = _build_recommended(summary, health)

    failures = [
        _result_dict(r)
        for r in summary.results
        if r.status not in ("AUTH_OK", "SKIP")
    ]
    payload = {
        "generated_at": ts,
        "server_reachable": summary.server_reachable or (health.reachable if health else False),
        "health": _health_dict(health),
        "recommended": recommended,
        "results": [_result_dict(r) for r in summary.results],
        "failures": failures,
        "counts": _status_counts(summary.results),
    }

    json_path = REPORTS_DIR / "latest.json"
    html_path = REPORTS_DIR / "latest.html"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    html_path.write_text(_render_html(payload), encoding="utf-8")
    return json_path, html_path


def _status_counts(results: list[ProbeResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def _render_html(data: dict) -> str:
    rows = ""
    for r in data["results"]:
        status = r["status"]
        cls = "ok" if status == "AUTH_OK" else ("skip" if status == "SKIP" else "fail")
        lat = f"{r['latency_ms']:.0f}" if r.get("latency_ms") is not None else ""
        rows += (
            f"<tr class='{cls}'><td>{_esc(r['method'])}</td><td>{r['port']}</td>"
            f"<td>{_esc(r['front'])}</td><td>{_esc(status)}</td><td>{lat}</td>"
            f"<td>{_esc(r.get('notes', ''))}</td></tr>\n"
        )

    rec = data.get("recommended") or []
    rec_html = "<ul>" + "".join(f"<li>{_esc(x)}</li>" for x in rec) + "</ul>" if rec else "<p>No AUTH_OK methods — check server or network.</p>"

    health = data.get("health") or {}
    health_line = _esc(health.get("summary", "Not run"))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>NetPath Probe Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0f1419; color: #e6edf3; }}
    h1 {{ font-size: 1.4rem; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 0.9rem; }}
    th, td {{ border: 1px solid #30363d; padding: 0.4rem 0.6rem; text-align: left; }}
    th {{ background: #161b22; }}
    tr.ok td:nth-child(4) {{ color: #3fb950; }}
    tr.fail td:nth-child(4) {{ color: #f85149; }}
    tr.skip td:nth-child(4) {{ color: #d29922; }}
    .meta {{ color: #8b949e; font-size: 0.85rem; }}
  </style>
</head>
<body>
  <h1>NetPath Lab Probe Report</h1>
  <p class="meta">Generated {_esc(data.get('generated_at', ''))}</p>
  <h2>Server health</h2>
  <p>{health_line}</p>
  <h2>Recommended methods</h2>
  {rec_html}
  <h2>All results</h2>
  <table>
    <thead><tr><th>Method</th><th>Port</th><th>Front</th><th>Status</th><th>Latency ms</th><th>Notes</th></tr></thead>
    <tbody>
{rows}    </tbody>
  </table>
  <p class="meta">Counts: {_esc(str(data.get('counts', {})))}</p>
</body>
</html>
"""


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
