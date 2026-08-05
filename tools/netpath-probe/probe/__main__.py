"""CLI entry: GUI by default, --cli for headless run."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from probe.config_loader import DEFAULT_CONFIG_DIR, load_configs
from probe.engine import run_all_configs
from probe.health import check_server
from probe.gui import run_gui
from probe.report import write_reports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NetPath Lab connection probe")
    parser.add_argument("--cli", action="store_true", help="Run headless in terminal (no GUI)")
    parser.add_argument("--health-only", action="store_true", help="Server health check only")
    parser.add_argument("--config-dir", type=str, default=str(DEFAULT_CONFIG_DIR))
    args = parser.parse_args(argv)

    if not args.cli and not args.health_only:
        run_gui()
        return 0

    def log(msg: str) -> None:
        print(msg, flush=True)

    health = check_server(log=log)
    if args.health_only:
        return 0 if health.reachable else 1

    configs = load_configs(Path(args.config_dir))
    log(f"Loaded {len(configs)} configs")
    summary = run_all_configs(configs, log=log, server_reachable=health.reachable)
    json_path, html_path = write_reports(summary, health)
    log(f"Reports: {json_path}, {html_path}")
    if summary.recommended:
        log("Recommended:")
        for line in summary.recommended:
            log(f"  {line}")
    return 0 if summary.server_reachable else 1


if __name__ == "__main__":
    sys.exit(main())
