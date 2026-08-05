"""Tkinter GUI for NetPath Lab probe."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Callable

from probe.config_loader import DEFAULT_CONFIG_DIR, load_configs
from probe.engine import RunSummary, run_all_configs
from probe.health import HealthReport, check_server
from probe.report import write_reports


class ProbeApp(tk.Tk):
    COLUMNS = ("method", "port", "front", "status", "latency", "notes")

    def __init__(self) -> None:
        super().__init__()
        self.title("NetPath Lab Probe")
        self.geometry("980x640")
        self.minsize(800, 500)

        self._cancel = False
        self._worker: threading.Thread | None = None
        self._last_health: HealthReport | None = None
        self._last_summary: RunSummary | None = None

        self._build_ui()

    def _build_ui(self) -> None:
        top = ttk.Frame(self, padding=8)
        top.pack(fill=tk.X)

        self.btn_health = ttk.Button(top, text="Test server only", command=self._on_health)
        self.btn_health.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_run = ttk.Button(top, text="Run all tests", command=self._on_run_all)
        self.btn_run.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_cancel = ttk.Button(top, text="Cancel", command=self._on_cancel, state=tk.DISABLED)
        self.btn_cancel.pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(top, mode="indeterminate", length=200)
        self.progress.pack(side=tk.RIGHT)

        info = ttk.Label(
            top,
            text=f"Configs: {DEFAULT_CONFIG_DIR}",
            font=("Segoe UI", 8),
        )
        info.pack(side=tk.RIGHT, padx=8)

        mid = ttk.Panedwindow(self, orient=tk.VERTICAL)
        mid.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        log_frame = ttk.LabelFrame(mid, text="Log", padding=4)
        self.log = scrolledtext.ScrolledText(log_frame, height=10, font=("Consolas", 9), wrap=tk.WORD)
        self.log.pack(fill=tk.BOTH, expand=True)
        mid.add(log_frame, weight=1)

        table_frame = ttk.LabelFrame(mid, text="Results", padding=4)
        self.tree = ttk.Treeview(
            table_frame,
            columns=self.COLUMNS,
            show="headings",
            height=12,
        )
        headings = {
            "method": ("Method", 200),
            "port": ("Port", 50),
            "front": ("Front", 180),
            "status": ("Status", 100),
            "latency": ("Latency", 70),
            "notes": ("Notes", 300),
        }
        for col, (title, width) in headings.items():
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor=tk.W)
        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        mid.add(table_frame, weight=2)

        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(self, textvariable=self.status_var, anchor=tk.W, padding=(8, 4))
        status.pack(fill=tk.X)

    def _append_log(self, line: str) -> None:
        def _do() -> None:
            self.log.insert(tk.END, line + "\n")
            self.log.see(tk.END)

        self.after(0, _do)

    def _set_busy(self, busy: bool) -> None:
        state_run = tk.DISABLED if busy else tk.NORMAL
        self.btn_run.configure(state=state_run)
        self.btn_health.configure(state=state_run)
        self.btn_cancel.configure(state=tk.NORMAL if busy else tk.DISABLED)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _on_cancel(self) -> None:
        self._cancel = True
        self._append_log("Cancelling…")

    def _on_health(self) -> None:
        self._start_worker(self._health_job)

    def _on_run_all(self) -> None:
        self._start_worker(self._run_all_job)

    def _start_worker(self, job: Callable[[], None]) -> None:
        if self._worker and self._worker.is_alive():
            messagebox.showwarning("Busy", "A test run is already in progress.")
            return
        self._cancel = False
        self._set_busy(True)
        self._worker = threading.Thread(target=self._wrap_job(job), daemon=True)
        self._worker.start()

    def _wrap_job(self, job: Callable[[], None]) -> Callable[[], None]:
        def _inner() -> None:
            try:
                job()
            except Exception as exc:
                self._append_log(f"ERROR: {exc}")
                self.after(0, lambda: messagebox.showerror("Error", str(exc)))
            finally:
                self.after(0, lambda: self._set_busy(False))

        return _inner

    def _health_job(self) -> None:
        self._append_log("=== Server health check ===")
        self._last_health = check_server(log=self._append_log)
        self.after(0, lambda: self.status_var.set(self._last_health.summary_line()))

    def _run_all_job(self) -> None:
        self.after(0, lambda: self.tree.delete(*self.tree.get_children()))
        self._append_log("=== Loading configs ===")
        configs = load_configs()
        self._append_log(f"Loaded {len(configs)} configs from {DEFAULT_CONFIG_DIR}")

        self._append_log("=== Server health check ===")
        self._last_health = check_server(log=self._append_log)

        self._append_log("=== Running all method probes ===")
        summary = run_all_configs(
            configs,
            log=self._append_log,
            cancel_check=lambda: self._cancel,
            server_reachable=self._last_health.reachable if self._last_health else None,
        )
        self._last_summary = summary

        def _fill_table() -> None:
            for r in summary.results:
                self.tree.insert("", tk.END, values=r.as_row())

        self.after(0, _fill_table)

        json_path, html_path = write_reports(summary, self._last_health)
        self._append_log(f"Report written: {json_path}")
        self._append_log(f"Report written: {html_path}")

        if summary.recommended:
            self._append_log("Recommended (fastest AUTH_OK):")
            for line in summary.recommended:
                self._append_log(f"  • {line}")
        else:
            self._append_log("No methods reached AUTH_OK.")

        self.after(
            0,
            lambda: self.status_var.set(
                f"Done — {len([r for r in summary.results if r.status == 'AUTH_OK'])} AUTH_OK / {len(summary.results)} total"
            ),
        )


def run_gui() -> None:
    app = ProbeApp()
    app.mainloop()
