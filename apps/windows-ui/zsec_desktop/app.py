"""Tk desktop client for the current ZSEC Antivirus CLI contracts.

This source client is deliberately unprivileged.  A production Windows build
should replace this shell with a signed .NET desktop client while retaining the
same fail-closed contract and privilege boundaries documented beside it.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import json
import math
import os
import queue
import threading
import time
import tkinter as tk
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from functools import partial
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from zsec_desktop.brand import render_mark
from zsec_desktop.bridge import BridgeError, CommandResult, WatchSession, ZsecBridge
from zsec_desktop.contracts import (
    companion_presentation,
    status_presentation,
    update_presentation,
    windows_cutover_presentation,
)
from zsec_desktop.settings import (
    DesktopSettings,
    StartupRegistration,
    load_settings,
    save_settings,
)
from zsec_desktop.support import build_support_snapshot, save_support_snapshot
from zsec_desktop.tray import TrayController
from zsec_shield import __version__ as ZSEC_VERSION

BACKGROUND = "#08111f"
SURFACE = "#101c2d"
SURFACE_ALT = "#15243a"
TEXT = "#e8f0fa"
MUTED = "#9fb0c4"
CYAN = "#26d9d1"
GREEN = "#32d583"
AMBER = "#f5b942"
RED = "#f97066"
STARTUP_EVIDENCE_NOTICE_MS = 10_000
COMPANION_REFRESH_INTERVAL_MS = 90_000


class ModernStatusCard(tk.Canvas):
    """Rounded evidence card rendered with native Tk primitives."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        motion_enabled: Callable[[], bool],
    ) -> None:
        super().__init__(
            parent,
            width=240,
            height=124,
            bg=BACKGROUND,
            highlightthickness=0,
            borderwidth=0,
            takefocus=1,
        )
        self.title = title
        self.motion_enabled = motion_enabled
        self.value = "Loading…"
        self.accent = CYAN
        self.hover_progress = 0.0
        self.hover_target = 0.0
        self.hover_job: str | None = None
        self.status_emphasis = 0.0
        self.status_job: str | None = None
        self.bind("<Configure>", self._render)
        self.bind("<Enter>", lambda _event: self._set_hover(1.0))
        self.bind("<Leave>", lambda _event: self._set_hover(0.0))
        self.bind("<FocusIn>", lambda _event: self._set_hover(1.0))
        self.bind("<FocusOut>", lambda _event: self._set_hover(0.0))
        self.bind("<Destroy>", self._cancel_animation)

    def set_value(self, value: str, accent: str) -> None:
        changed = value != self.value or accent != self.accent
        self.value = value
        self.accent = accent
        if changed and self.motion_enabled():
            self.status_emphasis = 1.0
            if self.status_job is None:
                self.status_job = self.after(40, self._animate_status_emphasis)
        else:
            self.status_emphasis = 0.0
        self._render()

    def _animate_status_emphasis(self) -> None:
        self.status_emphasis = max(0.0, self.status_emphasis - 0.12)
        self._render()
        if self.status_emphasis > 0.0 and self.motion_enabled():
            self.status_job = self.after(40, self._animate_status_emphasis)
        else:
            self.status_emphasis = 0.0
            self.status_job = None

    def sync_motion_preference(self) -> None:
        """Immediately settle decorative motion when reduced motion is enabled."""

        if self.motion_enabled():
            return
        if self.hover_job is not None:
            with contextlib.suppress(tk.TclError):
                self.after_cancel(self.hover_job)
            self.hover_job = None
        if self.status_job is not None:
            with contextlib.suppress(tk.TclError):
                self.after_cancel(self.status_job)
            self.status_job = None
        self.hover_progress = self.hover_target
        self.status_emphasis = 0.0
        self._render()

    def _set_hover(self, target: float) -> None:
        self.hover_target = target
        if not self.motion_enabled():
            if self.hover_job is not None:
                with contextlib.suppress(tk.TclError):
                    self.after_cancel(self.hover_job)
                self.hover_job = None
            self.hover_progress = target
            self._render()
            return
        if self.hover_job is None:
            self._animate_hover()

    def _cancel_animation(self, _event: tk.Event[tk.Misc] | None = None) -> None:
        if self.hover_job is not None:
            with contextlib.suppress(tk.TclError):
                self.after_cancel(self.hover_job)
            self.hover_job = None
        if self.status_job is not None:
            with contextlib.suppress(tk.TclError):
                self.after_cancel(self.status_job)
            self.status_job = None

    def _animate_hover(self) -> None:
        delta = self.hover_target - self.hover_progress
        if abs(delta) < 0.02:
            self.hover_progress = self.hover_target
            self.hover_job = None
            self._render()
            return
        self.hover_progress += delta * 0.28
        self._render()
        self.hover_job = self.after(16, self._animate_hover)

    def _rounded_rectangle(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        radius: float,
        **options: Any,
    ) -> int:
        points = (
            x1 + radius,
            y1,
            x2 - radius,
            y1,
            x2,
            y1,
            x2,
            y1 + radius,
            x2,
            y2 - radius,
            x2,
            y2,
            x2 - radius,
            y2,
            x1 + radius,
            y2,
            x1,
            y2,
            x1,
            y2 - radius,
            x1,
            y1 + radius,
            x1,
            y1,
        )
        return int(self.create_polygon(points, smooth=True, splinesteps=24, **options))

    def _render(self, _event: tk.Event[tk.Misc] | None = None) -> None:
        width = max(self.winfo_width(), 1)
        height = max(self.winfo_height(), 124)
        self.delete("all")
        shadow = int(14 + 18 * self.hover_progress)
        self._rounded_rectangle(
            5,
            7,
            width - 1,
            height - 2,
            18,
            fill=f"#{shadow:02x}{shadow + 8:02x}{shadow + 18:02x}",
            outline="",
        )
        self._rounded_rectangle(
            2,
            2,
            width - 2,
            height - 4,
            18,
            fill=SURFACE,
            outline=(
                self.accent
                if self.hover_progress > 0.55 or self.status_emphasis > 0.0
                else SURFACE_ALT
            ),
            width=2 + int(max(self.hover_progress, self.status_emphasis)),
        )
        self.create_rectangle(2, 24, 6, height - 26, fill=self.accent, outline=self.accent)
        self.create_text(
            22,
            23,
            text=self.title.upper(),
            anchor=tk.W,
            fill=MUTED,
            font=("Segoe UI Semibold", 9),
        )
        self.create_text(
            22,
            61,
            text=self.value,
            anchor=tk.W,
            width=max(width - 46, 20),
            fill=self.accent,
            font=("Segoe UI Semibold", 12),
        )


def _default_state_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "ZSEC" / "Shield"
    return Path.home() / "AppData" / "Local" / "ZSEC" / "Shield"


class ZsecDesktop:
    def __init__(self, root: tk.Tk, bridge: ZsecBridge, *, startup: bool = False) -> None:
        self.root = root
        self.bridge = bridge
        # Initial evidence comes from independent, read-only commands. Four workers
        # let the slow Windows provider query start immediately instead of sitting
        # behind status, readiness and list operations. Every bridge command keeps
        # its own existing timeout and fail-closed contract.
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="zsec-ui")
        self.ui_queue: queue.SimpleQueue[
            tuple[Callable[..., Any], tuple[Any, ...]]
        ] = queue.SimpleQueue()
        self.ui_queue_job: str | None = None
        self.closing = False
        self.scan_cancel: threading.Event | None = None
        self.watch_session: WatchSession | None = None
        self.quarantine_rows: dict[str, dict[str, Any]] = {}
        self.report_rows: dict[str, Path] = {}
        loaded_settings, self.settings_load_error = load_settings(bridge.state_dir)
        self.startup_registration = StartupRegistration()
        registered_startup, registration_error = self.startup_registration.current()
        if registration_error is not None:
            self.settings_load_error = "; ".join(
                value
                for value in (self.settings_load_error, registration_error)
                if value is not None
            )
        elif loaded_settings.start_with_windows != registered_startup:
            loaded_settings = DesktopSettings(
                close_to_tray=loaded_settings.close_to_tray,
                start_with_windows=registered_startup,
                reduce_motion=loaded_settings.reduce_motion,
                max_file_mebibytes=loaded_settings.max_file_mebibytes,
            )
        self.desktop_settings = loaded_settings
        self.reduce_motion = tk.BooleanVar(value=loaded_settings.reduce_motion)
        self.close_to_tray = tk.BooleanVar(value=loaded_settings.close_to_tray)
        self.start_with_windows = tk.BooleanVar(value=loaded_settings.start_with_windows)
        self.animation_phase = 0
        self.animation_job: str | None = None
        self.busy_operations = 0
        self.global_busy_visible = False
        self.companion_refresh_generation = 0
        self.companion_refresh_inflight = False
        self.companion_refresh_buttons: list[ttk.Button] = []
        self.companion_refresh_job: str | None = None
        self.startup_status_resolved = False
        self.startup_companion_resolved = False
        self.startup_evidence_deadline_job: str | None = None
        self.watch_session_id: str | None = None
        self.watch_last_sequence = 0
        self.watch_last_heartbeat_monotonic: float | None = None
        self.watch_watchdog_job: str | None = None
        self.tray_scan_status = "Local engine starting"
        self.tray_companion_status = "Companion evidence pending"
        self.protected_roots: tuple[Path, ...] = ()
        self.latest_status_payload: dict[str, Any] | None = None
        self.latest_companion_payload: dict[str, Any] | None = None

        self.root.title("ZSEC Antivirus")
        self.root.geometry("1180x760")
        self.root.minsize(960, 640)
        self.root.configure(bg=BACKGROUND)
        self._apply_brand_icon()
        self.root.protocol("WM_DELETE_WINDOW", self._window_close)
        self.root.bind("<Unmap>", self._window_unmapped)
        self.root.after(0, self._apply_windows_chrome)
        self._configure_style()
        self._build_header()
        self._build_tabs()
        self._set_initial_evidence_state()
        self.ui_queue_job = self.root.after(20, self._drain_ui_queue)
        self.tray = TrayController(
            dispatch=lambda callback: self._post(callback),
            open_window=self._open_window,
            scan_protected_folders=self._tray_scan_protected_folders,
            open_settings=self._open_settings,
            exit_application=self._exit_application,
        )
        self.tray.start()
        self._update_tray_status()
        self._animate_activity()
        self.root.after(120, self.refresh_all)
        self.startup_evidence_deadline_job = self.root.after(
            STARTUP_EVIDENCE_NOTICE_MS, self._startup_evidence_deadline
        )
        self.companion_refresh_job = self.root.after(
            COMPANION_REFRESH_INTERVAL_MS, self._periodic_companion_refresh
        )
        if startup and self.tray.active:
            self.root.after_idle(self.root.withdraw)

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        with contextlib.suppress(tk.TclError):
            style.theme_use("clam")
        style.configure("TFrame", background=BACKGROUND)
        style.configure("Surface.TFrame", background=SURFACE)
        style.configure("Alt.TFrame", background=SURFACE_ALT)
        style.configure("TLabel", background=BACKGROUND, foreground=TEXT, font=("Segoe UI", 10))
        style.configure(
            "Surface.TLabel", background=SURFACE, foreground=TEXT, font=("Segoe UI", 10)
        )
        style.configure(
            "Title.TLabel", background=BACKGROUND, foreground=TEXT, font=("Segoe UI Semibold", 22)
        )
        style.configure(
            "Subtitle.TLabel", background=BACKGROUND, foreground=MUTED, font=("Segoe UI", 10)
        )
        style.configure(
            "Section.TLabel", background=SURFACE, foreground=TEXT, font=("Segoe UI Semibold", 14)
        )
        style.configure(
            "Status.TLabel", background=SURFACE, foreground=CYAN, font=("Segoe UI Semibold", 11)
        )
        style.configure(
            "Warning.TLabel", background=SURFACE, foreground=AMBER, font=("Segoe UI Semibold", 10)
        )
        style.configure(
            "Danger.TLabel", background=SURFACE, foreground=RED, font=("Segoe UI Semibold", 10)
        )
        style.configure("Muted.TLabel", background=SURFACE, foreground=MUTED, font=("Segoe UI", 9))
        style.configure(
            "TButton",
            background=SURFACE_ALT,
            foreground=TEXT,
            padding=(12, 7),
            font=("Segoe UI Semibold", 9),
        )
        style.map(
            "TButton",
            background=[("active", "#1d3551"), ("disabled", "#172234")],
            foreground=[("disabled", "#637186")],
        )
        style.configure("Primary.TButton", background="#087f7a", foreground="#ffffff")
        style.map("Primary.TButton", background=[("active", "#0a9f98"), ("disabled", "#164a4d")])
        style.configure("Danger.TButton", background="#7f1d2d", foreground="#ffffff")
        style.map("Danger.TButton", background=[("active", "#9f2638")])
        style.configure("TNotebook", background=BACKGROUND, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=SURFACE,
            foreground=MUTED,
            padding=(13, 8),
            font=("Segoe UI Semibold", 9),
        )
        style.map(
            "TNotebook.Tab", background=[("selected", SURFACE_ALT)], foreground=[("selected", CYAN)]
        )
        style.configure(
            "Treeview",
            background="#0c1727",
            fieldbackground="#0c1727",
            foreground=TEXT,
            rowheight=28,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background=SURFACE_ALT,
            foreground=TEXT,
            relief="flat",
            font=("Segoe UI Semibold", 9),
        )
        style.map("Treeview", background=[("selected", "#155e75")])
        style.configure("TCheckbutton", background=SURFACE, foreground=TEXT, font=("Segoe UI", 9))
        style.map(
            "TCheckbutton", background=[("active", SURFACE)], foreground=[("disabled", MUTED)]
        )
        style.configure(
            "TEntry", fieldbackground="#0b1524", foreground=TEXT, insertcolor=TEXT, padding=7
        )
        style.configure("TCombobox", fieldbackground="#0b1524", foreground=TEXT, padding=6)
        style.configure("Horizontal.TProgressbar", troughcolor="#142137", background=CYAN)
        style.configure("Content.TNotebook", background=BACKGROUND, borderwidth=0, tabmargins=0)
        style.layout("Content.TNotebook.Tab", [])
        style.configure(
            "Nav.TButton",
            background=SURFACE,
            foreground=MUTED,
            borderwidth=0,
            focusthickness=0,
            padding=(16, 10),
            anchor=tk.W,
            font=("Segoe UI Semibold", 9),
        )
        style.map(
            "Nav.TButton",
            background=[("active", SURFACE_ALT)],
            foreground=[("active", TEXT)],
        )
        style.configure(
            "NavSelected.TButton",
            background="#123f4b",
            foreground=CYAN,
            borderwidth=0,
            focusthickness=0,
            padding=(16, 10),
            anchor=tk.W,
            font=("Segoe UI Semibold", 9),
        )
        style.map(
            "NavSelected.TButton",
            background=[("active", "#165668")],
            foreground=[("active", "#7ff8ee")],
        )

    def _build_header(self) -> None:
        header = ttk.Frame(self.root, padding=(24, 18, 24, 12))
        header.pack(fill=tk.X)
        title_row = ttk.Frame(header)
        title_row.pack(fill=tk.X)
        brand_canvas = tk.Canvas(
            title_row,
            width=42,
            height=42,
            bg=BACKGROUND,
            highlightthickness=0,
            borderwidth=0,
            takefocus=0,
        )
        brand_canvas.pack(side=tk.LEFT, padx=(0, 10))
        brand_canvas.create_polygon(
            21, 3, 37, 9, 37, 21, 34, 29, 28, 36, 21, 40,
            14, 36, 8, 29, 5, 21, 5, 9,
            fill="#102538", outline="#2e6470", width=2,
        )
        brand_canvas.create_polygon(
            11, 12, 31, 12, 31, 17, 20, 27, 31, 27, 31, 33,
            10, 33, 10, 27, 21, 17, 11, 17,
            fill=CYAN, outline="",
        )
        ttk.Label(title_row, text="ZSEC", style="Title.TLabel", foreground=CYAN).pack(side=tk.LEFT)
        ttk.Label(title_row, text="  Antivirus", style="Title.TLabel").pack(side=tk.LEFT)
        ttk.Label(
            title_row,
            text="COMMUNITY 0.3.22",
            style="Subtitle.TLabel",
            foreground=AMBER,
        ).pack(
            side=tk.LEFT, padx=(18, 0), pady=(9, 0)
        )
        self.global_busy = ttk.Progressbar(title_row, mode="indeterminate", length=150)
        self.activity_canvas = tk.Canvas(
            title_row,
            width=180,
            height=40,
            bg=BACKGROUND,
            highlightthickness=0,
            borderwidth=0,
            takefocus=0,
        )
        self.activity_canvas.pack(side=tk.RIGHT, padx=(0, 18), pady=2)
        ttk.Label(
            header,
            text=(
                "Microsoft Defender provides real-time enforcement. ZSEC adds automatic "
                "post-change inspection, protected-folder scans and recovery evidence."
            ),
            style="Subtitle.TLabel",
        ).pack(anchor=tk.W, pady=(4, 0))

    def _apply_brand_icon(self) -> None:
        self.brand_icon: Any | None = None
        try:
            from PIL import ImageTk

            icon: Any = ImageTk.PhotoImage(render_mark(64), master=self.root)
            self.brand_icon = icon
            self.root.iconphoto(True, self.brand_icon)
        except (ImportError, OSError, RuntimeError, tk.TclError):
            self.brand_icon = None

    def _apply_windows_chrome(self) -> None:
        if os.name != "nt":
            return
        with contextlib.suppress(OSError, AttributeError):
            self.root.update_idletasks()
            hwnd = ctypes.c_void_p(self.root.winfo_id())
            dark = ctypes.c_int(1)
            rounded = ctypes.c_int(2)
            dwm = ctypes.windll.dwmapi
            dwm.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(dark), ctypes.sizeof(dark))
            dwm.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(rounded), ctypes.sizeof(rounded))

    def _build_tabs(self) -> None:
        workspace = ttk.Frame(self.root, padding=(20, 0, 20, 20))
        workspace.pack(fill=tk.BOTH, expand=True)
        navigation = ttk.Frame(workspace, style="Surface.TFrame", padding=(12, 16))
        navigation.pack(side=tk.LEFT, fill=tk.Y)
        navigation.configure(width=220)
        navigation.pack_propagate(False)
        ttk.Label(
            navigation,
            text="PROTECTION CENTRE",
            style="Muted.TLabel",
            background=SURFACE,
            foreground=CYAN,
            font=("Segoe UI Semibold", 9),
        ).pack(anchor=tk.W, padx=10, pady=(0, 10))
        self.tabs = ttk.Notebook(workspace, style="Content.TNotebook")
        self.tabs.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(12, 0))
        self.overview_tab = self._tab("Overview")
        self.scan_tab = self._tab("Scan")
        self.monitor_tab = self._tab("Automatic monitoring")
        self.quarantine_tab = self._tab("Quarantine")
        self.windows_protection_tab = self._tab("Windows protection")
        self.feeds_tab = self._tab("Feeds")
        self.reports_tab = self._tab("Reports")
        self.health_tab = self._tab("Health")
        self.security_tab = self._tab("Encryption & recovery")
        self.readiness_tab = self._tab("Protection assurance")
        self.settings_tab = self._tab("Settings")
        self._build_overview()
        self._build_scan()
        self._build_monitor()
        self._build_quarantine()
        self._build_windows_protection()
        self._build_feeds()
        self._build_reports()
        self._build_health()
        self._build_security()
        self._build_readiness()
        self._build_settings()
        self.navigation_buttons: list[tuple[ttk.Frame, ttk.Button]] = []
        for frame, title in (
            (self.overview_tab, "Overview"),
            (self.scan_tab, "Scan"),
            (self.monitor_tab, "Automatic monitoring"),
            (self.quarantine_tab, "Quarantine"),
            (self.windows_protection_tab, "Windows protection"),
            (self.feeds_tab, "Signed feeds"),
            (self.reports_tab, "Reports"),
            (self.health_tab, "Evidence health"),
            (self.security_tab, "Encryption & recovery"),
            (self.readiness_tab, "Protection assurance"),
            (self.settings_tab, "Settings"),
        ):
            button = ttk.Button(
                navigation,
                text=title,
                style="Nav.TButton",
                command=partial(self._select_tab, frame),
            )
            button.pack(fill=tk.X, pady=2)
            self.navigation_buttons.append((frame, button))
        ttk.Separator(navigation).pack(fill=tk.X, pady=(14, 10))
        ttk.Label(
            navigation,
            text="LOCAL · NO ACCOUNT\nEVIDENCE FIRST",
            style="Muted.TLabel",
            background=SURFACE,
            foreground=MUTED,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, padx=10)
        self.tabs.bind("<<NotebookTabChanged>>", self._sync_navigation)
        self._sync_navigation()

    def _select_tab(self, frame: ttk.Frame) -> None:
        self.tabs.select(frame)  # type: ignore[no-untyped-call]
        self._sync_navigation()

    def _sync_navigation(self, _event: tk.Event[tk.Misc] | None = None) -> None:
        selected = self.tabs.select()  # type: ignore[no-untyped-call]
        for frame, button in self.navigation_buttons:
            button.configure(
                style=("NavSelected.TButton" if str(frame) == str(selected) else "Nav.TButton")
            )

    def _tab(self, title: str) -> ttk.Frame:
        frame = ttk.Frame(self.tabs, padding=16)
        self.tabs.add(frame, text=title)
        return frame

    def _panel(self, parent: ttk.Frame, *, padding: int = 18) -> ttk.Frame:
        panel = ttk.Frame(parent, style="Surface.TFrame", padding=padding)
        return panel

    def _build_overview(self) -> None:
        banner = self._panel(self.overview_tab)
        banner.pack(fill=tk.X, pady=(0, 12))
        ttk.Label(banner, text="Layered Windows protection", style="Status.TLabel").pack(
            anchor=tk.W
        )
        ttk.Label(
            banner,
            text=(
                "Windows Defender remains the real-time, pre-access protection engine. "
                "ZSEC automatically monitors everyday folders and adds local inspection, "
                "signed rules, evidence and encrypted recovery."
            ),
            style="Muted.TLabel",
            wraplength=900,
        ).pack(anchor=tk.W, pady=(5, 0))
        self.overview_cards_frame = ttk.Frame(self.overview_tab)
        self.overview_cards_frame.pack(fill=tk.X)
        self.scan_card = self._overview_card(self.overview_cards_frame, "Last scan")
        self.feed_card = self._overview_card(self.overview_cards_frame, "Advisory updates")
        self.quarantine_card = self._overview_card(
            self.overview_cards_frame, "Encrypted quarantine"
        )
        self.companion_card = self._overview_card(
            self.overview_cards_frame, "Automatic companion"
        )
        self.windows_card = self._overview_card(
            self.overview_cards_frame, "Windows enforcement"
        )
        self.overview_cards = [
            self.scan_card,
            self.feed_card,
            self.quarantine_card,
            self.companion_card,
            self.windows_card,
        ]
        self.overview_card_columns = 0
        self.overview_cards_frame.bind("<Configure>", self._layout_overview_cards)
        self.overview_tab.bind("<Map>", self._layout_overview_cards)
        self.root.after_idle(self._layout_overview_cards)
        actions = self._panel(self.overview_tab)
        actions.pack(fill=tk.X, pady=(12, 0))
        ttk.Label(actions, text="Quick actions", style="Section.TLabel").pack(anchor=tk.W)
        row = ttk.Frame(actions, style="Surface.TFrame")
        row.pack(fill=tk.X, pady=(12, 0))
        self.overview_action_buttons: list[ttk.Button] = []
        refresh_button = ttk.Button(
            row, text="Refresh evidence", style="Primary.TButton", command=self.refresh_all
        )
        self.overview_action_buttons.append(refresh_button)
        self.scan_protected_button = ttk.Button(
            row,
            text="Scan protected folders now",
            command=self._scan_protected_folders,
            state=tk.DISABLED,
        )
        self.overview_action_buttons.append(self.scan_protected_button)
        details_button = ttk.Button(
            row,
            text="Protection details",
            command=lambda: self.tabs.select(self.monitor_tab),  # type: ignore[no-untyped-call]
        )
        self.overview_action_buttons.append(details_button)
        assurance_button = ttk.Button(
            row,
            text="Protection assurance",
            command=lambda: self.tabs.select(  # type: ignore[no-untyped-call]
                self.readiness_tab
            ),
        )
        self.overview_action_buttons.append(assurance_button)
        self.overview_actions_row = row
        self.overview_action_columns = 0
        row.bind("<Configure>", self._layout_overview_actions)
        self.overview_tab.bind("<Map>", self._layout_overview_actions, add="+")
        self.root.after_idle(self._layout_overview_actions)

    def _overview_card(self, parent: ttk.Frame, title: str) -> ModernStatusCard:
        return ModernStatusCard(parent, title, lambda: not self.reduce_motion.get())

    def _layout_overview_cards(self, event: tk.Event[tk.Misc] | None = None) -> None:
        del event
        width = max(
            self.overview_cards_frame.winfo_width(),
            self.overview_tab.winfo_width() - 32,
        )
        columns = 4 if width >= 1040 else 2 if width >= 520 else 1
        if columns == self.overview_card_columns:
            return
        self.overview_card_columns = columns
        for column in range(4):
            self.overview_cards_frame.columnconfigure(
                column, weight=0, minsize=0, uniform=""
            )
        for column in range(columns):
            self.overview_cards_frame.columnconfigure(
                column, weight=1, minsize=240, uniform="overview"
            )
        for index, card in enumerate(self.overview_cards):
            card.grid_forget()
            row, column = divmod(index, columns)
            card.grid(
                row=row,
                column=column,
                sticky="nsew",
                padx=(0 if column == 0 else 6, 0 if column == columns - 1 else 6),
                pady=(0 if row == 0 else 6, 6),
            )

    def _layout_overview_actions(self, event: tk.Event[tk.Misc] | None = None) -> None:
        del event
        width = max(
            self.overview_actions_row.winfo_width(),
            self.overview_tab.winfo_width() - 68,
        )
        columns = 4 if width >= 780 else 2 if width >= 390 else 1
        if columns == self.overview_action_columns:
            return
        self.overview_action_columns = columns
        for column in range(4):
            self.overview_actions_row.columnconfigure(
                column, weight=0, minsize=0, uniform=""
            )
        for column in range(columns):
            self.overview_actions_row.columnconfigure(
                column, weight=1, minsize=180, uniform="overview-actions"
            )
        for index, button in enumerate(self.overview_action_buttons):
            button.grid_forget()
            row, column = divmod(index, columns)
            button.grid(
                row=row,
                column=column,
                sticky="ew",
                padx=(0 if column == 0 else 4, 0 if column == columns - 1 else 4),
                pady=(0 if row == 0 else 8, 0),
            )

    def _build_scan(self) -> None:
        panel = self._panel(self.scan_tab)
        panel.pack(fill=tk.BOTH, expand=True)
        ttk.Label(panel, text="On-demand scanner", style="Section.TLabel").pack(anchor=tk.W)
        ttk.Label(
            panel,
            text=(
                "Hashes regular files and checks exact built-in plus verified-feed rules. "
                "Links, reparse points, inaccessible files, oversized files, and skipped "
                "filesystems remain explicit gaps."
            ),
            style="Muted.TLabel",
            wraplength=920,
        ).pack(anchor=tk.W, pady=(4, 14))
        path_row = ttk.Frame(panel, style="Surface.TFrame")
        path_row.pack(fill=tk.X)
        self.scan_path = tk.StringVar(value=str(Path.home() / "Downloads"))
        ttk.Entry(path_row, textvariable=self.scan_path).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(path_row, text="Folder…", command=self._choose_scan_folder).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Button(path_row, text="File…", command=self._choose_scan_file).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        self.scan_quarantine = tk.BooleanVar(value=False)
        self.scan_cross_fs = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            panel,
            text="Explicitly quarantine configured-rule matches into recoverable encrypted storage",
            variable=self.scan_quarantine,
        ).pack(anchor=tk.W, pady=(14, 2))
        ttk.Checkbutton(
            panel,
            text="Cross filesystem/device boundaries (advanced; expands scope and risk)",
            variable=self.scan_cross_fs,
        ).pack(anchor=tk.W, pady=2)
        controls = ttk.Frame(panel, style="Surface.TFrame")
        controls.pack(fill=tk.X, pady=(14, 10))
        self.scan_start_button = ttk.Button(
            controls, text="Start scan", style="Primary.TButton", command=self._start_scan
        )
        self.scan_start_button.pack(side=tk.LEFT)
        self.scan_cancel_button = ttk.Button(
            controls, text="Cancel", command=self._cancel_scan, state=tk.DISABLED
        )
        self.scan_cancel_button.pack(side=tk.LEFT, padx=8)
        self.scan_result_label = ttk.Label(controls, text="Ready", style="Muted.TLabel")
        self.scan_result_label.pack(side=tk.LEFT, padx=8)
        self.scan_output = tk.Text(
            panel,
            height=16,
            bg="#08111f",
            fg=TEXT,
            insertbackground=TEXT,
            relief=tk.FLAT,
            wrap=tk.WORD,
            font=("Cascadia Mono", 9),
        )
        self.scan_output.pack(fill=tk.BOTH, expand=True)
        self.scan_output.insert(tk.END, "No scan has been started from this desktop session.\n")
        self.scan_output.configure(state=tk.DISABLED)

    def _build_monitor(self) -> None:
        panel = self._panel(self.monitor_tab)
        panel.pack(fill=tk.BOTH, expand=True)
        ttk.Label(panel, text="Automatic post-change monitoring", style="Section.TLabel").pack(
            anchor=tk.W
        )
        ttk.Label(
            panel,
            text=(
                "ZSEC starts automatically at sign-in, inspects changes in your protected "
                "folders, reconciles metadata every 5 minutes and performs a complete "
                "cache-independent reconciliation every 24 hours. Defender separately "
                "provides real-time, pre-access protection."
            ),
            style="Warning.TLabel",
            wraplength=920,
        ).pack(anchor=tk.W, pady=(5, 10))
        status_row = ttk.Frame(panel, style="Surface.TFrame")
        status_row.pack(fill=tk.X)
        self.companion_status_label = ttk.Label(
            status_row, text="Companion status not checked", style="Status.TLabel"
        )
        self.companion_status_label.pack(side=tk.LEFT)
        companion_check_button = ttk.Button(
            status_row, text="Check installed companion", command=self.refresh_companion
        )
        companion_check_button.pack(side=tk.RIGHT)
        self.companion_refresh_buttons.append(companion_check_button)
        self.protected_roots_label = ttk.Label(
            panel,
            text="Protected folders: checking installed coverage…",
            style="Muted.TLabel",
            wraplength=920,
        )
        self.protected_roots_label.pack(anchor=tk.W, pady=(8, 0))
        ttk.Separator(panel).pack(fill=tk.X, pady=14)
        ttk.Label(
            panel,
            text="Advanced temporary monitoring session",
            style="Surface.TLabel",
            font=("Segoe UI Semibold", 11),
        ).pack(anchor=tk.W)
        ttk.Label(
            panel,
            text=(
                "Optional diagnostic control; it is not required for normal automatic "
                "protection. The installed companion selects and monitors its protected "
                "folders automatically, starts at Windows sign-in, retries after failure, "
                "and refreshes signed intelligence on its configured schedule."
            ),
            style="Muted.TLabel",
            wraplength=920,
        ).pack(anchor=tk.W, pady=(4, 2))
        row = ttk.Frame(panel, style="Surface.TFrame")
        row.pack(fill=tk.X, pady=(8, 6))
        self.watch_path = tk.StringVar(value=str(Path.home() / "Downloads"))
        ttk.Entry(row, textvariable=self.watch_path).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(row, text="Folder…", command=self._choose_watch_folder).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        self.watch_quarantine = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            panel,
            text="Quarantine configured-rule matches (explicit opt-in)",
            variable=self.watch_quarantine,
        ).pack(anchor=tk.W, pady=4)
        button_row = ttk.Frame(panel, style="Surface.TFrame")
        button_row.pack(fill=tk.X, pady=(8, 8))
        self.watch_start_button = ttk.Button(
            button_row,
            text="Start temporary session",
            style="Primary.TButton",
            command=self._start_watch,
        )
        self.watch_start_button.pack(side=tk.LEFT)
        self.watch_stop_button = ttk.Button(
            button_row, text="Stop", command=self._stop_watch, state=tk.DISABLED
        )
        self.watch_stop_button.pack(side=tk.LEFT, padx=8)
        self.watch_state_label = ttk.Label(button_row, text="Stopped", style="Muted.TLabel")
        self.watch_state_label.pack(side=tk.LEFT, padx=8)
        self.watch_events = tk.Listbox(
            panel,
            bg="#08111f",
            fg=TEXT,
            selectbackground="#155e75",
            relief=tk.FLAT,
            font=("Cascadia Mono", 9),
            height=14,
        )
        self.watch_events.pack(fill=tk.BOTH, expand=True)

    def _build_quarantine(self) -> None:
        panel = self._panel(self.quarantine_tab)
        panel.pack(fill=tk.BOTH, expand=True)
        header = ttk.Frame(panel, style="Surface.TFrame")
        header.pack(fill=tk.X)
        ttk.Label(header, text="Encrypted, recoverable quarantine", style="Section.TLabel").pack(
            side=tk.LEFT
        )
        ttk.Button(header, text="Refresh", command=self.refresh_quarantine).pack(side=tk.RIGHT)
        ttk.Label(
            panel,
            text=(
                "Restore never overwrites an existing destination. The authenticated "
                "recovery copy is retained after restore."
            ),
            style="Muted.TLabel",
        ).pack(anchor=tk.W, pady=(4, 10))
        columns = ("state", "path", "sha256")
        self.quarantine_tree = ttk.Treeview(
            panel, columns=columns, show="headings", selectmode="browse"
        )
        self.quarantine_tree.heading("state", text="State")
        self.quarantine_tree.heading("path", text="Original path")
        self.quarantine_tree.heading("sha256", text="SHA-256")
        self.quarantine_tree.column("state", width=110, stretch=False)
        self.quarantine_tree.column("path", width=560)
        self.quarantine_tree.column("sha256", width=330)
        self.quarantine_tree.pack(fill=tk.BOTH, expand=True)
        ttk.Button(panel, text="Restore selected…", command=self._restore_selected).pack(
            anchor=tk.E, pady=(10, 0)
        )

    def _build_windows_protection(self) -> None:
        panel = self._panel(self.windows_protection_tab)
        panel.pack(fill=tk.BOTH, expand=True)
        header = ttk.Frame(panel, style="Surface.TFrame")
        header.pack(fill=tk.X)
        ttk.Label(
            header,
            text="Windows protection control plane",
            style="Section.TLabel",
        ).pack(side=tk.LEFT)
        windows_refresh_button = ttk.Button(
            header, text="Refresh evidence", command=self.refresh_companion
        )
        windows_refresh_button.pack(side=tk.RIGHT)
        self.companion_refresh_buttons.append(windows_refresh_button)
        ttk.Label(
            panel,
            text=(
                "ZSEC verifies Windows Security Center and Microsoft Defender evidence. "
                "Defender or another registered provider remains the enforcement layer; "
                "these controls never disable a provider, add exclusions, or change "
                "Windows Security registration."
            ),
            style="Muted.TLabel",
            wraplength=900,
        ).pack(anchor=tk.W, pady=(5, 10))
        self.windows_provider_status = ttk.Label(
            panel,
            text="Windows provider evidence is loading…",
            style="Status.TLabel",
            wraplength=900,
        )
        self.windows_provider_status.pack(anchor=tk.W, pady=(0, 10))

        columns = ("control", "evidence")
        self.windows_protection_tree = ttk.Treeview(
            panel,
            columns=columns,
            show="headings",
            height=10,
        )
        self.windows_protection_tree.heading("control", text="Protection control")
        self.windows_protection_tree.heading("evidence", text="Current evidence")
        self.windows_protection_tree.column("control", width=275, stretch=False)
        self.windows_protection_tree.column("evidence", width=660)
        self.windows_protection_tree.pack(fill=tk.BOTH, expand=True)

        actions = ttk.Frame(panel, style="Surface.TFrame")
        actions.pack(fill=tk.X, pady=(12, 0))
        self.defender_update_button = ttk.Button(
            actions,
            text="Update Defender intelligence",
            state=tk.DISABLED,
            command=lambda: self._run_windows_protection_action("UpdateSignatures"),
        )
        self.defender_update_button.pack(side=tk.LEFT)
        self.defender_quick_scan_button = ttk.Button(
            actions,
            text="Run Defender quick scan",
            state=tk.DISABLED,
            command=lambda: self._run_windows_protection_action("QuickScan"),
        )
        self.defender_quick_scan_button.pack(side=tk.LEFT, padx=8)
        self.defender_full_scan_button = ttk.Button(
            actions,
            text="Run Defender full scan…",
            state=tk.DISABLED,
            command=lambda: self._run_windows_protection_action("FullScan"),
        )
        self.defender_full_scan_button.pack(side=tk.LEFT)
        self.windows_action_status = ttk.Label(
            panel,
            text="No Windows protection action has run in this session.",
            style="Muted.TLabel",
            wraplength=900,
        )
        self.windows_action_status.pack(anchor=tk.W, pady=(10, 0))

    def _build_feeds(self) -> None:
        panel = self._panel(self.feeds_tab)
        panel.pack(fill=tk.BOTH, expand=True)
        ttk.Label(panel, text="Scanner rules and advisory updates", style="Section.TLabel").pack(
            anchor=tk.W
        )
        self.feed_status_label = ttk.Label(
            panel, text="Loading feed status…", style="Status.TLabel", wraplength=900
        )
        self.feed_status_label.pack(anchor=tk.W, pady=(12, 5))
        self.feed_detail_label = ttk.Label(panel, text="", style="Muted.TLabel", wraplength=900)
        self.feed_detail_label.pack(anchor=tk.W)

        update_panel = ttk.Frame(panel, style="Alt.TFrame", padding=16)
        update_panel.pack(fill=tk.X, pady=(18, 0))
        update_heading = ttk.Frame(update_panel, style="Alt.TFrame")
        update_heading.pack(fill=tk.X)
        ttk.Label(
            update_heading,
            text="Automatic advisory catalog",
            style="Surface.TLabel",
            background=SURFACE_ALT,
            font=("Segoe UI Semibold", 11),
        ).pack(side=tk.LEFT)
        self.feed_update_state_label = ttk.Label(
            update_heading,
            text="CHECKING STATUS",
            style="Surface.TLabel",
            background=SURFACE_ALT,
            foreground=CYAN,
            font=("Segoe UI Semibold", 9),
        )
        self.feed_update_state_label.pack(side=tk.RIGHT)
        self.feed_update_schedule_label = ttk.Label(
            update_panel,
            text="Waiting for update-service evidence…",
            style="Muted.TLabel",
            background=SURFACE_ALT,
            wraplength=850,
        )
        self.feed_update_schedule_label.pack(anchor=tk.W, pady=(8, 2))
        self.feed_update_source_label = ttk.Label(
            update_panel,
            text="Only a pinned ZSEC HTTPS endpoint and a valid signed data payload are accepted.",
            style="Muted.TLabel",
            background=SURFACE_ALT,
            wraplength=850,
        )
        self.feed_update_source_label.pack(anchor=tk.W)
        update_controls = ttk.Frame(update_panel, style="Alt.TFrame")
        update_controls.pack(fill=tk.X, pady=(12, 0))
        self.feed_update_refresh_button = ttk.Button(
            update_controls,
            text="Refresh update evidence",
            command=self.refresh_status,
        )
        self.feed_update_refresh_button.pack(side=tk.LEFT)
        ttk.Label(
            update_controls,
            text=(
                "Signed advisory data activates automatically after verification, but it "
                "does not create malware detection rules or remediate the PC. "
                "Application releases remain notification-only and require a reviewed "
                "installer; this interface never treats an unsigned package as trusted."
            ),
            style="Muted.TLabel",
            background=SURFACE_ALT,
            wraplength=650,
            justify=tk.LEFT,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(14, 0))

        ttk.Separator(panel).pack(fill=tk.X, pady=18)
        ttk.Label(
            panel,
            text="Verification contract",
            style="Surface.TLabel",
            font=("Segoe UI Semibold", 11),
        ).pack(anchor=tk.W)
        ttk.Label(
            panel,
            text=(
                "Advisory checks accept data only from the release-owned endpoint. A candidate "
                "must pass Ed25519 signature, sequence, expiry, schema and payload-digest "
                "validation before atomic activation. The last valid feed remains active if a "
                "check fails. Scanner rules are the separately verified feed shown above."
            ),
            style="Muted.TLabel",
            wraplength=900,
        ).pack(anchor=tk.W, pady=(4, 14))
        ttk.Button(
            panel, text="Install reviewed signed feed file…", command=self._choose_feed_file
        ).pack(anchor=tk.W)
        ttk.Label(
            panel,
            text=(
                "Feed verification enforces Ed25519 trust, expiry, maximum validity, "
                "sequence rollback resistance, and exact data-only rule fields."
            ),
            style="Muted.TLabel",
            wraplength=900,
        ).pack(anchor=tk.W, pady=(12, 0))

    def _build_reports(self) -> None:
        panel = self._panel(self.reports_tab)
        panel.pack(fill=tk.BOTH, expand=True)
        header = ttk.Frame(panel, style="Surface.TFrame")
        header.pack(fill=tk.X)
        ttk.Label(header, text="Local scan reports", style="Section.TLabel").pack(side=tk.LEFT)
        ttk.Button(header, text="Refresh", command=self.refresh_reports).pack(side=tk.RIGHT)
        columns = ("generated", "outcome", "size")
        self.report_tree = ttk.Treeview(
            panel, columns=columns, show="tree headings", selectmode="browse"
        )
        self.report_tree.heading("#0", text="Report")
        self.report_tree.heading("generated", text="Generated")
        self.report_tree.heading("outcome", text="Outcome")
        self.report_tree.heading("size", text="Bytes")
        self.report_tree.column("#0", width=310)
        self.report_tree.column("generated", width=190)
        self.report_tree.column("outcome", width=260)
        self.report_tree.column("size", width=100, stretch=False)
        self.report_tree.pack(fill=tk.BOTH, expand=True, pady=(12, 10))
        ttk.Button(panel, text="View validated report", command=self._view_selected_report).pack(
            anchor=tk.E
        )
        support = ttk.Frame(panel, style="Alt.TFrame", padding=14)
        support.pack(fill=tk.X, pady=(14, 0))
        ttk.Label(
            support,
            text="Privacy-bounded support snapshot",
            style="Surface.TLabel",
            background=SURFACE_ALT,
            font=("Segoe UI Semibold", 11),
        ).pack(anchor=tk.W)
        ttk.Label(
            support,
            text=(
                "Export validated protection and automation evidence without file paths, "
                "quarantine contents, user or device identifiers. Nothing is uploaded or "
                "transmitted automatically."
            ),
            style="Muted.TLabel",
            background=SURFACE_ALT,
            wraplength=850,
        ).pack(anchor=tk.W, pady=(4, 10))
        support_controls = ttk.Frame(support, style="Alt.TFrame")
        support_controls.pack(fill=tk.X)
        self.export_support_button = ttk.Button(
            support_controls,
            text="Export support snapshot…",
            command=self._export_support_snapshot,
            state=tk.DISABLED,
        )
        self.export_support_button.pack(side=tk.LEFT)
        self.export_support_status = ttk.Label(
            support_controls,
            text="Waiting for validated status and companion evidence.",
            style="Muted.TLabel",
            background=SURFACE_ALT,
            wraplength=620,
        )
        self.export_support_status.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(12, 0))

    def _build_health(self) -> None:
        panel = self._panel(self.health_tab)
        panel.pack(fill=tk.BOTH, expand=True)
        header = ttk.Frame(panel, style="Surface.TFrame")
        header.pack(fill=tk.X)
        ttk.Label(header, text="Evidence-backed health", style="Section.TLabel").pack(side=tk.LEFT)
        ttk.Button(header, text="Refresh", command=self.refresh_health).pack(side=tk.RIGHT)
        ttk.Label(
            panel,
            text=(
                "Green states are rendered only from validated status contracts. "
                "Scanner health and replacement eligibility remain separate."
            ),
            style="Muted.TLabel",
            wraplength=900,
        ).pack(anchor=tk.W, pady=(4, 10))
        self.health_text = tk.Text(
            panel,
            bg="#08111f",
            fg=TEXT,
            insertbackground=TEXT,
            relief=tk.FLAT,
            wrap=tk.WORD,
            font=("Cascadia Mono", 9),
        )
        self.health_text.pack(fill=tk.BOTH, expand=True)
        self.health_text.configure(state=tk.DISABLED)

    def _build_security(self) -> None:
        panel = self._panel(self.security_tab)
        panel.pack(fill=tk.BOTH, expand=True)
        ttk.Label(panel, text="Security and recovery", style="Section.TLabel").pack(anchor=tk.W)
        items = (
            (
                "Automatic quarantine encryption",
                (
                    "Per-object AES-256-GCM with fresh random content keys; the device "
                    "root is protected by Windows DPAPI in the current Windows build."
                ),
            ),
            (
                "ZBA / ZMath scope",
                (
                    "Typed provenance and lifecycle state only. It is not a cipher, "
                    "malware detector, quantum-security proof, or replacement for "
                    "Windows security controls."
                ),
            ),
            (
                "YubiKey recovery",
                (
                    "Designed but not shipped. No button here pretends to enrol a key. "
                    "A future route requires tested FIDO2/WebAuthn PRF support or managed "
                    "PIV, user verification, lost-key drills, revocation, and two "
                    "independent recovery records."
                ),
            ),
            (
                "Secrets and telemetry",
                (
                    "The desktop client does not request an account password, YubiKey "
                    "PIN, file upload, or browsing history. It does not add telemetry "
                    "endpoints."
                ),
            ),
        )
        for title, detail in items:
            card = ttk.Frame(panel, style="Alt.TFrame", padding=14)
            card.pack(fill=tk.X, pady=(12, 0))
            ttk.Label(
                card,
                text=title,
                background=SURFACE_ALT,
                foreground=CYAN,
                font=("Segoe UI Semibold", 11),
            ).pack(anchor=tk.W)
            ttk.Label(
                card,
                text=detail,
                background=SURFACE_ALT,
                foreground=MUTED,
                font=("Segoe UI", 9),
                wraplength=880,
            ).pack(anchor=tk.W, pady=(5, 0))
        self.yubikey_status = ttk.Label(
            panel,
            text=(
                "Hardware-key recovery is not enabled in Community 0.3.22. When "
                "quarantine is explicitly enabled, encryption remains automatic, "
                "authenticated and device-bound."
            ),
            style="Warning.TLabel",
        )
        self.yubikey_status.pack(anchor=tk.W, pady=(18, 0))

    def _build_readiness(self) -> None:
        panel = self._panel(self.readiness_tab)
        panel.pack(fill=tk.BOTH, expand=True)
        header = ttk.Frame(panel, style="Surface.TFrame")
        header.pack(fill=tk.X)
        ttk.Label(
            header, text="Protection assurance", style="Section.TLabel"
        ).pack(side=tk.LEFT)
        ttk.Button(header, text="Refresh", command=self.refresh_readiness).pack(side=tk.RIGHT)
        ttk.Button(
            header,
            text="Run recovery self-test",
            command=self.run_recovery_drill,
        ).pack(side=tk.RIGHT, padx=(0, 8))
        self.readiness_decision = ttk.Label(panel, text="Loading…", style="Danger.TLabel")
        self.readiness_decision.pack(anchor=tk.W, pady=(12, 4))
        self.recovery_drill_status = ttk.Label(
            panel,
            text="Recovery self-test: not run in this session",
            style="Muted.TLabel",
        )
        self.recovery_drill_status.pack(anchor=tk.W, pady=(0, 8))
        ttk.Label(
            panel,
            text=(
                "This page verifies the Windows protection chain and recovery controls. "
                "ZSEC never silently disables Defender, removes providers or creates "
                "security exclusions."
            ),
            style="Muted.TLabel",
            wraplength=900,
        ).pack(anchor=tk.W, pady=(0, 10))
        self.readiness_tree = ttk.Treeview(panel, columns=("title", "evidence"), show="headings")
        self.readiness_tree.heading("title", text="Assurance control")
        self.readiness_tree.heading("evidence", text="Evidence required")
        self.readiness_tree.column("title", width=300)
        self.readiness_tree.column("evidence", width=650)
        self.readiness_tree.pack(fill=tk.BOTH, expand=True)

    def _build_settings(self) -> None:
        panel = self._panel(self.settings_tab)
        panel.pack(fill=tk.BOTH, expand=True)
        ttk.Label(panel, text="Desktop settings", style="Section.TLabel").pack(anchor=tk.W)
        grid = ttk.Frame(panel, style="Surface.TFrame")
        grid.pack(fill=tk.X, pady=(14, 0))
        grid.columnconfigure(1, weight=1)
        ttk.Label(grid, text="State directory", style="Surface.TLabel").grid(
            row=0, column=0, sticky=tk.W, pady=6
        )
        state_value = ttk.Entry(grid)
        state_value.insert(0, str(self.bridge.state_dir))
        state_value.configure(state="readonly")
        state_value.grid(row=0, column=1, sticky=tk.EW, padx=(14, 0), pady=6)
        ttk.Label(grid, text="CLI command", style="Surface.TLabel").grid(
            row=1, column=0, sticky=tk.W, pady=6
        )
        cli_value = ttk.Entry(grid)
        cli_value.insert(0, " ".join(self.bridge.cli_prefix))
        cli_value.configure(state="readonly")
        cli_value.grid(row=1, column=1, sticky=tk.EW, padx=(14, 0), pady=6)
        ttk.Label(grid, text="Maximum file size", style="Surface.TLabel").grid(
            row=2, column=0, sticky=tk.W, pady=6
        )
        self.max_file_mebibytes = tk.IntVar(value=self.desktop_settings.max_file_mebibytes)
        max_box = ttk.Spinbox(
            grid, from_=1, to=16384, textvariable=self.max_file_mebibytes, width=12
        )
        max_box.grid(row=2, column=1, sticky=tk.W, padx=(14, 0), pady=6)
        ttk.Label(grid, text="Interface motion", style="Surface.TLabel").grid(
            row=3, column=0, sticky=tk.W, pady=6
        )
        ttk.Checkbutton(
            grid,
            text="Reduce motion (keeps operation status visible)",
            variable=self.reduce_motion,
            command=self._motion_preference_changed,
        ).grid(row=3, column=1, sticky=tk.W, padx=(14, 0), pady=6)
        ttk.Label(grid, text="Window close button", style="Surface.TLabel").grid(
            row=4, column=0, sticky=tk.W, pady=6
        )
        ttk.Checkbutton(
            grid,
            text="Keep protection available in the notification area",
            variable=self.close_to_tray,
        ).grid(row=4, column=1, sticky=tk.W, padx=(14, 0), pady=6)
        ttk.Label(grid, text="Windows sign-in", style="Surface.TLabel").grid(
            row=5, column=0, sticky=tk.W, pady=6
        )
        ttk.Checkbutton(
            grid,
            text="Start ZSEC Antivirus in the notification area",
            variable=self.start_with_windows,
        ).grid(row=5, column=1, sticky=tk.W, padx=(14, 0), pady=6)
        actions = ttk.Frame(panel, style="Surface.TFrame")
        actions.pack(fill=tk.X, pady=(18, 0))
        ttk.Button(
            actions,
            text="Save settings",
            style="Primary.TButton",
            command=self._save_desktop_settings,
        ).pack(side=tk.LEFT)
        ttk.Button(
            actions,
            text="Restore safe defaults",
            command=self._restore_default_settings,
        ).pack(side=tk.LEFT, padx=(8, 0))
        self.settings_status = ttk.Label(
            panel,
            text=(
                f"Settings recovery notice: {self.settings_load_error}"
                if self.settings_load_error
                else "Settings loaded from local protected application state."
            ),
            style="Warning.TLabel" if self.settings_load_error else "Muted.TLabel",
        )
        self.settings_status.pack(anchor=tk.W, pady=(14, 0))
        ttk.Label(
            panel,
            text=(
                "Safety defaults are fixed: quarantine off for each new action, "
                "cross-filesystem traversal off, no provider changes, no Windows Security "
                "registration, and no remote feed URL entry."
            ),
            style="Warning.TLabel",
            wraplength=900,
        ).pack(anchor=tk.W, pady=(18, 0))

    def _run_async(
        self,
        operation: Callable[[], Any],
        success: Callable[[Any], None],
        *,
        failure: Callable[[BaseException], None] | None = None,
    ) -> Future[Any]:
        self.busy_operations += 1
        if self.busy_operations == 1:
            if not self.global_busy_visible:
                self.global_busy.pack(side=tk.RIGHT, pady=8)
                self.global_busy_visible = True
            self._sync_global_busy_motion()
            self._animate_activity()
        future = self.executor.submit(operation)

        def done(completed: Future[Any]) -> None:
            def deliver() -> None:
                if self.closing:
                    return
                self.busy_operations = max(0, self.busy_operations - 1)
                if self.busy_operations == 0:
                    self.global_busy.stop()
                    self.global_busy.pack_forget()
                    self.global_busy_visible = False
                    if self.animation_job is not None:
                        with contextlib.suppress(tk.TclError):
                            self.root.after_cancel(self.animation_job)
                        self.animation_job = None
                    self._animate_activity()
                try:
                    value = completed.result()
                except BaseException as exc:
                    if failure is not None:
                        failure(exc)
                    else:
                        messagebox.showerror(
                            "ZSEC operation failed", str(exc)[:1200], parent=self.root
                        )
                    return
                success(value)

            self._post(deliver)

        future.add_done_callback(done)
        return future

    def _motion_preference_changed(self) -> None:
        if self.animation_job is not None:
            with contextlib.suppress(tk.TclError):
                self.root.after_cancel(self.animation_job)
            self.animation_job = None
        self.animation_phase = 0
        if hasattr(self, "overview_cards"):
            for card in self.overview_cards:
                card.sync_motion_preference()
        if hasattr(self, "global_busy"):
            self._sync_global_busy_motion()
        self._animate_activity()

    def _sync_global_busy_motion(self) -> None:
        self.global_busy.stop()
        if self.busy_operations <= 0:
            return
        if bool(self.reduce_motion.get()):
            self.global_busy.configure(mode="determinate", value=100)
        else:
            self.global_busy.configure(mode="indeterminate", value=0)
            self.global_busy.start(12)

    def _save_desktop_settings(self) -> None:
        try:
            maximum = int(self.max_file_mebibytes.get())
            if not 1 <= maximum <= 16384:
                raise ValueError("Maximum file size must be between 1 and 16384 MiB.")
            requested = DesktopSettings(
                close_to_tray=bool(self.close_to_tray.get()),
                start_with_windows=bool(self.start_with_windows.get()),
                reduce_motion=bool(self.reduce_motion.get()),
                max_file_mebibytes=maximum,
            )
            previous_startup, startup_error = self.startup_registration.current()
            if startup_error is not None and requested.start_with_windows:
                raise OSError(startup_error)
            self.startup_registration.set_enabled(requested.start_with_windows)
            try:
                save_settings(self.bridge.state_dir, requested)
            except BaseException:
                with contextlib.suppress(OSError):
                    self.startup_registration.set_enabled(previous_startup)
                raise
            self.desktop_settings = requested
            self.settings_status.configure(
                text="Settings saved and Windows startup ownership verified.",
                foreground=GREEN,
            )
            self._motion_preference_changed()
        except (OSError, ValueError, tk.TclError) as exc:
            self.settings_status.configure(text=f"Settings not saved: {exc}", foreground=RED)

    def _restore_default_settings(self) -> None:
        defaults = DesktopSettings()
        self.close_to_tray.set(defaults.close_to_tray)
        self.start_with_windows.set(defaults.start_with_windows)
        self.reduce_motion.set(defaults.reduce_motion)
        self.max_file_mebibytes.set(defaults.max_file_mebibytes)
        self._save_desktop_settings()

    def _open_window(self) -> None:
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _open_settings(self) -> None:
        self._open_window()
        self._select_tab(self.settings_tab)

    def _window_unmapped(self, _event: tk.Event[tk.Misc]) -> None:
        if self.closing or not hasattr(self, "tray") or not self.tray.active:
            return
        self.root.after(80, self._hide_if_minimized)

    def _hide_if_minimized(self) -> None:
        if not self.closing and self.root.state() == "iconic" and self.tray.active:
            self.root.withdraw()

    def _window_close(self) -> None:
        if bool(self.close_to_tray.get()) and self.tray.active:
            self.root.withdraw()
            self.tray.notify(
                "ZSEC Antivirus is still running. Use the tray menu to scan, open, or exit."
            )
            return
        self._exit_application()

    def _update_tray_status(self) -> None:
        if hasattr(self, "tray"):
            self.tray.set_status(f"{self.tray_scan_status}; {self.tray_companion_status}")

    def _tray_scan_protected_folders(self) -> None:
        self._scan_protected_folders(from_tray=True)

    def _scan_protected_folders(self, *, from_tray: bool = False) -> None:
        if self.scan_cancel is not None:
            self.tray.notify("A scan is already running.")
            return
        roots = tuple(path for path in self.protected_roots if path.is_dir())
        if not roots:
            self.tray.notify(
                "Protected-folder evidence is not available yet. Open ZSEC and refresh."
            )
            return
        self.scan_quarantine.set(False)
        self.scan_cross_fs.set(False)
        self._begin_scan(roots, "protected folders")
        self.tray_scan_status = "Scanning protected folders"
        self._update_tray_status()
        if not from_tray:
            self._select_tab(self.scan_tab)

    def _animate_activity(self) -> None:
        if self.closing:
            return
        reduced = bool(self.reduce_motion.get())
        working = self.busy_operations > 0
        colour = CYAN if working else MUTED
        status = "VERIFYING LOCAL EVIDENCE" if working else "LOCAL ENGINE IDLE"
        self.activity_canvas.delete("activity")
        if reduced:
            self.activity_canvas.create_oval(
                8, 10, 28, 30, outline=colour, width=3, tags="activity"
            )
        else:
            pulse = 2.0 + 2.0 * ((math.sin(math.radians(self.animation_phase)) + 1.0) / 2.0)
            self.activity_canvas.create_oval(
                11 - pulse,
                13 - pulse,
                25 + pulse,
                27 + pulse,
                outline=colour,
                width=1,
                tags="activity",
            )
            self.activity_canvas.create_arc(
                6,
                8,
                30,
                32,
                start=self.animation_phase,
                extent=110,
                style=tk.ARC,
                outline=colour,
                width=3,
                tags="activity",
            )
        self.activity_canvas.create_oval(
            15, 17, 21, 23, fill=colour, outline=colour, tags="activity"
        )
        self.activity_canvas.create_text(
            39,
            20,
            text=status,
            anchor=tk.W,
            fill=colour,
            font=("Segoe UI Semibold", 8),
            tags="activity",
        )
        self.animation_phase = (self.animation_phase + 12) % 360
        if working and not reduced:
            self.animation_job = self.root.after(80, self._animate_activity)
        else:
            self.animation_job = None

    def refresh_all(self) -> None:
        self.refresh_status()
        self.refresh_readiness()
        self.refresh_quarantine()
        self.refresh_reports()
        self.refresh_companion()

    def _set_initial_evidence_state(self) -> None:
        """Describe startup work without implying either health or failure."""

        self.scan_card.set_value("Checking scan evidence…", CYAN)
        self.feed_card.set_value("Checking signed intelligence…", CYAN)
        self.quarantine_card.set_value("Checking recovery entries…", CYAN)
        self.companion_card.set_value("Verifying local companion…", CYAN)
        self.windows_card.set_value("Verifying Windows protection…", CYAN)

    def _startup_evidence_deadline(self) -> None:
        """Replace an unusually long neutral wait with an honest review state."""

        self.startup_evidence_deadline_job = None
        if self.closing:
            return
        if not self.startup_status_resolved:
            self.scan_card.set_value("Scan verification taking longer", AMBER)
            self.feed_card.set_value("Intelligence verification taking longer", AMBER)
            self.quarantine_card.set_value("Recovery verification taking longer", AMBER)
        if not self.startup_companion_resolved:
            self.companion_card.set_value("Companion verification taking longer", AMBER)
            self.windows_card.set_value("Windows verification taking longer", AMBER)

    def _resolve_startup_evidence(self, group: str) -> None:
        if group == "status":
            self.startup_status_resolved = True
        elif group == "companion":
            self.startup_companion_resolved = True
        else:  # pragma: no cover - internal programming guard
            raise ValueError(f"unknown startup evidence group: {group}")
        if (
            self.startup_status_resolved
            and self.startup_companion_resolved
            and self.startup_evidence_deadline_job is not None
        ):
            with contextlib.suppress(tk.TclError):
                self.root.after_cancel(self.startup_evidence_deadline_job)
            self.startup_evidence_deadline_job = None

    def refresh_status(self) -> None:
        if hasattr(self, "feed_update_refresh_button"):
            self.feed_update_refresh_button.configure(state=tk.DISABLED)
        self._run_async(self.bridge.status, self._render_status, failure=self._status_failure)

    def _status_failure(self, exc: BaseException) -> None:
        self._resolve_startup_evidence("status")
        self.latest_status_payload = None
        self._update_support_export_state()
        if hasattr(self, "feed_update_refresh_button"):
            self.feed_update_refresh_button.configure(state=tk.NORMAL)
        self.scan_card.set_value("Evidence unavailable", RED)
        self.feed_card.set_value("Evidence unavailable", RED)
        self.quarantine_card.set_value("Evidence unavailable", RED)
        self.feed_status_label.configure(text=f"Status error: {exc}", foreground=RED)
        self.feed_update_state_label.configure(text="STATUS UNAVAILABLE", foreground=RED)
        self.feed_update_schedule_label.configure(
            text="Automatic-update evidence could not be read."
        )
        self.feed_update_source_label.configure(
            text="The interface does not infer that an update succeeded."
        )
        self.tray_scan_status = "Scan evidence unavailable"
        self._update_tray_status()

    def _render_status(self, result: CommandResult) -> None:
        self._resolve_startup_evidence("status")
        if hasattr(self, "feed_update_refresh_button"):
            self.feed_update_refresh_button.configure(state=tk.NORMAL)
        status = result.payload
        self.latest_status_payload = status
        self._update_support_export_state()
        presentation = status_presentation(status)
        self.tray_scan_status = presentation.headline
        self._update_tray_status()
        self.scan_card.set_value(presentation.headline, presentation.accent)
        feed = status["feed"]
        feed_text = f"{feed['state'].upper()} — {feed.get('rules_count', 0)} verified rule(s)"
        feed_colour = (
            GREEN if feed["state"] == "valid" else AMBER if feed["state"] == "absent" else RED
        )
        update_view = update_presentation(status.get("update_status"))
        update_colour = {
            "green": GREEN, "cyan": CYAN, "amber": AMBER, "red": RED
        }[update_view.accent]
        self.feed_card.set_value(update_view.headline, update_colour)
        self.quarantine_card.set_value(
            (
                f"{status['quarantine_count']} recovery "
                f"entr{'y' if status['quarantine_count'] == 1 else 'ies'}"
            ),
            CYAN,
        )
        self.feed_status_label.configure(text=feed_text, foreground=feed_colour)
        detail = f"Definitions: {status['definitions']}"
        detail += " | worker: bounded rules plus review-only PE/script/archive providers"
        if feed.get("expires_at"):
            detail += f" | expires {feed['expires_at']}"
        if feed.get("error"):
            detail += f" | error: {feed['error']}"
        self.feed_detail_label.configure(text=detail)
        self._render_update_status(status)
        self._render_health_payload(status)

    def _render_update_status(self, status: dict[str, Any]) -> None:
        """Render optional automatic-update evidence without inventing a healthy state."""

        update = status.get("update_status")
        if not isinstance(update, dict):
            self.feed_update_state_label.configure(text="EVIDENCE UNAVAILABLE", foreground=AMBER)
            self.feed_update_schedule_label.configure(
                text="This engine did not return automatic-update status evidence."
            )
            self.feed_update_source_label.configure(
                text=(
                    "The installed signed feed remains visible above; no update success "
                    "is inferred."
                )
            )
            return

        update_view = update_presentation(update)
        colour = {"green": GREEN, "cyan": CYAN, "amber": AMBER, "red": RED}[
            update_view.accent
        ]
        self.feed_update_state_label.configure(
            text=update_view.headline.upper(), foreground=colour
        )
        last_checked = str(update.get("last_checked_at") or "not yet recorded")
        last_success = str(update.get("last_success_at") or "not yet recorded")
        next_check = str(update.get("next_check_at") or "not scheduled")
        self.feed_update_schedule_label.configure(
            text=(
                f"Last checked: {last_checked}  ·  Last valid update: {last_success}  ·  "
                f"Next check: {next_check}"
            )
        )
        source = str(update.get("source") or "pinned endpoint not reported")
        sequence = update.get("feed_sequence")
        expires = str(update.get("feed_expires_at") or "not reported")
        sequence_text = str(sequence) if sequence is not None else "not reported"
        evidence = update_view.detail + "  ·  " + (
            f"Source: {source}  ·  Advisory sequence: {sequence_text}  ·  Expires: {expires}"
        )
        error = update.get("error")
        if error:
            evidence += f"  ·  Last error: {error}"
        self.feed_update_source_label.configure(text=evidence)

    def refresh_health(self) -> None:
        self.refresh_status()
        self.refresh_companion()

    def _render_health_payload(self, status: dict[str, Any]) -> None:
        view = {
            "schema": status["schema"],
            "generated_at": status["generated_at"],
            "engine_version": status["version"],
            "scanner_mode": status["scanner_mode"],
            "content_worker": status["content_worker"],
            "real_time_protection": status["real_time_protection"],
            "last_scan": status["last_scan"],
            "last_scan_outcome": status["last_scan_outcome"],
            "last_scan_errors": status["last_scan_errors"],
            "findings": status["findings"],
            "observations": status["observations"],
            "feed": status["feed"],
            "quarantine": status["quarantine"],
            "inventory": status["inventory"],
        }
        self._set_text(
            self.health_text, json.dumps(view, indent=2, sort_keys=True, ensure_ascii=False)
        )

    def _choose_scan_folder(self) -> None:
        chosen = filedialog.askdirectory(parent=self.root, title="Choose folder to scan")
        if chosen:
            self.scan_path.set(chosen)

    def _choose_scan_file(self) -> None:
        chosen = filedialog.askopenfilename(parent=self.root, title="Choose file to scan")
        if chosen:
            self.scan_path.set(chosen)

    def _start_scan(self) -> None:
        path = Path(self.scan_path.get().strip())
        self._begin_scan((path,), str(path))

    def _begin_scan(self, paths: tuple[Path, ...], label: str) -> None:
        try:
            max_bytes = int(self.max_file_mebibytes.get()) * 1024 * 1024
        except (tk.TclError, ValueError):
            messagebox.showerror(
                "Invalid size",
                "Maximum file size must be an integer number of MiB.",
                parent=self.root,
            )
            return
        quarantine = bool(self.scan_quarantine.get())
        cross_filesystems = bool(self.scan_cross_fs.get())
        if quarantine and not messagebox.askyesno(
            "Confirm recoverable quarantine",
            (
                "Configured-rule matches will be encrypted into recoverable quarantine "
                "and the matching original will be removed only after verification. "
                "Continue?"
            ),
            parent=self.root,
        ):
            return
        report_path = self.bridge.new_report_path()
        self.scan_cancel = threading.Event()
        self.scan_start_button.configure(state=tk.DISABLED)
        self.scan_cancel_button.configure(state=tk.NORMAL)
        self.scan_result_label.configure(text="Scanning…", foreground=CYAN)
        display_paths = "\n".join(f"  • {path}" for path in paths)
        self._set_text(
            self.scan_output,
            f"Scanning {label}\n{display_paths}\nReport target: {report_path}\n",
        )

        def operation() -> CommandResult:
            assert self.scan_cancel is not None
            return self.bridge.scan(
                list(paths),
                quarantine=quarantine,
                max_file_bytes=max_bytes,
                cross_filesystems=cross_filesystems,
                report_path=report_path,
                cancel=self.scan_cancel,
            )

        self._run_async(operation, self._scan_complete, failure=self._scan_failed)

    def _scan_complete(self, result: CommandResult) -> None:
        self.scan_start_button.configure(state=tk.NORMAL)
        self.scan_cancel_button.configure(state=tk.DISABLED)
        self.scan_cancel = None
        report = result.payload
        scan = report["scan"]
        summary = (
            f"Outcome: {report['outcome']}\n"
            f"Files hashed: {scan['stats'].get('files_hashed', 0)}\n"
            f"Bytes hashed: {scan['stats'].get('bytes_hashed', 0)}\n"
            f"Findings: {len(scan['findings'])}\n"
            f"Review-only observations: {len(scan['observations'])}\n"
            f"Issues: {len(scan['issues'])}\n\n"
        )
        for finding in scan["findings"]:
            summary += f"MATCH {finding.get('severity', 'unknown').upper()} {finding.get('path')}\n"
        for observation in scan["observations"]:
            summary += (
                f"REVIEW {observation.get('severity', 'unknown').upper()} "
                f"{observation.get('path')} — {observation.get('provider')}:"
                f"{observation.get('category')} (never auto-quarantined)\n"
            )
        for issue in scan["issues"]:
            summary += (
                f"INCOMPLETE {issue.get('path')}: {issue.get('code')}: {issue.get('message')}\n"
            )
        self._set_text(self.scan_output, summary)
        colour = (
            GREEN
            if report["outcome"] == "no_configured_rule_matches"
            else AMBER
            if report["outcome"] == "review_observations"
            else RED
        )
        self.scan_result_label.configure(
            text=report["outcome"].replace("_", " "), foreground=colour
        )
        self.scan_quarantine.set(False)
        self.refresh_status()
        self.refresh_quarantine()
        self.refresh_reports()
        self.tray.notify(f"Scan finished: {report['outcome'].replace('_', ' ')}.")

    def _scan_failed(self, exc: BaseException) -> None:
        self.scan_start_button.configure(state=tk.NORMAL)
        self.scan_cancel_button.configure(state=tk.DISABLED)
        self.scan_cancel = None
        self.scan_result_label.configure(text="Incomplete", foreground=RED)
        self._set_text(
            self.scan_output, f"Scan did not complete: {exc}\nNo clean state is available.\n"
        )
        self.tray_scan_status = "Scan incomplete"
        self._update_tray_status()
        self.tray.notify("Scan did not complete; open ZSEC Antivirus for details.")

    def _cancel_scan(self) -> None:
        if self.scan_cancel is not None:
            self.scan_cancel.set()
            self.scan_result_label.configure(text="Cancelling…", foreground=AMBER)

    def _choose_watch_folder(self) -> None:
        chosen = filedialog.askdirectory(parent=self.root, title="Choose folder to monitor")
        if chosen:
            self.watch_path.set(chosen)

    def _start_watch(self) -> None:
        path = Path(self.watch_path.get().strip())
        if not path.is_dir():
            messagebox.showerror("Invalid folder", "Choose an existing folder.", parent=self.root)
            return
        quarantine = bool(self.watch_quarantine.get())
        if quarantine and not messagebox.askyesno(
            "Confirm monitoring quarantine",
            (
                "Every configured-rule match during this session may be moved into "
                "encrypted recoverable quarantine. Continue?"
            ),
            parent=self.root,
        ):
            return
        self.watch_events.delete(0, tk.END)
        self.watch_session_id = None
        self.watch_last_sequence = 0
        self.watch_last_heartbeat_monotonic = None
        if self.watch_watchdog_job is not None:
            with contextlib.suppress(tk.TclError):
                self.root.after_cancel(self.watch_watchdog_job)
        self.watch_watchdog_job = self.root.after(5_000, self._watch_heartbeat_watchdog)
        try:
            self.watch_session = self.bridge.start_watch(
                [path],
                on_event=lambda event: self._post(self._watch_event, event),
                on_complete=lambda code, error: self._post(self._watch_complete, code, error),
                quarantine=quarantine,
            )
        except BridgeError as exc:
            messagebox.showerror("Could not start monitoring", str(exc), parent=self.root)
            return
        self.watch_start_button.configure(state=tk.DISABLED)
        self.watch_stop_button.configure(state=tk.NORMAL)
        self.watch_state_label.configure(text="Starting…", foreground=CYAN)

    def _watch_event(self, event: dict[str, Any]) -> None:
        name = event["event"]
        session_id = str(event["session_id"])
        sequence = int(event["sequence"])
        if self.watch_session_id is None:
            self.watch_session_id = session_id
        if session_id != self.watch_session_id or sequence <= self.watch_last_sequence:
            self.watch_state_label.configure(
                text="Monitoring evidence rejected — session or sequence integrity failed",
                foreground=RED,
            )
            if self.watch_session is not None:
                self.watch_session.stop()
            return
        self.watch_last_sequence = sequence
        detail = ""
        if name == "scan_completed":
            outcome = event.get("outcome")
            detail = f" outcome={outcome}"
            if outcome == "no_configured_rule_matches":
                self.watch_state_label.configure(
                    text="Latest scan: no configured rule matches",
                    foreground=GREEN,
                )
            elif outcome == "configured_rule_matches_detected":
                self.watch_state_label.configure(
                    text="Configured rule matches detected — review required",
                    foreground=RED,
                )
            elif outcome == "review_observations":
                self.watch_state_label.configure(
                    text="Review-only PE, script, or archive observations found",
                    foreground=AMBER,
                )
            else:
                self.watch_state_label.configure(
                    text="Scan incomplete — coverage is unknown",
                    foreground=RED,
                )
        elif name == "health_issue":
            detail = f" {event.get('code')}: {event.get('message')}"
            self.watch_state_label.configure(
                text="Monitoring degraded — review the health event",
                foreground=RED,
            )
        elif name == "session_started":
            detail = f" backend={event.get('backend_active')}"
            self.watch_state_label.configure(
                text="Observer started — health evidence pending",
                foreground=CYAN,
            )
        elif name == "backend_fallback":
            self.watch_state_label.configure(
                text="Fallback observer active — review backend evidence",
                foreground=AMBER,
            )
        elif name == "health_heartbeat":
            self.watch_last_heartbeat_monotonic = time.monotonic()
            if event["operational_incomplete"]:
                self.watch_state_label.configure(
                    text="Monitoring incomplete — heartbeat reports a coverage gap",
                    foreground=RED,
                )
            else:
                self.watch_state_label.configure(
                    text="Observer active — fresh complete heartbeat received",
                    foreground=GREEN,
                )
        self.watch_events.insert(tk.END, f"{event['sequence']:>5}  {name}{detail}")
        if self.watch_events.size() > 500:
            self.watch_events.delete(0, self.watch_events.size() - 500)
        self.watch_events.yview_moveto(1.0)

    def _watch_heartbeat_watchdog(self) -> None:
        self.watch_watchdog_job = None
        if self.closing or self.watch_session is None:
            return
        last = self.watch_last_heartbeat_monotonic
        if last is not None and time.monotonic() - last > 75:
            self.watch_state_label.configure(
                text="Monitoring evidence stale — coverage is unknown",
                foreground=RED,
            )
        self.watch_watchdog_job = self.root.after(5_000, self._watch_heartbeat_watchdog)

    def _stop_watch(self) -> None:
        if self.watch_session is not None:
            self.watch_session.stop()
            self.watch_state_label.configure(text="Stopping…", foreground=AMBER)

    def _watch_complete(self, exit_code: int, error: str | None) -> None:
        self.watch_session = None
        if self.watch_watchdog_job is not None:
            with contextlib.suppress(tk.TclError):
                self.root.after_cancel(self.watch_watchdog_job)
            self.watch_watchdog_job = None
        self.watch_start_button.configure(state=tk.NORMAL)
        self.watch_stop_button.configure(state=tk.DISABLED)
        self.watch_quarantine.set(False)
        if error:
            self.watch_state_label.configure(text=error, foreground=RED)
        elif exit_code == 1:
            self.watch_state_label.configure(
                text="Completed — configured rule matches require review",
                foreground=RED,
            )
        else:
            self.watch_state_label.configure(
                text="Session ended — no configured rule matches in completed scans",
                foreground=CYAN,
            )

    def refresh_companion(self) -> bool:
        if self.companion_refresh_inflight:
            return False
        self.companion_refresh_inflight = True
        for button in self.companion_refresh_buttons:
            button.configure(state=tk.DISABLED)
        self.companion_refresh_generation += 1
        generation = self.companion_refresh_generation
        self._run_async(
            self.bridge.companion_status,
            lambda result: self._render_companion(result, generation),
            failure=lambda exc: self._companion_failure(exc, generation),
        )
        return True

    def _finish_companion_refresh(self, generation: int) -> bool:
        if generation != self.companion_refresh_generation:
            return False
        self.companion_refresh_inflight = False
        for button in self.companion_refresh_buttons:
            button.configure(state=tk.NORMAL)
        return True

    def _periodic_companion_refresh(self) -> None:
        self.companion_refresh_job = None
        if self.closing:
            return
        self.refresh_companion()
        self.companion_refresh_job = self.root.after(
            COMPANION_REFRESH_INTERVAL_MS, self._periodic_companion_refresh
        )

    def _render_companion(self, result: CommandResult, generation: int) -> None:
        if not self._finish_companion_refresh(generation):
            return
        self._resolve_startup_evidence("companion")
        payload = result.payload
        self.latest_companion_payload = payload
        self._update_support_export_state()
        presentation = companion_presentation(payload)
        self.tray_companion_status = presentation.headline
        self._update_tray_status()
        colour = {"green": GREEN, "cyan": CYAN, "amber": AMBER, "red": RED}[
            presentation.accent
        ]
        self.companion_status_label.configure(
            text=f"{presentation.headline} — {presentation.detail}", foreground=colour
        )
        self.companion_card.set_value(presentation.headline, colour)
        record = payload.get("health", {}).get("last_record") or {}
        roots = tuple(
            Path(value)
            for value in record.get("roots", [])
            if isinstance(value, str) and value.strip()
        )
        self.protected_roots = roots
        if roots:
            folder_names = ", ".join(path.name or str(path) for path in roots)
            self.protected_roots_label.configure(
                text=(
                    f"Protected automatically: {folder_names}. Changes are inspected; "
                    "5-minute metadata reconciliation and a 24-hour complete "
                    "reconciliation run without folder selection."
                ),
                foreground=GREEN if payload["healthy"] else AMBER,
            )
            self.scan_protected_button.configure(state=tk.NORMAL)
        else:
            self.protected_roots_label.configure(
                text="Protected-folder coverage could not be verified.", foreground=RED
            )
            self.scan_protected_button.configure(state=tk.DISABLED)
        self._render_windows_protection(payload)

    def _render_windows_protection(self, payload: dict[str, Any]) -> None:
        evidence = payload["existing_primary_protection"]
        defender = evidence["defender"]
        aggregate_good = bool(evidence["aggregate_good"])
        defender_active = bool(defender["confirmed_active"])
        if aggregate_good and defender_active:
            headline = "Windows Security reports GOOD; Defender real-time controls are confirmed."
            colour = GREEN
            self.windows_card.set_value("Defender enforcement verified", GREEN)
        elif aggregate_good:
            headline = (
                "Windows Security reports GOOD; Defender is not the confirmed active "
                "real-time provider."
            )
            colour = AMBER
            self.windows_card.set_value("Registered antivirus reports healthy", GREEN)
        else:
            headline = "Windows antivirus aggregate health is not confirmed GOOD."
            colour = RED
            self.windows_card.set_value("Provider health unconfirmed", RED)
        self.windows_provider_status.configure(text=headline, foreground=colour)

        products = evidence["registered_products"]
        product_names = ", ".join(item["display_name"] for item in products) or "None observed"
        services = ", ".join(
            f"{service['name']}={service['status']}" for service in evidence["security_services"]
        )
        signatures = defender["signatures"]
        scans = defender["scans"]
        cutover = windows_cutover_presentation(payload)

        def enabled(value: Any) -> str:
            if value is None:
                return "Unavailable"
            return "Enabled" if value is True else "Disabled"

        def yes_no(value: Any) -> str:
            if value is None:
                return "Unavailable"
            return "Yes" if value is True else "No"

        signature_detail = (
            f"Version {signatures['antivirus_version'] or 'unavailable'}; "
            f"updated {signatures['antivirus_last_updated'] or 'unavailable'}; "
            f"provider reports out-of-date: "
            f"{yes_no(signatures['defender_reports_out_of_date'])}"
        )
        rows = (
            ("Windows Security aggregate", evidence["aggregate_health"]),
            (
                "Registered antivirus products",
                product_names + " (raw registrations; active selection is not inferred)",
            ),
            (
                "Defender real-time enforcement",
                "Confirmed active" if defender_active else "Not confirmed active",
            ),
            (
                "Defender baseline features",
                (
                    f"Behavior {enabled(defender['behavior_monitor_enabled'])}; "
                    f"download/attachment {enabled(defender['ioav_protection_enabled'])}; "
                    f"on-access {enabled(defender['on_access_protection_enabled'])}; "
                    f"network inspection {enabled(defender['network_inspection_enabled'])}"
                ),
            ),
            ("Defender tamper protection", defender["tamper_protection"].capitalize()),
            ("Defender security intelligence", signature_detail),
            (
                "Last Defender quick scan",
                scans["quick_scan_end"] or "No supported timestamp available",
            ),
            (
                "Last Defender full scan",
                scans["full_scan_end"] or "No supported timestamp available",
            ),
            ("Windows security services", services),
            (
                "Provider handoff interlock",
                f"{cutover.headline} — {cutover.detail}",
            ),
        )
        for item in self.windows_protection_tree.get_children():
            self.windows_protection_tree.delete(item)
        for control, value in rows:
            self.windows_protection_tree.insert("", tk.END, values=(control, value))
        self.defender_update_button.configure(
            state=tk.NORMAL if defender["available"] else tk.DISABLED
        )
        scan_state = tk.NORMAL if defender_active else tk.DISABLED
        self.defender_quick_scan_button.configure(state=scan_state)
        self.defender_full_scan_button.configure(state=scan_state)

    def _run_windows_protection_action(self, action: str) -> None:
        if action == "FullScan" and not messagebox.askyesno(
            "Run a Defender full scan?",
            (
                "A full scan can take considerable time and CPU. It does not change the "
                "active antivirus provider. Continue?"
            ),
            parent=self.root,
        ):
            return
        labels = {
            "UpdateSignatures": "Updating Microsoft Defender security intelligence…",
            "QuickScan": "Microsoft Defender quick scan is running…",
            "FullScan": "Microsoft Defender full scan is running…",
        }
        self.windows_action_status.configure(text=labels[action], foreground=CYAN)
        for button in (
            self.defender_update_button,
            self.defender_quick_scan_button,
            self.defender_full_scan_button,
        ):
            button.configure(state=tk.DISABLED)
        self._run_async(
            lambda: self.bridge.windows_protection_action(action),
            self._render_windows_protection_action,
            failure=self._windows_protection_action_failure,
        )

    def _render_windows_protection_action(self, result: CommandResult) -> None:
        payload = result.payload
        if payload["outcome"] == "completed":
            action_name = {
                "UpdateSignatures": "Defender intelligence update",
                "QuickScan": "Defender quick scan",
                "FullScan": "Defender full scan",
            }[payload["action"]]
            self.windows_action_status.configure(
                text=f"{action_name} completed; refreshing provider evidence.",
                foreground=GREEN,
            )
        else:
            self.windows_action_status.configure(
                text=f"Windows protection action failed: {payload['error']}",
                foreground=RED,
            )
        self.refresh_companion()

    def _windows_protection_action_failure(self, exc: BaseException) -> None:
        self.windows_action_status.configure(
            text=f"Windows protection action could not be verified: {exc}",
            foreground=RED,
        )
        self.refresh_companion()

    def _companion_failure(self, exc: BaseException, generation: int) -> None:
        if not self._finish_companion_refresh(generation):
            return
        self.latest_companion_payload = None
        self._update_support_export_state()
        self._resolve_startup_evidence("companion")
        self.companion_status_label.configure(
            text=f"Companion evidence unavailable: {exc}", foreground=RED
        )
        self.companion_card.set_value("Evidence unavailable", RED)
        self.windows_card.set_value("Evidence unavailable", RED)
        self.windows_provider_status.configure(
            text=f"Windows provider evidence unavailable: {exc}", foreground=RED
        )
        for button in (
            self.defender_update_button,
            self.defender_quick_scan_button,
            self.defender_full_scan_button,
        ):
            button.configure(state=tk.DISABLED)
        self.tray_companion_status = "Companion evidence unavailable"
        self._update_tray_status()

    def refresh_quarantine(self) -> None:
        self._run_async(
            self.bridge.quarantine_entries, self._render_quarantine, failure=lambda exc: None
        )

    def _render_quarantine(self, result: CommandResult) -> None:
        self.quarantine_rows.clear()
        for item in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(item)
        for entry in result.payload["entries"]:
            entry_id = str(entry["id"])
            self.quarantine_rows[entry_id] = entry
            self.quarantine_tree.insert(
                "",
                tk.END,
                iid=entry_id,
                values=(entry["state"], entry["original_path"], entry["sha256"]),
            )

    def _restore_selected(self) -> None:
        selection = self.quarantine_tree.selection()
        if not selection:
            messagebox.showinfo(
                "Choose an entry", "Select one quarantine entry to restore.", parent=self.root
            )
            return
        entry_id = selection[0]
        entry = self.quarantine_rows[entry_id]
        destination = filedialog.asksaveasfilename(
            parent=self.root,
            title="Restore to a new path",
            initialfile=Path(entry["original_path"]).name,
        )
        if not destination:
            return
        if not messagebox.askyesno(
            "Confirm restore",
            (
                f"Restore the authenticated recovery copy to:\n{destination}\n\n"
                "The destination must not already exist."
            ),
            parent=self.root,
        ):
            return
        self._run_async(
            lambda: self.bridge.restore_quarantine(entry_id, Path(destination)),
            lambda result: self._restore_complete(result),
        )

    def _restore_complete(self, result: CommandResult) -> None:
        messagebox.showinfo(
            "Restore verified",
            f"Restored to {result.payload['destination']}. The recovery copy was retained.",
            parent=self.root,
        )
        self.refresh_quarantine()

    def _choose_feed_file(self) -> None:
        chosen = filedialog.askopenfilename(
            parent=self.root,
            title="Choose a reviewed signed feed",
            filetypes=(("JSON feed", "*.json"), ("All files", "*.*")),
        )
        if not chosen:
            return
        if not messagebox.askyesno(
            "Install signed feed",
            (
                "The file will be accepted only if its Ed25519 signature, trust key, "
                "expiry, schema, and rollback sequence validate. Continue?"
            ),
            parent=self.root,
        ):
            return
        self._run_async(lambda: self.bridge.update_feed_file(Path(chosen)), self._feed_updated)

    def _feed_updated(self, result: CommandResult) -> None:
        payload = result.payload
        messagebox.showinfo(
            "Feed verified",
            (
                f"Feed {payload['outcome']}: sequence {payload['sequence']}, "
                f"{payload['rules_count']} rules."
            ),
            parent=self.root,
        )
        self.refresh_status()

    def refresh_reports(self) -> None:
        self._run_async(self.bridge.list_reports, self._render_reports, failure=lambda exc: None)

    def _update_support_export_state(self) -> None:
        if not hasattr(self, "export_support_button"):
            return
        ready = self.latest_status_payload is not None and self.latest_companion_payload is not None
        self.export_support_button.configure(state=tk.NORMAL if ready else tk.DISABLED)
        if ready:
            self.export_support_status.configure(
                text="Validated evidence is ready for a local, user-chosen JSON export.",
                foreground=GREEN,
            )
        else:
            self.export_support_status.configure(
                text="Waiting for validated status and companion evidence.",
                foreground=MUTED,
            )

    def _export_support_snapshot(self) -> None:
        status = self.latest_status_payload
        companion = self.latest_companion_payload
        if status is None or companion is None:
            self._update_support_export_state()
            return
        destination = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export privacy-bounded support snapshot",
            defaultextension=".json",
            filetypes=(("JSON files", "*.json"),),
            initialfile="zsec-antivirus-support-snapshot.json",
        )
        if not destination:
            self.export_support_status.configure(
                text="Export cancelled; no file was written or transmitted.", foreground=MUTED
            )
            return
        try:
            snapshot = build_support_snapshot(
                status,
                companion,
                desktop_version=ZSEC_VERSION,
            )
            target = Path(destination)
            save_support_snapshot(target, snapshot)
        except (OSError, TypeError, ValueError) as exc:
            self.export_support_status.configure(
                text=f"Support snapshot export failed: {exc}", foreground=RED
            )
            return
        self.export_support_status.configure(
            text=f"Support snapshot saved locally: {target.name}. Nothing was uploaded.",
            foreground=GREEN,
        )

    def _render_reports(self, reports: list[dict[str, Any]]) -> None:
        self.report_rows.clear()
        for item in self.report_tree.get_children():
            self.report_tree.delete(item)
        for index, report in enumerate(reports):
            item_id = f"report-{index}"
            self.report_rows[item_id] = Path(report["path"])
            self.report_tree.insert(
                "",
                tk.END,
                iid=item_id,
                text=report["name"],
                values=(
                    report["generated_at"] or "—",
                    report["outcome"],
                    report["size"] if report["size"] is not None else "—",
                ),
            )

    def _view_selected_report(self) -> None:
        selection = self.report_tree.selection()
        if not selection:
            messagebox.showinfo("Choose a report", "Select one report to view.", parent=self.root)
            return
        path = self.report_rows[selection[0]]
        self._run_async(
            lambda: self.bridge.read_report(path),
            lambda report: self._show_json("Validated scan report", report),
        )

    def _show_json(self, title: str, payload: dict[str, Any]) -> None:
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("900x650")
        window.configure(bg=BACKGROUND)
        text = tk.Text(
            window,
            bg="#08111f",
            fg=TEXT,
            insertbackground=TEXT,
            relief=tk.FLAT,
            wrap=tk.NONE,
            font=("Cascadia Mono", 9),
        )
        text.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        text.insert(tk.END, json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
        text.configure(state=tk.DISABLED)

    def refresh_readiness(self) -> None:
        self._run_async(
            self.bridge.replacement_readiness,
            self._render_readiness,
            failure=self._readiness_failure,
        )

    def run_recovery_drill(self) -> None:
        self.recovery_drill_status.configure(
            text="Recovery self-test: running on isolated synthetic data…",
            foreground=CYAN,
        )
        self._run_async(
            self.bridge.recovery_drill,
            self._render_recovery_drill,
            failure=self._recovery_drill_failure,
        )

    def _render_recovery_drill(self, result: CommandResult) -> None:
        payload = result.payload
        summary = payload["summary"]
        if payload["passed"]:
            self.recovery_drill_status.configure(
                text=(
                    "Recovery self-test: PASSED — "
                    f"{summary['passed']}/{summary['total']} isolated controls verified; "
                    "independent certification remains required"
                ),
                foreground=GREEN,
            )
        else:
            self.recovery_drill_status.configure(
                text=(
                    "Recovery self-test: FAILED — "
                    f"{summary['failed']} control(s) need investigation"
                ),
                foreground=RED,
            )

    def _recovery_drill_failure(self, exc: BaseException) -> None:
        self.recovery_drill_status.configure(
            text=f"Recovery self-test unavailable: {exc}",
            foreground=RED,
        )

    def _render_readiness(self, result: CommandResult) -> None:
        payload = result.payload
        self.readiness_decision.configure(
            text=(
                "KEEP EXISTING PROTECTION — "
                f"{payload['gate_counts']['not_met']} production gate(s) not met"
            ),
            foreground=RED,
        )
        for item in self.readiness_tree.get_children():
            self.readiness_tree.delete(item)
        for gate in payload["blocking_gates"]:
            self.readiness_tree.insert(
                "", tk.END, values=(gate["title"], gate["evidence_required"])
            )

    def _readiness_failure(self, exc: BaseException) -> None:
        self.readiness_decision.configure(
            text=f"READINESS EVIDENCE UNAVAILABLE — keep existing protection: {exc}", foreground=RED
        )

    def _set_text(self, widget: tk.Text, value: str) -> None:
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, value)
        widget.configure(state=tk.DISABLED)

    def _post(self, callback: Callable[..., Any], *arguments: Any) -> None:
        if self.closing:
            return
        self.ui_queue.put((callback, arguments))

    def _drain_ui_queue(self) -> None:
        """Run worker/tray completions only on Tk's owning thread."""

        self.ui_queue_job = None
        if self.closing:
            return
        # Schedule the next drain before invoking callbacks so an unexpected UI
        # callback exception cannot permanently strand later worker completions.
        self.ui_queue_job = self.root.after(20, self._drain_ui_queue)
        for _ in range(128):
            try:
                callback, arguments = self.ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                callback(*arguments)
            except Exception as exc:
                self.root.report_callback_exception(
                    type(exc), exc, exc.__traceback__
                )
            if self.closing:
                return

    def _exit_application(self) -> None:
        self.closing = True
        if self.ui_queue_job is not None:
            with contextlib.suppress(tk.TclError):
                self.root.after_cancel(self.ui_queue_job)
            self.ui_queue_job = None
        if hasattr(self, "tray"):
            self.tray.stop()
        if self.animation_job is not None:
            with contextlib.suppress(tk.TclError):
                self.root.after_cancel(self.animation_job)
            self.animation_job = None
        if self.companion_refresh_job is not None:
            with contextlib.suppress(tk.TclError):
                self.root.after_cancel(self.companion_refresh_job)
            self.companion_refresh_job = None
        if self.startup_evidence_deadline_job is not None:
            with contextlib.suppress(tk.TclError):
                self.root.after_cancel(self.startup_evidence_deadline_job)
            self.startup_evidence_deadline_job = None
        if self.watch_watchdog_job is not None:
            with contextlib.suppress(tk.TclError):
                self.root.after_cancel(self.watch_watchdog_job)
            self.watch_watchdog_job = None
        if self.watch_session is not None:
            self.watch_session.stop()
        if self.scan_cancel is not None:
            self.scan_cancel.set()
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.root.destroy()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Unprivileged ZSEC Antivirus desktop client")
    parser.add_argument("--state-dir", type=Path, default=_default_state_dir())
    parser.add_argument("--cli", type=Path, help="reviewed zero-security/zsec-shield executable")
    parser.add_argument("--companion-status-script", type=Path)
    parser.add_argument("--windows-protection-action-script", type=Path)
    parser.add_argument("--startup", action="store_true", help="start hidden in notification area")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        bridge = ZsecBridge(
            state_dir=args.state_dir,
            cli=args.cli,
            companion_status_script=args.companion_status_script,
            windows_protection_action_script=args.windows_protection_action_script,
        )
    except BridgeError as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("ZSEC Desktop cannot start", str(exc), parent=root)
        root.destroy()
        return 2
    root = tk.Tk()
    ZsecDesktop(root, bridge, startup=bool(args.startup))
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
