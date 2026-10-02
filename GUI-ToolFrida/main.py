"""
GUI-ToolFrida - Master Android CTF Assistant & Frida Studio
Modern Dark-Mode Desktop GUI for Android Reverse Engineering,
ADB Package Management, Root Triage, and Live Frida Dynamic Hooking.
Designed for HackToday & CTF Finalists.
"""

import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Any, Dict, List, Optional

import customtkinter as ctk

from adb_manager import ADBManager
from apk_triage import APKTriage
from frida_runner import FridaRunner
from templates import TEMPLATES

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class FridaCTFAssistant(ctk.CTk):
    """Main Application Window."""

    def __init__(self):
        super().__init__()

        self.title("⚡ Frida Android CTF Assistant - HackToday 2026")
        self.geometry("1180x820")
        self.minsize(1050, 720)

        # Core Managers
        self.adb = ADBManager()
        self.runner = FridaRunner(on_output=self.on_frida_output, on_exit=self.on_frida_exit)
        self.triage = APKTriage(workspace_dir=os.path.join(os.path.dirname(os.path.abspath(__file__)), "triage_workspace"))
        self.log_queue = queue.Queue()

        # State
        self.selected_device_id = None
        self.current_apk_info = {}
        self.last_triage_result = {}
        self.logcat_process = None
        self.logcat_thread = None
        self.is_logcat_running = False

        # Build UI
        self._build_header()
        self._build_tabs()
        self._build_status_bar()

        # Periodic queue processor for thread-safe UI updates
        self.after(100, self._process_log_queue)

        # Initial background status scan
        threading.Thread(target=self.refresh_devices_and_status, daemon=True).start()

    # =========================================================================
    # UI CONSTRUCTION
    # =========================================================================

    def _build_header(self):
        """Top Header Bar with Quick Status Badges and Controls."""
        self.header_frame = ctk.CTkFrame(self, corner_radius=8, fg_color="#181b20")
        self.header_frame.pack(fill="x", padx=14, pady=(12, 6))

        # Title & Subtitle
        title_box = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        title_box.pack(side="left", padx=12, pady=10)
        ctk.CTkLabel(
            title_box,
            text="⚡ FRIDA ANDROID CTF ASSISTANT",
            font=ctk.CTkFont(family="Consolas", size=17, weight="bold"),
            text_color="#38bdf8"
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_box,
            text="Automated APK Installer, Root Inspector & Live Dynamic Hooking Studio",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8"
        ).pack(anchor="w")

        # Right side status badges & controls
        btn_box = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        btn_box.pack(side="right", padx=12, pady=8)

        # Device selector
        ctk.CTkLabel(btn_box, text="Device:", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=(0, 4))
        self.device_combo = ctk.CTkComboBox(
            btn_box,
            values=["Searching..."],
            width=160,
            command=self._on_device_selected
        )
        self.device_combo.pack(side="left", padx=4)

        # Root Badge
        self.root_badge = ctk.CTkLabel(
            btn_box,
            text="Root: ⏳",
            fg_color="#334155",
            corner_radius=6,
            padx=8,
            pady=4,
            font=ctk.CTkFont(size=11, weight="bold")
        )
        self.root_badge.pack(side="left", padx=4)

        # Frida Server Badge
        self.frida_badge = ctk.CTkLabel(
            btn_box,
            text="Frida: ⏳",
            fg_color="#334155",
            corner_radius=6,
            padx=8,
            pady=4,
            font=ctk.CTkFont(size=11, weight="bold")
        )
        self.frida_badge.pack(side="left", padx=4)

        # Quick Actions
        self.btn_refresh = ctk.CTkButton(
            btn_box,
            text="🔄 Refresh",
            width=80,
            fg_color="#0284c7",
            hover_color="#0369a1",
            command=self.refresh_devices_and_status
        )
        self.btn_refresh.pack(side="left", padx=4)

        self.btn_toggle_frida = ctk.CTkButton(
            btn_box,
            text="⚡ Start Frida",
            width=95,
            fg_color="#16a34a",
            hover_color="#15803d",
            command=self.toggle_frida_server
        )
        self.btn_toggle_frida.pack(side="left", padx=4)

    def _build_tabs(self):
        """Tabbed view for APK Manager, Frida Studio, and Device Tools."""
        self.tabview = ctk.CTkTabview(self, corner_radius=8)
        self.tabview.pack(fill="both", expand=True, padx=14, pady=6)

        self.tab_apk = self.tabview.add("📱 APK & App Manager")
        self.tab_hook = self.tabview.add("💉 Frida Hooking Studio")
        self.tab_tools = self.tabview.add("⚙️ Device, Server & Logcat")

        self._build_apk_tab()
        self._build_hook_tab()
        self._build_tools_tab()

    # -------------------------------------------------------------------------
    # TAB 1: APK & APP MANAGER
    # -------------------------------------------------------------------------
    def _build_apk_tab(self):
        # 1. APK File Selection Frame
        apk_box = ctk.CTkFrame(self.tab_apk, corner_radius=8)
        apk_box.pack(fill="x", padx=10, pady=(10, 6))

        ctk.CTkLabel(
            apk_box,
            text="1. PILIH FILE APK TARGET (DARI PC ATAU TARIK DARI EMULATOR):",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#38bdf8"
        ).pack(anchor="w", padx=12, pady=(10, 4))

        picker_row = ctk.CTkFrame(apk_box, fg_color="transparent")
        picker_row.pack(fill="x", padx=12, pady=(0, 10))

        self.apk_entry = ctk.CTkEntry(
            picker_row,
            placeholder_text="Path APK di Windows (atau klik 'Tarik APK' pada daftar di bawah)..."
        )
        self.apk_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            picker_row,
            text="📂 Browse APK",
            width=110,
            command=self._browse_apk
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            picker_row,
            text="⚡ Triage APK (Rev Tool)",
            width=150,
            fg_color="#0d9488",
            hover_color="#0f766e",
            font=ctk.CTkFont(weight="bold"),
            command=self._run_apk_triage
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            picker_row,
            text="📥 Install ke Emu",
            width=120,
            fg_color="#16a34a",
            hover_color="#15803d",
            command=self._install_selected_apk
        ).pack(side="left")

        # 2. Extracted Package Info Card
        self.info_card = ctk.CTkFrame(self.tab_apk, corner_radius=8, fg_color="#1e242c")
        self.info_card.pack(fill="x", padx=10, pady=6)

        info_grid = ctk.CTkFrame(self.info_card, fg_color="transparent")
        info_grid.pack(fill="x", padx=12, pady=10)

        ctk.CTkLabel(info_grid, text="Package Name:", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", pady=2)
        self.lbl_pkg = ctk.CTkLabel(info_grid, text="-", text_color="#a3e635", font=ctk.CTkFont(family="Consolas"))
        self.lbl_pkg.grid(row=0, column=1, sticky="w", padx=10, pady=2)

        ctk.CTkLabel(info_grid, text="Main Activity:", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, sticky="w", pady=2)
        self.lbl_act = ctk.CTkLabel(info_grid, text="-", font=ctk.CTkFont(family="Consolas"))
        self.lbl_act.grid(row=1, column=1, sticky="w", padx=10, pady=2)

        ctk.CTkLabel(info_grid, text="File Size:", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, sticky="w", pady=2)
        self.lbl_size = ctk.CTkLabel(info_grid, text="-")
        self.lbl_size.grid(row=2, column=1, sticky="w", padx=10, pady=2)

        # Quick Control Buttons for this App
        app_ctrl_row = ctk.CTkFrame(self.info_card, fg_color="transparent")
        app_ctrl_row.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkButton(
            app_ctrl_row,
            text="🚀 Buka Aplikasi",
            width=115,
            fg_color="#0284c7",
            command=self._launch_target_app
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            app_ctrl_row,
            text="🛑 Force Stop",
            width=100,
            fg_color="#dc2626",
            hover_color="#b91c1c",
            command=self._force_stop_app
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            app_ctrl_row,
            text="🧹 Clear Data",
            width=100,
            fg_color="#d97706",
            hover_color="#b45309",
            command=self._clear_app_data
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            app_ctrl_row,
            text="📦 Unpack Folder APK",
            width=140,
            fg_color="#475569",
            hover_color="#334155",
            command=self._unpack_apk_folder
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            app_ctrl_row,
            text="💉 Siapkan Hook Frida",
            width=150,
            fg_color="#9333ea",
            hover_color="#7e22ce",
            command=self._send_pkg_to_hook_tab
        ).pack(side="left")

        # 3. Dynamic Triage & Recommendation Card (Rev Tool Integration)
        self.triage_card = ctk.CTkFrame(self.tab_apk, corner_radius=8, fg_color="#0f172a", border_width=1, border_color="#334155")
        # Hidden until triage runs

        # 4. Installed Packages on Emulator
        self.pkg_box = ctk.CTkFrame(self.tab_apk, corner_radius=8)
        self.pkg_box.pack(fill="both", expand=True, padx=10, pady=(6, 10))

        pkg_header = ctk.CTkFrame(self.pkg_box, fg_color="transparent")
        pkg_header.pack(fill="x", padx=12, pady=(10, 4))

        ctk.CTkLabel(
            pkg_header,
            text="DAFTAR APLIKASI DI EMULATOR:",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(side="left", padx=(0, 10))

        self.pkg_filter_var = ctk.StringVar(value="Semua")
        self.pkg_seg_filter = ctk.CTkSegmentedButton(
            pkg_header,
            values=["Semua", "⭐ Target CTF", "👤 User App"],
            variable=self.pkg_filter_var,
            command=lambda v: self._filter_package_list()
        )
        self.pkg_seg_filter.pack(side="left", padx=(0, 10))

        self.pkg_search_entry = ctk.CTkEntry(pkg_header, placeholder_text="Filter nama package...", width=180)
        self.pkg_search_entry.pack(side="right", padx=(6, 0))
        self.pkg_search_entry.bind("<KeyRelease>", lambda e: self._filter_package_list())

        ctk.CTkButton(
            pkg_header,
            text="🔄 Refresh List",
            width=90,
            command=self.refresh_installed_packages
        ).pack(side="right", padx=6)

        # Scrollable list of packages
        self.pkg_list_frame = ctk.CTkScrollableFrame(self.pkg_box, corner_radius=6)
        self.pkg_list_frame.pack(fill="both", expand=True, padx=12, pady=(4, 10))
        self.all_installed_packages = []

    # -------------------------------------------------------------------------
    # TAB 2: FRIDA HOOKING STUDIO
    # -------------------------------------------------------------------------
    def _build_hook_tab(self):
        # Main Paned / Split Layout
        hook_layout = ctk.CTkFrame(self.tab_hook, fg_color="transparent")
        hook_layout.pack(fill="both", expand=True, padx=6, pady=6)

        # Left Column: Controls & Presets
        left_col = ctk.CTkFrame(hook_layout, width=360, corner_radius=8)
        left_col.pack(side="left", fill="y", padx=(0, 6), pady=0)
        left_col.pack_propagate(False)

        ctk.CTkLabel(
            left_col,
            text="TARGET & SCRIPT CONFIG:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#38bdf8"
        ).pack(anchor="w", padx=12, pady=(10, 4))

        # Target package entry
        ctk.CTkLabel(left_col, text="Package Name Target:", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=12, pady=(4, 0))
        self.hook_pkg_entry = ctk.CTkEntry(left_col, placeholder_text="com.example.challenge")
        self.hook_pkg_entry.pack(fill="x", padx=12, pady=(2, 8))

        # Master Auto-Solver Shortcut Button
        self.btn_auto_solver = ctk.CTkButton(
            left_col,
            text="🔥 PILIH AUTO-SOLVER (ALL-IN-ONE)\n(Root Bypass + String + Crypto Sniffer)",
            height=44,
            fg_color="#b45309",
            hover_color="#d97706",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._select_master_auto_solver
        )
        self.btn_auto_solver.pack(fill="x", padx=12, pady=(2, 6))

        # Preset Templates Dropdown
        ctk.CTkLabel(left_col, text="Atau Pilih Template Spesifik:", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=12, pady=(4, 0))
        template_keys = list(TEMPLATES.keys())
        self.template_combo = ctk.CTkComboBox(
            left_col,
            values=template_keys,
            command=self._on_template_selected
        )
        self.template_combo.pack(fill="x", padx=12, pady=(2, 8))
        self.template_combo.set(template_keys[0])

        # Hook Mode Selection (Spawn vs Attach)
        ctk.CTkLabel(left_col, text="Mode Eksekusi Frida:", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=12, pady=(4, 0))
        self.hook_mode_var = ctk.StringVar(value="spawn")

        ctk.CTkRadioButton(
            left_col,
            text="⚡ Spawn (-f) [Rekomendasi CTF]",
            variable=self.hook_mode_var,
            value="spawn"
        ).pack(anchor="w", padx=14, pady=2)

        ctk.CTkRadioButton(
            left_col,
            text="🔗 Attach (-n) [Aplikasi Sudah Buka]",
            variable=self.hook_mode_var,
            value="attach"
        ).pack(anchor="w", padx=14, pady=2)

        # Live Real-time Status Card
        self.hook_state_frame = ctk.CTkFrame(left_col, fg_color="#111827", corner_radius=6, border_width=1, border_color="#334155")
        self.hook_state_frame.pack(fill="x", padx=12, pady=(6, 10))

        self.lbl_hook_state = ctk.CTkLabel(
            self.hook_state_frame,
            text="⚪ STATUS: IDLE / STANDBY\n(Klik 'START HOOK' lalu buka app di emulator)",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#94a3b8",
            justify="center"
        )
        self.lbl_hook_state.pack(padx=8, pady=8)

        # Script File Actions
        file_action_row = ctk.CTkFrame(left_col, fg_color="transparent")
        file_action_row.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkButton(
            file_action_row,
            text="📂 Load JS",
            width=90,
            command=self._load_custom_js
        ).pack(side="left", padx=(0, 4))

        ctk.CTkButton(
            file_action_row,
            text="💾 Save JS",
            width=90,
            command=self._save_editor_js
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            file_action_row,
            text="🧹 Clear Log",
            width=80,
            fg_color="#475569",
            hover_color="#334155",
            command=self._clear_console
        ).pack(side="right")

        # Big Launch Buttons
        self.btn_run_hook = ctk.CTkButton(
            left_col,
            text="▶ START HOOK (RUN FRIDA)",
            height=44,
            fg_color="#16a34a",
            hover_color="#15803d",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.start_frida_hook
        )
        self.btn_run_hook.pack(fill="x", padx=12, pady=(10, 6))

        self.btn_stop_hook = ctk.CTkButton(
            left_col,
            text="⏹ STOP HOOK",
            height=36,
            fg_color="#dc2626",
            hover_color="#b91c1c",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self.stop_frida_hook,
            state="disabled"
        )
        self.btn_stop_hook.pack(fill="x", padx=12, pady=(0, 10))

        # Quick Tip
        tip_box = ctk.CTkFrame(left_col, fg_color="#1e242c", corner_radius=6)
        tip_box.pack(fill="x", padx=12, pady=(10, 0))
        ctk.CTkLabel(
            tip_box,
            text="💡 TIPS CTF:\n1. Pilih template 'String_Equals_Sniffer'\n2. Klik Start Hook\n3. Buka app di emulator & ketik flag acak\n4. Flag asli langsung muncul di console!",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8",
            justify="left"
        ).pack(padx=8, pady=8)

        # Right Column: Live Frida Console (Full height by default) + Collapsible Editor
        right_col = ctk.CTkFrame(hook_layout, fg_color="transparent")
        right_col.pack(side="right", fill="both", expand=True)

        # Toggle bar for Script Editor
        self._editor_visible = False
        editor_bar = ctk.CTkFrame(right_col, fg_color="transparent")
        editor_bar.pack(fill="x", pady=(0, 4))

        self.btn_toggle_editor = ctk.CTkButton(
            editor_bar,
            text="▶ Buka Script Editor (Opsional / Edit JS)",
            font=ctk.CTkFont(size=11),
            fg_color="#334155",
            hover_color="#475569",
            height=26,
            command=self._toggle_script_editor
        )
        self.btn_toggle_editor.pack(side="left")

        # Container for Script Editor (Hidden by default)
        self.editor_container = ctk.CTkFrame(right_col, fg_color="transparent")
        # will only pack when user clicks toggle

        self.script_editor = ctk.CTkTextbox(
            self.editor_container,
            height=220,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="none"
        )
        self.script_editor.pack(fill="both", expand=True, pady=(0, 6))
        # Load default template
        first_tpl = list(TEMPLATES.values())[0].strip()
        self.script_editor.insert("1.0", first_tpl)


        # Live Frida Console Output (Takes priority and full space)
        self.console_label_row = ctk.CTkFrame(right_col, fg_color="transparent")
        self.console_label_row.pack(fill="x", pady=(2, 2))
        ctk.CTkLabel(
            self.console_label_row,
            text="LIVE FRIDA CONSOLE OUTPUT (Flag / Secret / Logs):",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#a3e635"
        ).pack(side="left")

        self.console_output = ctk.CTkTextbox(
            right_col,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#0b0f17",
            text_color="#e2e8f0",
            wrap="char"
        )
        self.console_output.pack(fill="both", expand=True)

    # -------------------------------------------------------------------------
    # TAB 3: DEVICE, SERVER & LOGCAT
    # -------------------------------------------------------------------------
    def _build_tools_tab(self):
        container = ctk.CTkScrollableFrame(self.tab_tools)
        container.pack(fill="both", expand=True, padx=8, pady=8)

        # 1. Root & Device Details
        root_card = ctk.CTkFrame(container, corner_radius=8)
        root_card.pack(fill="x", padx=6, pady=6)
        ctk.CTkLabel(root_card, text="STATUS ROOT EMULATOR:", font=ctk.CTkFont(size=13, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=12, pady=(10, 4))
        self.lbl_root_details = ctk.CTkLabel(root_card, text="Checking root...", font=ctk.CTkFont(family="Consolas", size=12))
        self.lbl_root_details.pack(anchor="w", padx=12, pady=(0, 10))

        # 2. Push Frida Server Binary
        push_card = ctk.CTkFrame(container, corner_radius=8)
        push_card.pack(fill="x", padx=6, pady=6)
        ctk.CTkLabel(push_card, text="PUSH FRIDA-SERVER BINARY KE EMULATOR:", font=ctk.CTkFont(size=13, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=12, pady=(10, 4))
        ctk.CTkLabel(push_card, text="Jika frida-server belum ada di emulator, pilih binary di PC dan tekan Push:", font=ctk.CTkFont(size=11), text_color="#94a3b8").pack(anchor="w", padx=12, pady=(0, 6))

        push_row = ctk.CTkFrame(push_card, fg_color="transparent")
        push_row.pack(fill="x", padx=12, pady=(0, 10))
        self.frida_bin_entry = ctk.CTkEntry(push_row, placeholder_text="Path file frida-server di Windows...")
        self.frida_bin_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(push_row, text="📂 Browse", width=90, command=self._browse_frida_bin).pack(side="left", padx=(0, 8))
        ctk.CTkButton(push_row, text="⬆️ Push & Chmod 755", width=140, fg_color="#16a34a", command=self._push_frida_server).pack(side="left")

        # 3. Emulator AVD Launcher
        avd_card = ctk.CTkFrame(container, corner_radius=8)
        avd_card.pack(fill="x", padx=6, pady=6)
        ctk.CTkLabel(avd_card, text="LAUNCH ANDROID VIRTUAL DEVICE (AVD):", font=ctk.CTkFont(size=13, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=12, pady=(10, 4))

        avd_row = ctk.CTkFrame(avd_card, fg_color="transparent")
        avd_row.pack(fill="x", padx=12, pady=(0, 10))
        self.avd_combo = ctk.CTkComboBox(avd_row, values=["Checking AVDs..."], width=240)
        self.avd_combo.pack(side="left", padx=(0, 8))
        ctk.CTkButton(avd_row, text="▶ Jalankan Emulator", width=140, fg_color="#0284c7", command=self._launch_avd).pack(side="left")

        # 4. Live Logcat Viewer
        logcat_card = ctk.CTkFrame(container, corner_radius=8)
        logcat_card.pack(fill="both", expand=True, padx=6, pady=6)
        ctk.CTkLabel(logcat_card, text="LIVE ADB LOGCAT MONITOR:", font=ctk.CTkFont(size=13, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=12, pady=(10, 4))

        log_ctrl_row = ctk.CTkFrame(logcat_card, fg_color="transparent")
        log_ctrl_row.pack(fill="x", padx=12, pady=(0, 6))
        self.logcat_filter_entry = ctk.CTkEntry(log_ctrl_row, placeholder_text="Filter logcat (misal: flag, secret, com.chall)...")
        self.logcat_filter_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.btn_toggle_logcat = ctk.CTkButton(
            log_ctrl_row,
            text="▶ Start Logcat",
            width=110,
            fg_color="#16a34a",
            command=self.toggle_logcat
        )
        self.btn_toggle_logcat.pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            log_ctrl_row,
            text="🧹 Clear",
            width=80,
            fg_color="#475569",
            command=lambda: self.logcat_text.delete("1.0", "end")
        ).pack(side="left")

        self.logcat_text = ctk.CTkTextbox(
            logcat_card,
            height=200,
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color="#0b0f17",
            text_color="#e2e8f0"
        )
        self.logcat_text.pack(fill="both", expand=True, padx=12, pady=(0, 10))

    def _build_status_bar(self):
        """Bottom status bar."""
        self.status_bar = ctk.CTkFrame(self, height=26, corner_radius=0, fg_color="#0f172a")
        self.status_bar.pack(fill="x", side="bottom")
        self.lbl_status = ctk.CTkLabel(
            self.status_bar,
            text="Ready. Silakan pilih APK atau hubungkan emulator.",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8"
        )
        self.lbl_status.pack(side="left", padx=14)

    # =========================================================================
    # CORE LOGIC & EVENT HANDLERS
    # =========================================================================

    def refresh_devices_and_status(self):
        """Scan connected devices, root status, frida PID, and AVDs."""
        self.set_status("Scanning devices & emulator status...")
        devices = self.adb.list_devices()

        if not devices:
            self.selected_device_id = None
            self.device_combo.configure(values=["No device found"])
            self.device_combo.set("No device found")
            self.root_badge.configure(text="Root: ❌ No Device", fg_color="#7f1d1d")
            self.frida_badge.configure(text="Frida: ❌ Off", fg_color="#7f1d1d")
            self.lbl_root_details.configure(text="Tidak ada emulator/device yang terdeteksi via ADB.")
            self.set_status("Tidak ada device/emulator yang terdeteksi.")
        else:
            dev_ids = [d["id"] for d in devices]
            self.device_combo.configure(values=dev_ids)
            if not self.selected_device_id or self.selected_device_id not in dev_ids:
                self.selected_device_id = dev_ids[0]
            self.device_combo.set(self.selected_device_id)

            # Check root
            is_root, root_info = self.adb.check_root(self.selected_device_id)
            if is_root:
                self.root_badge.configure(text="Root: 🟢 UID 0", fg_color="#14532d")
                self.lbl_root_details.configure(text=f"✅ ROOT AKTIF:\n{root_info}")
            else:
                self.root_badge.configure(text="Root: 🔴 Denied", fg_color="#7f1d1d")
                self.lbl_root_details.configure(text=f"❌ Root tidak aktif / su command gagal:\n{root_info}")

            # Check Frida PID
            frida_pid = self.adb.get_frida_server_pid(self.selected_device_id)
            if frida_pid:
                self.frida_badge.configure(text=f"Frida: 🟢 PID {frida_pid}", fg_color="#14532d")
                self.btn_toggle_frida.configure(text="🛑 Stop Frida", fg_color="#dc2626")
            else:
                self.frida_badge.configure(text="Frida: 🔴 Stopped", fg_color="#7f1d1d")
                self.btn_toggle_frida.configure(text="⚡ Start Frida", fg_color="#16a34a")

            self.set_status(f"Device aktif: {self.selected_device_id} | Root: {'OK' if is_root else 'NO'} | Frida: {'ON' if frida_pid else 'OFF'}")

        # Update AVD list
        avds = self.adb.list_avds()
        if avds:
            self.avd_combo.configure(values=avds)
            self.avd_combo.set(avds[0])
        else:
            self.avd_combo.configure(values=["No AVDs found"])
            self.avd_combo.set("No AVDs found")

    def _on_device_selected(self, choice):
        if choice != "No device found":
            self.selected_device_id = choice
            threading.Thread(target=self.refresh_devices_and_status, daemon=True).start()

    def toggle_frida_server(self):
        """Start or stop frida-server on the selected device."""
        if not self.selected_device_id:
            messagebox.showwarning("Peringatan", "Tidak ada device/emulator yang dipilih!")
            return

        pid = self.adb.get_frida_server_pid(self.selected_device_id)
        if pid:
            # Stop
            self.set_status("Menghentikan frida-server...")
            success, msg = self.adb.stop_frida_server(self.selected_device_id)
            self.refresh_devices_and_status()
            messagebox.showinfo("Frida Server", msg)
        else:
            # Start
            self.set_status("Menjalankan frida-server di background...")
            threading.Thread(target=self._start_frida_thread, daemon=True).start()

    def _start_frida_thread(self):
        success, msg = self.adb.start_frida_server(self.selected_device_id)
        self.refresh_devices_and_status()
        self.set_status(msg)

    # -------------------------------------------------------------------------
    # APK Actions
    # -------------------------------------------------------------------------
    def _browse_apk(self):
        path = filedialog.askopenfilename(
            title="Pilih File APK",
            filetypes=[("Android Package (*.apk)", "*.apk"), ("All Files", "*.*")]
        )
        if path:
            self.apk_entry.delete(0, "end")
            self.apk_entry.insert(0, path)
            self._load_apk_info(path)

    def _load_apk_info(self, apk_path: str):
        self.set_status("Membedah AndroidManifest.xml...")
        info = self.adb.extract_apk_info(apk_path)
        self.current_apk_info = info

        pkg = info.get("package_name") or "Unknown"
        act = info.get("main_activity") or "Unknown"
        sz = info.get("file_size", 0)

        self.lbl_pkg.configure(text=pkg)
        self.lbl_act.configure(text=act)
        self.lbl_size.configure(text=f"{sz:,} bytes ({sz / (1024*1024):.2f} MB)")

        if pkg and pkg != "Unknown":
            self.hook_pkg_entry.delete(0, "end")
            self.hook_pkg_entry.insert(0, pkg)

        self.set_status(f"APK Loaded: {pkg}")

    def _install_selected_apk(self):
        apk_path = self.apk_entry.get().strip()
        if not apk_path or not os.path.exists(apk_path):
            messagebox.showerror("Error", "Pilih file APK yang valid terlebih dahulu!")
            return

        if not self.selected_device_id:
            messagebox.showerror("Error", "Device / emulator tidak terhubung!")
            return

        self.set_status(f"Menginstall {os.path.basename(apk_path)} ke {self.selected_device_id}...")

        def _do_install():
            success, msg = self.adb.install_apk(self.selected_device_id, apk_path)
            self.set_status(f"Install: {msg}")
            if success:
                messagebox.showinfo("Berhasil", f"APK Berhasil Terinstall di Emulator!\n\nStatus: {msg}")
                self.refresh_installed_packages()
            else:
                messagebox.showerror("Gagal Install", f"Install Gagal:\n{msg}")

        threading.Thread(target=_do_install, daemon=True).start()

    def _launch_target_app(self):
        pkg = self.lbl_pkg.cget("text")
        if not pkg or pkg == "-":
            pkg = self.hook_pkg_entry.get().strip()
        if not pkg:
            messagebox.showwarning("Peringatan", "Tentukan package name terlebih dahulu!")
            return
        success, msg = self.adb.launch_app(self.selected_device_id, pkg)
        self.set_status(msg)

    def _force_stop_app(self):
        pkg = self.lbl_pkg.cget("text")
        if not pkg or pkg == "-":
            pkg = self.hook_pkg_entry.get().strip()
        if pkg:
            self.adb.force_stop_app(self.selected_device_id, pkg)
            self.set_status(f"Force stopped: {pkg}")

    def _clear_app_data(self):
        pkg = self.lbl_pkg.cget("text")
        if not pkg or pkg == "-":
            pkg = self.hook_pkg_entry.get().strip()
        if pkg:
            self.adb.clear_app_data(self.selected_device_id, pkg)
            self.set_status(f"Data cleared: {pkg}")

    def _send_pkg_to_hook_tab(self):
        pkg = self.lbl_pkg.cget("text")
        if pkg and pkg != "-":
            self.hook_pkg_entry.delete(0, "end")
            self.hook_pkg_entry.insert(0, pkg)
            self.tabview.set("💉 Frida Hooking Studio")

    # -------------------------------------------------------------------------
    # APK Triage & Unpack (Rev Engine Integration)
    # -------------------------------------------------------------------------
    def _run_apk_triage(self, apk_path: Optional[str] = None):
        if not apk_path:
            apk_path = self.apk_entry.get().strip()

        if not apk_path or not os.path.exists(apk_path):
            current_pkg = self.lbl_pkg.cget("text")
            if current_pkg and current_pkg != "-" and self.selected_device_id:
                self._pull_package_apk(current_pkg)
                return
            messagebox.showerror("Error", "Pilih file APK terlebih dahulu atau klik 'Tarik APK' pada salah satu package!")
            return

        self.set_status(f"Memindai & Triage {os.path.basename(apk_path)} (Rev CTF Engine)...")

        def _worker():
            report = self.triage.triage_apk(apk_path)
            self.last_triage_result = report
            self.after(0, lambda: self._render_triage_result(report))
            rec = report.get("recommended_template", "")
            self.set_status(f"Triage selesai: Rekomendasi -> {rec}")

        threading.Thread(target=_worker, daemon=True).start()

    def _render_triage_result(self, report: Dict[str, Any]):
        for widget in self.triage_card.winfo_children():
            widget.destroy()

        if not report.get("success"):
            ctk.CTkLabel(
                self.triage_card,
                text=f"❌ Error Triage: {report.get('error', 'Gagal membedah APK')}",
                text_color="#f87171"
            ).pack(padx=12, pady=10)
            try:
                self.triage_card.pack(fill="x", padx=10, pady=(0, 6), before=self.pkg_box)
            except Exception:
                self.triage_card.pack(fill="x", padx=10, pady=(0, 6))
            return

        # Header Row
        head_row = ctk.CTkFrame(self.triage_card, fg_color="transparent")
        head_row.pack(fill="x", padx=12, pady=(10, 4))

        ctk.CTkLabel(
            head_row,
            text="⚡ HASIL STATIC TRIAGE & REKOMENDASI (REV CTF ENGINE):",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#38bdf8"
        ).pack(side="left")

        ctk.CTkLabel(
            head_row,
            text=f"Scan: {report.get('raw_strings_count', 0):,} strings",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8"
        ).pack(side="left", padx=10)

        # 1. Flags Found Box (If any)
        flags = report.get("flags_found", [])
        if flags:
            flag_box = ctk.CTkFrame(self.triage_card, fg_color="#064e3b", corner_radius=6, border_width=1, border_color="#10b981")
            flag_box.pack(fill="x", padx=12, pady=4)
            ctk.CTkLabel(
                flag_box,
                text=f"🚩 FLAG / KEY DITEMUKAN DALAM APK:\n" + "\n".join(flags),
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                text_color="#34d399",
                justify="left"
            ).pack(padx=10, pady=8, anchor="w")

        # 2. Findings Badges / Bullets
        findings = report.get("findings", [])
        if findings:
            find_box = ctk.CTkFrame(self.triage_card, fg_color="#1e293b", corner_radius=6)
            find_box.pack(fill="x", padx=12, pady=4)
            for f in findings:
                ctk.CTkLabel(
                    find_box,
                    text=f"• {f}",
                    font=ctk.CTkFont(size=11),
                    text_color="#e2e8f0"
                ).pack(anchor="w", padx=8, pady=2)

        # 3. Recommendation Box
        rec_tpl = report.get("recommended_template", "01_String_Equals_Sniffer")
        rec_reason = report.get("recommended_reason", "")

        rec_box = ctk.CTkFrame(self.triage_card, fg_color="#172554", corner_radius=6, border_width=1, border_color="#3b82f6")
        rec_box.pack(fill="x", padx=12, pady=(4, 10))

        rec_head = ctk.CTkFrame(rec_box, fg_color="transparent")
        rec_head.pack(fill="x", padx=10, pady=(6, 2))

        ctk.CTkLabel(
            rec_head,
            text=f"🎯 REKOMENDASI HOOK: {rec_tpl}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#60a5fa"
        ).pack(side="left")

        ctk.CTkButton(
            rec_head,
            text="👉 Terapkan Hook & Buka Studio",
            width=230,
            height=28,
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            font=ctk.CTkFont(weight="bold"),
            command=lambda: self._apply_recommended_hook(rec_tpl)
        ).pack(side="right")

        if rec_reason:
            ctk.CTkLabel(
                rec_box,
                text=rec_reason,
                font=ctk.CTkFont(size=11),
                text_color="#bfdbfe",
                wraplength=800,
                justify="left"
            ).pack(anchor="w", padx=10, pady=(0, 6))

        # Show the triage card in Tab 1
        try:
            self.triage_card.pack(fill="x", padx=10, pady=(0, 6), before=self.pkg_box)
        except Exception:
            self.triage_card.pack(fill="x", padx=10, pady=(0, 6))

    def _unpack_apk_folder(self):
        apk_path = self.apk_entry.get().strip()
        if not apk_path or not os.path.exists(apk_path):
            current_pkg = self.lbl_pkg.cget("text")
            if current_pkg and current_pkg != "-" and self.selected_device_id:
                self._pull_package_apk(current_pkg)
                return
            messagebox.showerror("Error", "Pilih file APK yang valid terlebih dahulu!")
            return

        self.set_status(f"Mengekstrak / Unpack {os.path.basename(apk_path)}...")
        ok, res = self.triage.unpack_apk(apk_path)
        if ok:
            self.set_status(f"APK diekstrak ke: {res}")
            # Open directory in Windows Explorer
            try:
                if os.name == "nt":
                    os.startfile(res)
                else:
                    subprocess.Popen(["xdg-open", res])
            except Exception:
                pass
            messagebox.showinfo("Unpack Sukses", f"Folder hasil ekstrak APK dibuka:\n{res}")
        else:
            messagebox.showerror("Gagal Unpack", f"Gagal mengekstrak APK: {res}")

    def _pull_package_apk(self, pkg_name: str):
        if not self.selected_device_id:
            messagebox.showerror("Error", "Device emulator tidak terhubung!")
            return

        self.set_status(f"Menarik (Pull) base.apk {pkg_name} dari emulator...")

        def _worker():
            ok, res = self.adb.pull_apk(self.selected_device_id, pkg_name)
            if ok:
                self.after(0, lambda: self._on_apk_pulled(pkg_name, res))
            else:
                self.after(0, lambda: messagebox.showerror("Gagal Tarik APK", f"Gagal menarik APK {pkg_name}:\n{res}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_apk_pulled(self, pkg_name: str, local_path: str):
        self.apk_entry.delete(0, "end")
        self.apk_entry.insert(0, local_path)
        self._load_apk_info(local_path)
        self.set_status(f"APK {pkg_name} berhasil ditarik ke PC!")
        self._run_apk_triage(local_path)

    def _apply_recommended_hook(self, template_key: str):
        if template_key in TEMPLATES:
            self.template_combo.set(template_key)
            self._on_template_selected(template_key)

        pkg = self.lbl_pkg.cget("text")
        if pkg and pkg != "-":
            self.hook_pkg_entry.delete(0, "end")
            self.hook_pkg_entry.insert(0, pkg)

        self.tabview.set("💉 Frida Hooking Studio")
        self.set_status(f"Rekomendasi '{template_key}' dimuat untuk target '{self.hook_pkg_entry.get().strip()}'. Tinggal klik START HOOK!")

    # -------------------------------------------------------------------------
    # Package Listing & Filters
    # -------------------------------------------------------------------------
    def refresh_installed_packages(self):
        if not self.selected_device_id:
            return
        packages = self.adb.get_detailed_packages(self.selected_device_id)
        self.all_installed_packages = packages
        self._filter_package_list()

    def _filter_package_list(self):
        if not hasattr(self, "all_installed_packages"):
            return

        cat_filter = self.pkg_filter_var.get() if hasattr(self, "pkg_filter_var") else "Semua"
        query = self.pkg_search_entry.get().strip().lower() if hasattr(self, "pkg_search_entry") else ""

        filtered = []
        for item in self.all_installed_packages:
            pkg = item.get("package", "")
            cat = item.get("category", "SYSTEM")

            # Category filter
            if cat_filter == "⭐ Target CTF" and cat != "CTF_TARGET":
                continue
            if cat_filter == "👤 User App" and cat not in ("CTF_TARGET", "USER_APP"):
                continue

            # Query search
            if query and query not in pkg.lower():
                continue

            filtered.append(item)

        self._display_packages(filtered)

    def _display_packages(self, packages: List[Dict[str, Any]]):
        for widget in self.pkg_list_frame.winfo_children():
            widget.destroy()

        if not packages:
            ctk.CTkLabel(self.pkg_list_frame, text="Tidak ada packages yang cocok dengan filter.", text_color="#94a3b8").pack(pady=10)
            return

        for item in packages:
            pkg = item.get("package", "")
            cat = item.get("category", "SYSTEM")

            row = ctk.CTkFrame(self.pkg_list_frame, fg_color="#181b20", corner_radius=6)
            row.pack(fill="x", pady=2, padx=4)

            # Badge category
            if cat == "CTF_TARGET":
                badge_bg = "#065f46"
                badge_txt_color = "#34d399"
                badge_lbl = "⭐ TARGET CTF"
            elif cat == "USER_APP":
                badge_bg = "#1e3a8a"
                badge_txt_color = "#93c5fd"
                badge_lbl = "👤 USER"
            else:
                badge_bg = "#334155"
                badge_txt_color = "#94a3b8"
                badge_lbl = "⚙️ SYS"

            badge = ctk.CTkFrame(row, fg_color=badge_bg, corner_radius=4)
            badge.pack(side="left", padx=(6, 8), pady=4)
            ctk.CTkLabel(
                badge,
                text=badge_lbl,
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=badge_txt_color
            ).pack(padx=6, pady=1)

            # Package Name
            ctk.CTkLabel(
                row,
                text=pkg,
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold" if cat == "CTF_TARGET" else "normal"),
                text_color="#f8fafc" if cat == "CTF_TARGET" else "#cbd5e1"
            ).pack(side="left", padx=2, pady=4)

            # Action Buttons: Set Target & Pull APK
            btn_set = ctk.CTkButton(
                row,
                text="🎯 Set Target",
                width=85,
                height=24,
                fg_color="#0284c7",
                command=lambda name=pkg: self._set_package_target(name)
            )
            btn_set.pack(side="right", padx=4, pady=4)

            btn_pull = ctk.CTkButton(
                row,
                text="📥 Tarik APK",
                width=85,
                height=24,
                fg_color="#0f766e",
                hover_color="#0d9488",
                command=lambda name=pkg: self._pull_package_apk(name)
            )
            btn_pull.pack(side="right", padx=(0, 4), pady=4)

    def _set_package_target(self, pkg_name: str):
        self.hook_pkg_entry.delete(0, "end")
        self.hook_pkg_entry.insert(0, pkg_name)
        self.lbl_pkg.configure(text=pkg_name)
        self.tabview.set("💉 Frida Hooking Studio")
        self.set_status(f"Target diset ke: {pkg_name}")

    # -------------------------------------------------------------------------
    # Frida Hooking Studio Actions
    # -------------------------------------------------------------------------
    def _select_master_auto_solver(self):
        tpl = list(TEMPLATES.keys())[0]
        if tpl in TEMPLATES:
            self.template_combo.set(tpl)
            self._on_template_selected(tpl)
            self.set_status("🔥 Master Auto-Solver dimuat! (Root Bypass + String Sniffer + Crypto Sniffer Aktif)")


    def _on_template_selected(self, key):
        if key in TEMPLATES:
            code = TEMPLATES[key].strip()
            self.script_editor.delete("1.0", "end")
            self.script_editor.insert("1.0", code)
            self.set_status(f"Template '{key}' dimuat.")

    def _load_custom_js(self):
        path = filedialog.askopenfilename(
            title="Pilih Script Frida (.js)",
            filetypes=[("JavaScript Files (*.js)", "*.js"), ("All Files", "*.*")]
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    code = f.read()
                self.script_editor.delete("1.0", "end")
                self.script_editor.insert("1.0", code)
                self.set_status(f"Script dimuat dari {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Gagal membaca file: {e}")

    def _save_editor_js(self):
        path = filedialog.asksaveasfilename(
            title="Simpan Script Frida (.js)",
            defaultextension=".js",
            filetypes=[("JavaScript Files (*.js)", "*.js")]
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.script_editor.get("1.0", "end"))
                messagebox.showinfo("Sukses", f"Script tersimpan di: {path}")
            except Exception as e:
                messagebox.showerror("Error", f"Gagal menyimpan: {e}")

    def _clear_console(self):
        self.console_output.delete("1.0", "end")

    def _toggle_script_editor(self):
        if not self._editor_visible:
            self.editor_container.pack(fill="x", pady=(0, 6), before=self.console_label_row)
            self.btn_toggle_editor.configure(text="▼ Sembunyikan Script Editor")
            self._editor_visible = True
        else:
            self.editor_container.pack_forget()
            self.btn_toggle_editor.configure(text="▶ Buka Script Editor (Opsional / Edit JS)")
            self._editor_visible = False

    def start_frida_hook(self):
        """Execute the Frida script against target app — smart auto-mode."""
        pkg = self.hook_pkg_entry.get().strip()
        if not pkg or pkg == "Unknown":
            messagebox.showerror(
                "Package Belum Dipilih",
                "Pilih dulu package dari tab 'APK & App Manager', lalu klik namanya untuk set sebagai target!"
            )
            return

        if not self.selected_device_id:
            messagebox.showerror("Error", "Device emulator tidak terhubung!")
            return

        # Ensure frida-server is running on emulator
        pid = self.adb.get_frida_server_pid(self.selected_device_id)
        if not pid:
            ask = messagebox.askyesno(
                "Frida Server Belum Aktif",
                "Frida server di emulator belum berjalan.\n\nApakah ingin menjalankannya sekarang secara otomatis?"
            )
            if ask:
                self.adb.start_frida_server(self.selected_device_id)
                self.refresh_devices_and_status()
            else:
                return

        # Auto-load Auto-Solver if script editor is empty / default
        current_code = self.script_editor.get("1.0", "end").strip()
        if not current_code:
            self._select_master_auto_solver()
            current_code = self.script_editor.get("1.0", "end").strip()

        # Save current editor code to a temporary script file
        temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scratch")
        os.makedirs(temp_dir, exist_ok=True)
        script_file = os.path.join(temp_dir, f"hook_{pkg}_{int(time.time())}.js")
        with open(script_file, "w", encoding="utf-8") as f:
            f.write(current_code)

        # Store for auto-retry in error handler
        self._last_script_file = script_file
        self._last_pkg = pkg

        # ── SMART MODE DETECTION ──────────────────────────────────────────────
        # Auto-detect: if the user selected "spawn" but app is already running,
        # automatically switch to attach (avoids NullPointerException crash)
        user_mode = self.hook_mode_var.get()
        app_already_running = self.adb.is_app_running(self.selected_device_id, pkg)

        if user_mode == "spawn" and app_already_running:
            spawn = False
            mode_note = "Auto-switch ke ATTACH (app sudah berjalan)"
        elif user_mode == "attach" and not app_already_running:
            spawn = True
            mode_note = "Auto-switch ke SPAWN (app belum berjalan)"
        else:
            spawn = (user_mode == "spawn")
            mode_note = "Spawn (-f)" if spawn else "Attach (-n)"
        # ─────────────────────────────────────────────────────────────────────

        self._clear_console()
        self.append_console(f"[*] Target: {pkg}\n")
        self.append_console(f"[*] Mode  : {mode_note}\n")
        self.append_console(f"[*] Script: {os.path.basename(script_file)}\n\n")

        self.btn_run_hook.configure(state="disabled", fg_color="#334155")
        self.btn_stop_hook.configure(state="normal")
        if hasattr(self, "lbl_hook_state"):
            self.lbl_hook_state.configure(
                text=f"🟢 HOOK SEDANG BERJALAN!\n→ Buka/interaksi app di emulator → flag di console!",
                text_color="#22c55e"
            )

        success = self.runner.start_hook(
            package_name=pkg,
            script_path=script_file,
            spawn=spawn,
            device_id=self.selected_device_id
        )

        if not success:
            # If spawn failed, auto-retry with attach
            if spawn:
                self.append_console("\n[!] Spawn gagal — mencoba ulang dengan mode Attach (-n)...\n\n")
                success = self.runner.start_hook(
                    package_name=pkg,
                    script_path=script_file,
                    spawn=False,
                    device_id=self.selected_device_id
                )

        if not success:
            self.btn_run_hook.configure(state="normal", fg_color="#16a34a")
            self.btn_stop_hook.configure(state="disabled")
            if hasattr(self, "lbl_hook_state"):
                self.lbl_hook_state.configure(
                    text="❌ GAGAL — Pastikan:\n1. App sudah di-install\n2. Frida server hidup\n3. Emulator terhubung",
                    text_color="#ef4444"
                )

    def stop_frida_hook(self):
        """Stop running Frida session."""
        self.runner.stop_hook()
        self.btn_run_hook.configure(state="normal", fg_color="#16a34a")
        self.btn_stop_hook.configure(state="disabled")
        if hasattr(self, "lbl_hook_state"):
            self.lbl_hook_state.configure(text="⚪ STATUS: HOOK DIHENTIKAN", text_color="#94a3b8")


    def on_frida_output(self, text: str):
        """Callback from runner thread."""
        self.log_queue.put(("frida", text))

    def on_frida_exit(self, code: int):
        """Callback when process terminates."""
        self.log_queue.put(("frida_exit", code))

    def append_console(self, text: str):
        self.console_output.insert("end", text)
        self.console_output.see("end")

    def _process_log_queue(self):
        """Drain queue on the Tkinter main thread — with smart error detection."""
        while not self.log_queue.empty():
            msg_type, data = self.log_queue.get_nowait()

            if msg_type == "frida":
                self.append_console(data)

                # ── BINGO / FLAG DETECTED ALERT ──────────────────────────────
                data_l = data.lower()
                if "bingo" in data_l or "flag{" in data_l or "hacktoday{" in data_l or "ctf{" in data_l:
                    if hasattr(self, "lbl_hook_state"):
                        self.lbl_hook_state.configure(
                            text="🎉 BINGO! FLAG DITEMUKAN!\n→ CEK OUTPUT CONSOLE DI KANAN!",
                            text_color="#22c55e"
                        )
                    self.set_status("🚩 [BINGO!] Flag / Secret terdeteksi di konsol output!")

                # ── SMART ERROR DETECTION ────────────────────────────────────
                # Error 1: App belum buka di emulator → Attach gagal
                if "unable to find process" in data_l:
                    pkg = self.hook_pkg_entry.get().strip()
                    script = getattr(self, "_last_script_file", None)
                    if script and pkg:
                        self.append_console(
                            "\n[AUTO-FIX] App belum buka → mencoba SPAWN (buka otomatis)...\n\n"
                        )
                        if hasattr(self, "lbl_hook_state"):
                            self.lbl_hook_state.configure(
                                text="🔄 Auto-retry: SPAWN mode (membuka app)...",
                                text_color="#f59e0b"
                            )
                        self.runner.start_hook(
                            package_name=pkg,
                            script_path=script,
                            spawn=True,
                            device_id=self.selected_device_id
                        )

                # Error 2: Spawn gagal NullPointerException (Frida17 + some APKs)
                elif "nullpointerexception" in data_l and "failed to spawn" in data_l:
                    pkg = self.hook_pkg_entry.get().strip()
                    script = getattr(self, "_last_script_file", None)
                    if script and pkg:
                        self.append_console(
                            "\n[AUTO-FIX] Spawn NPE → coba buka app manual, lalu Attach...\n"
                            "  → Buka app di emulator (tap icon) lalu tunggu 2 detik\n"
                            "  → AUTO mencoba Attach dalam 3 detik...\n\n"
                        )
                        if hasattr(self, "lbl_hook_state"):
                            self.lbl_hook_state.configure(
                                text="🔄 Auto-retry: ATTACH mode dalam 3 detik...\n→ Buka app di emulator sekarang!",
                                text_color="#f59e0b"
                            )
                        # Delay 3s then attach
                        self.after(3000, lambda p=pkg, s=script: self.runner.start_hook(
                            package_name=p,
                            script_path=s,
                            spawn=False,
                            device_id=self.selected_device_id
                        ))
                # ─────────────────────────────────────────────────────────────


            elif msg_type == "frida_exit":
                self.btn_run_hook.configure(state="normal", fg_color="#16a34a")
                self.btn_stop_hook.configure(state="disabled")
                if hasattr(self, "lbl_hook_state"):
                    self.lbl_hook_state.configure(text="⚪ STATUS: SELESAI / BERHENTI", text_color="#94a3b8")
            elif msg_type == "logcat":
                self.logcat_text.insert("end", data)
                self.logcat_text.see("end")

        self.after(100, self._process_log_queue)


    # -------------------------------------------------------------------------
    # TAB 3 Tools & AVD Actions
    # -------------------------------------------------------------------------
    def _browse_frida_bin(self):
        path = filedialog.askopenfilename(
            title="Pilih Binary frida-server",
            filetypes=[("All Files", "*.*")]
        )
        if path:
            self.frida_bin_entry.delete(0, "end")
            self.frida_bin_entry.insert(0, path)

    def _push_frida_server(self):
        local = self.frida_bin_entry.get().strip()
        if not local or not os.path.exists(local):
            messagebox.showerror("Error", "Pilih binary frida-server lokal di PC terlebih dahulu!")
            return
        if not self.selected_device_id:
            messagebox.showerror("Error", "Device emulator tidak terhubung!")
            return

        self.set_status("Pushing frida-server ke /data/local/tmp/...")
        threading.Thread(target=self._push_frida_thread, args=(local,), daemon=True).start()

    def _push_frida_thread(self, local_path):
        success, msg = self.adb.push_file(self.selected_device_id, local_path, "/data/local/tmp/frida-server", chmod="755")
        self.set_status(msg)
        if success:
            messagebox.showinfo("Berhasil", "frida-server berhasil di-push dan di-chmod 755!\nSilakan tekan 'Start Frida'.")
            self.refresh_devices_and_status()
        else:
            messagebox.showerror("Gagal Push", msg)

    def _launch_avd(self):
        avd_name = self.avd_combo.get().strip()
        if not avd_name or "No AVDs" in avd_name:
            messagebox.showerror("Error", "Tidak ada AVD yang valid!")
            return
        self.set_status(f"Meluncurkan AVD {avd_name}...")
        self.adb.start_avd(avd_name)
        messagebox.showinfo("AVD Diluncurkan", f"Emulator {avd_name} sedang dinyalakan di background.\nTunggu 10-30 detik lalu tekan 'Refresh'.")

    def toggle_logcat(self):
        if self.is_logcat_running:
            self.is_logcat_running = False
            if self.logcat_process:
                self.logcat_process.kill()
                self.logcat_process = None
            self.btn_toggle_logcat.configure(text="▶ Start Logcat", fg_color="#16a34a")
            self.set_status("Logcat dihentikan")
        else:
            if not self.selected_device_id:
                messagebox.showerror("Error", "Device tidak terhubung!")
                return
            self.is_logcat_running = True
            self.btn_toggle_logcat.configure(text="⏹ Stop Logcat", fg_color="#dc2626")
            self.set_status("Logcat berjalan...")
            threading.Thread(target=self._stream_logcat, daemon=True).start()

    def _stream_logcat(self):
        filt = self.logcat_filter_entry.get().strip()
        cmd = [self.adb.adb_path, "-s", self.selected_device_id, "logcat", "-v", "time"]

        try:
            self.logcat_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            for line in iter(self.logcat_process.stdout.readline, ""):
                if not self.is_logcat_running:
                    break
                if filt:
                    if filt.lower() in line.lower():
                        self.log_queue.put(("logcat", line))
                else:
                    self.log_queue.put(("logcat", line))
        except Exception:
            pass
        self.is_logcat_running = False

    def set_status(self, msg: str):
        self.lbl_status.configure(text=msg)


def main():
    app = FridaCTFAssistant()
    app.mainloop()


if __name__ == "__main__":
    main()
