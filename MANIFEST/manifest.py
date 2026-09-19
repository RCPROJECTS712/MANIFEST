#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MANIFEST - live process triage
-------------------------------
A no-nonsense process monitor for Windows that does the one thing Task Manager
won't: it tells you WHAT EACH PROCESS ACTUALLY IS.

Every running process is labelled:
    CORE  - essential to Windows. Killing it crashes your machine. LOCKED.
    HW    - a hardware / driver service (audio, graphics, bluetooth, etc).
    OEM   - a manufacturer add-on (Lenovo Vantage, etc). Safe to close.
    YOU   - software you installed / opened.
    ???   - unclassified. Investigate before trusting.

Pure Python standard library. No pip installs. Data comes from PowerShell
(built into Windows). Runs without admin, though killing some processes that
belong to SYSTEM may require you to relaunch as administrator.

Edit the CLASSIFICATION section below to teach it about your own software.
"""

import os
import sys
import json
import time
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox

# ----------------------------------------------------------------------------
# LOOK & FEEL  (phosphor-green CRT)
# ----------------------------------------------------------------------------
BG        = "#050805"     # near-black
PANEL     = "#0a0f0a"
GREEN     = "#33ff66"     # primary phosphor
DIMGREEN  = "#1f7a3d"
SELECT_BG = "#04331c"
SELECT_FG = "#9dffc2"
FONT      = ("Consolas", 10)
FONT_B    = ("Consolas", 10, "bold")
FONT_BIG  = ("Consolas", 13, "bold")

REFRESH_SECONDS = 3       # live refresh interval

# ----------------------------------------------------------------------------
# CLASSIFICATION
# ----------------------------------------------------------------------------
# Category metadata: symbol, row colour, whether the tool will let you kill it.
CATS = {
    "CORE":   {"sym": "CORE", "color": "#c96a6a", "kill": False,
               "desc": "Essential to Windows - locked"},
    "HW":     {"sym": " HW ", "color": "#4fd6ff", "kill": True,
               "desc": "Hardware / driver service"},
    "OEM":    {"sym": "OEM ", "color": "#ffcc33", "kill": True,
               "desc": "Manufacturer add-on - optional"},
    "YOU":    {"sym": "YOU ", "color": "#66ff99", "kill": True,
               "desc": "Your software"},
    "UNK":    {"sym": " ?? ", "color": "#e6e6e6", "kill": True,
               "desc": "Unclassified - investigate"},
}
CAT_ORDER = ["CORE", "HW", "OEM", "YOU", "UNK"]

# Essential Windows processes. Killing any of these can crash the session.
# msedgewebview2 is here on purpose: it is the shared web component that powers
# Start-menu Search, Widgets and many apps. Nuking it breaks those.
CORE = {
    "system", "system idle process", "secure system", "registry",
    "memory compression", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe",
    "fontdrvhost.exe", "dwm.exe", "explorer.exe", "runtimebroker.exe",
    "shellexperiencehost.exe", "startmenuexperiencehost.exe", "searchhost.exe",
    "searchindexer.exe", "searchapp.exe", "sihost.exe", "taskhostw.exe",
    "ctfmon.exe", "conhost.exe", "dllhost.exe", "wmiprvse.exe", "spoolsv.exe",
    "audiodg.exe", "dashost.exe", "wudfhost.exe", "backgroundtaskhost.exe",
    "applicationframehost.exe", "systemsettings.exe", "textinputhost.exe",
    "useroobebroker.exe", "lockapp.exe", "smartscreen.exe", "shellhost.exe",
    "crossdeviceresume.exe", "appprovisioningplugin.exe", "biolso.exe",
    "ngc.exe", "ngciso.exe", "ngclso.exe", "widgets.exe", "widgetservice.exe",
    "phoneexperiencehost.exe", "msedgewebview2.exe",
    # Windows Defender - treated as locked so you don't disable your own AV
    "msmpeng.exe", "nissrv.exe", "mpdefendercoreservice.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe",
    "sgrmbroker.exe", "mpcmdrun.exe",
}

# Hardware / driver services.
HW = {
    "intelaudioservice.exe", "rtkauduservice64.exe", "rtkbtmanserv.exe",
    "igfxcuiservice.exe", "igfxext.exe", "igfxem.exe",
    "intelgraphicssoftware.service.exe", "intelcphdcpsvc.exe", "dax3api.exe",
    "elevoccontrolservice.exe", "elevocaudiomanager.exe", "ipfsvc.exe",
    "ipf_helper.exe", "ipf_uf.exe", "offloaditemservice.exe",
    "presentmonservice.exe", "esrv_svc.exe", "jhi_service.exe", "lms.exe",
    "ravcpl64.exe", "ravbg64.exe", "nvcontainer.exe",
    "nvdisplay.container.exe", "nvsphelper64.exe",
}

# Manufacturer add-ons - safe to close.
OEM = {
    "lenovovantage-(genericmessagingaddin).exe",
    "lenovovantage-(vantagecoreaddin).exe", "lenovovantageservice.exe",
    "facebeautify.exe", "lsaissrpcserver.exe", "messagingplugin.exe",
    "readyforservice.exe", "microsoftedgeupdate.exe", "braveupdate.exe",
}

# Software you installed / this tool itself.
YOU = {
    "brave.exe", "mullvad.exe", "mullvad-gui.exe", "mullvad-daemon.exe",
    "malwarebytes.exe", "mbamservice.exe", "ddshelper.exe",
    "python.exe", "pythonw.exe", "taskmgr.exe",
}


def classify(name, path):
    """Return a category key for a process."""
    n = (name or "").strip().lower()
    if n in CORE:
        return "CORE"
    if "euterpe" in n:                 # Lenovo wireless-keyboard driver
        return "HW"
    if n in HW:
        return "HW"
    if n in OEM:
        return "OEM"
    if n.startswith("lenovovantage") or "vantage" in n:
        return "OEM"
    if "lenovo" in n:
        return "OEM"
    if n in YOU:
        return "YOU"
    return "UNK"


# ----------------------------------------------------------------------------
# DATA COLLECTION  (PowerShell -> JSON)
# ----------------------------------------------------------------------------
_NO_WIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)

PS_QUERY = (
    "Get-CimInstance Win32_Process | "
    "Select-Object ProcessId,Name,WorkingSetSize,KernelModeTime,"
    "UserModeTime,ExecutablePath | ConvertTo-Json -Compress"
)


def _run_powershell(cmd):
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=25, creationflags=_NO_WIN,
        )
        return out.stdout or ""
    except Exception:
        return ""


def fetch_processes():
    """Return a list of dicts: pid, name, mem(bytes), cputicks, path."""
    raw = _run_powershell(PS_QUERY)
    if not raw:
        return []
    # Trim anything before the JSON payload.
    i = min([x for x in (raw.find("["), raw.find("{")) if x != -1] or [-1])
    if i < 0:
        return []
    try:
        data = json.loads(raw[i:])
    except Exception:
        return []
    if isinstance(data, dict):        # single process -> wrap
        data = [data]
    procs = []
    for d in data:
        try:
            pid = int(d.get("ProcessId") or 0)
        except Exception:
            continue
        kt = int(d.get("KernelModeTime") or 0)
        ut = int(d.get("UserModeTime") or 0)
        procs.append({
            "pid":  pid,
            "name": d.get("Name") or "(unknown)",
            "mem":  int(d.get("WorkingSetSize") or 0),
            "cpu_ticks": kt + ut,
            "path": d.get("ExecutablePath") or "",
        })
    return procs


def verify_signature(path):
    """On-demand Authenticode check. Returns (status, signer)."""
    if not path:
        return ("NO FILE", "process has no on-disk image")
    safe = path.replace("'", "''")
    cmd = (
        "$s = Get-AuthenticodeSignature -LiteralPath '%s'; "
        "$subj = if ($s.SignerCertificate) "
        "{ $s.SignerCertificate.Subject } else { 'none' }; "
        "Write-Output ($s.Status.ToString() + '|' + $subj)"
    ) % safe
    out = _run_powershell(cmd).strip()
    if "|" in out:
        status, signer = out.split("|", 1)
        return (status.strip(), signer.strip())
    return ("UNKNOWN", out or "could not read signature")


# ----------------------------------------------------------------------------
# HELPERS
# ----------------------------------------------------------------------------
def human_mb(nbytes):
    return "{:,.0f}".format(nbytes / (1024 * 1024))


# ----------------------------------------------------------------------------
# APP
# ----------------------------------------------------------------------------
class Manifest(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MANIFEST  -  live process triage")
        self.configure(bg=BG)
        self.geometry("880x620")
        self.minsize(720, 460)

        self._prev_ticks = {}         # pid -> cpu_ticks  (for CPU% delta)
        self._prev_time = None
        self._ncpu = os.cpu_count() or 1
        self._auto = True
        self._sort_col = "mem"
        self._sort_desc = True
        self._rows = []               # last fetched+classified rows

        self.filters = {c: tk.BooleanVar(value=True) for c in CAT_ORDER}

        self._build_style()
        self._build_header()
        self._build_toolbar()
        self._build_table()
        self._build_actions()
        self._build_statusbar()

        self.refresh()
        self._tick()

    # ---- styling -----------------------------------------------------------
    def _build_style(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except Exception:
            pass
        st.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                     foreground=GREEN, font=FONT, rowheight=22, borderwidth=0)
        st.configure("Treeview.Heading", background="#0f160f",
                     foreground=GREEN, font=FONT_B, relief="flat")
        st.map("Treeview.Heading", background=[("active", "#142014")])
        st.map("Treeview",
               background=[("selected", SELECT_BG)],
               foreground=[("selected", SELECT_FG)])

    # ---- header ------------------------------------------------------------
    def _build_header(self):
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=10, pady=(8, 2))
        tk.Label(bar, text="// MANIFEST", bg=BG, fg=GREEN,
                 font=FONT_BIG).pack(side="left")
        self.summary = tk.Label(bar, text="", bg=BG, fg=DIMGREEN, font=FONT)
        self.summary.pack(side="right")

    # ---- toolbar -----------------------------------------------------------
    def _build_toolbar(self):
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=10, pady=2)

        for c in CAT_ORDER:
            meta = CATS[c]
            cb = tk.Checkbutton(
                bar, text=c, variable=self.filters[c],
                command=self.render, bg=BG, fg=meta["color"],
                selectcolor=BG, activebackground=BG,
                activeforeground=meta["color"], font=FONT_B,
                bd=0, highlightthickness=0)
            cb.pack(side="left", padx=(0, 6))

        tk.Frame(bar, bg=DIMGREEN, width=1, height=18).pack(
            side="left", padx=8, fill="y")

        self._btn(bar, "SHOW ONLY OPTIONAL", self.only_optional).pack(
            side="left", padx=3)
        self._btn(bar, "SHOW ALL", self.show_all).pack(side="left", padx=3)

    # ---- table -------------------------------------------------------------
    def _build_table(self):
        wrap = tk.Frame(self, bg=BG)
        wrap.pack(fill="both", expand=True, padx=10, pady=6)

        cols = ("cat", "name", "pid", "cpu", "mem")
        heads = {"cat": "TYPE", "name": "PROCESS", "pid": "PID",
                 "cpu": "CPU%", "mem": "MEM (MB)"}
        widths = {"cat": 70, "name": 360, "pid": 80, "cpu": 80, "mem": 110}
        anchors = {"cat": "center", "name": "w", "pid": "e",
                   "cpu": "e", "mem": "e"}
        sortkey = {"cat": "cat", "name": "name", "pid": "pid",
                   "cpu": "cpu", "mem": "mem"}

        self.tree = ttk.Treeview(wrap, columns=cols, show="headings",
                                 selectmode="browse")
        for c in cols:
            self.tree.heading(
                c, text=heads[c],
                command=lambda k=sortkey[c]: self._sort_by(k))
            self.tree.column(c, width=widths[c], anchor=anchors[c],
                             stretch=(c == "name"))
        for c in CAT_ORDER:
            self.tree.tag_configure(c, foreground=CATS[c]["color"])

        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    # ---- actions -----------------------------------------------------------
    def _build_actions(self):
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=10, pady=(0, 4))

        self.kill_btn = self._btn(bar, "END PROCESS", self.kill_selected,
                                  danger=True)
        self.kill_btn.pack(side="left", padx=3)
        self._btn(bar, "FILE LOCATION", self.open_location).pack(
            side="left", padx=3)
        self._btn(bar, "VERIFY SIGNATURE", self.verify_selected).pack(
            side="left", padx=3)
        self._btn(bar, "COPY PID", self.copy_pid).pack(side="left", padx=3)

        tk.Frame(bar, bg=DIMGREEN, width=1, height=18).pack(
            side="left", padx=8, fill="y")

        self._btn(bar, "STARTUP MANAGER", self.open_startup).pack(
            side="left", padx=3)
        self.auto_btn = self._btn(bar, "AUTO-REFRESH: ON",
                                  self.toggle_auto)
        self.auto_btn.pack(side="right", padx=3)
        self._btn(bar, "REFRESH", self.refresh).pack(side="right", padx=3)

    # ---- status bar --------------------------------------------------------
    def _build_statusbar(self):
        self.status = tk.Label(self, text="", bg="#0f160f", fg=GREEN,
                               font=FONT, anchor="w", padx=8)
        self.status.pack(fill="x", side="bottom")
        self._set_status("Select a process for details.")

    # ---- little factory ----------------------------------------------------
    def _btn(self, parent, text, cmd, danger=False):
        fg = "#ff6b6b" if danger else GREEN
        b = tk.Button(parent, text=text, command=cmd, bg=PANEL, fg=fg,
                      activebackground=SELECT_BG, activeforeground=fg,
                      font=FONT_B, bd=1, relief="ridge",
                      highlightbackground=DIMGREEN, padx=8, pady=2,
                      cursor="hand2")
        return b

    # ---- data flow ---------------------------------------------------------
    def refresh(self):
        procs = fetch_processes()
        now = time.time()

        # CPU% from tick deltas since last refresh.
        elapsed = (now - self._prev_time) if self._prev_time else 0
        denom = elapsed * 1e7 * self._ncpu if elapsed > 0 else 0
        cur_ticks = {}
        rows = []
        for p in procs:
            pid = p["pid"]
            cur_ticks[pid] = p["cpu_ticks"]
            cpu = 0.0
            if denom and pid in self._prev_ticks:
                delta = p["cpu_ticks"] - self._prev_ticks[pid]
                if delta > 0:
                    cpu = max(0.0, min(100.0, (delta / denom) * 100.0))
            cat = classify(p["name"], p["path"])
            rows.append({
                "cat": cat, "name": p["name"], "pid": pid,
                "cpu": cpu, "mem": p["mem"], "path": p["path"],
            })
        self._prev_ticks = cur_ticks
        self._prev_time = now
        self._rows = rows

        if not procs:
            self._set_status("Could not read processes. "
                             "Is PowerShell available? Try REFRESH.")
        self.render()

    def render(self):
        keep_pid = self._selected_pid()
        for i in self.tree.get_children():
            self.tree.delete(i)

        counts = {c: 0 for c in CAT_ORDER}
        total_mem = 0
        shown = 0
        rows = sorted(self._rows, key=self._sort_lambda(),
                      reverse=self._sort_desc)
        reselect = None
        for r in rows:
            counts[r["cat"]] += 1
            total_mem += r["mem"]
            if not self.filters[r["cat"]].get():
                continue
            shown += 1
            iid = str(r["pid"])
            self.tree.insert(
                "", "end", iid=iid, tags=(r["cat"],),
                values=(CATS[r["cat"]]["sym"], r["name"], r["pid"],
                        ("--" if r["cpu"] == 0 else "%.1f" % r["cpu"]),
                        human_mb(r["mem"])))
            if r["pid"] == keep_pid:
                reselect = iid
        if reselect:
            self.tree.selection_set(reselect)
            self.tree.see(reselect)

        parts = ["TOTAL %d" % len(self._rows)]
        for c in CAT_ORDER:
            parts.append("%s %d" % (c, counts[c]))
        self.summary.config(
            text="   ".join(parts) + "    MEM %s MB" % human_mb(total_mem))

    # ---- sorting -----------------------------------------------------------
    def _sort_lambda(self):
        key = self._sort_col
        if key == "cat":
            return lambda r: (CAT_ORDER.index(r["cat"]), -r["mem"])
        if key == "name":
            return lambda r: r["name"].lower()
        return lambda r: r.get(key, 0)

    def _sort_by(self, key):
        if self._sort_col == key:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_col = key
            self._sort_desc = key in ("mem", "cpu", "pid")
        self.render()

    # ---- selection helpers -------------------------------------------------
    def _selected_pid(self):
        sel = self.tree.selection()
        if not sel:
            return None
        try:
            return int(sel[0])
        except Exception:
            return None

    def _selected_row(self):
        pid = self._selected_pid()
        if pid is None:
            return None
        for r in self._rows:
            if r["pid"] == pid:
                return r
        return None

    def _on_select(self, _evt=None):
        r = self._selected_row()
        if not r:
            return
        meta = CATS[r["cat"]]
        kill_ok = meta["kill"]
        self.kill_btn.config(state=("normal" if kill_ok else "disabled"))
        loc = r["path"] if r["path"] else "(no on-disk image)"
        self._set_status("%s  |  %s  |  PID %d  |  %s" %
                         (r["name"], meta["desc"], r["pid"], loc))

    # ---- actions -----------------------------------------------------------
    def kill_selected(self):
        r = self._selected_row()
        if not r:
            return
        if not CATS[r["cat"]]["kill"]:
            messagebox.showwarning(
                "Locked",
                "%s is essential to Windows.\nEnding it will crash your "
                "session, so MANIFEST won't do it." % r["name"])
            return
        warn = ""
        if r["cat"] == "HW":
            warn = ("\n\nThis is a hardware/driver service - ending it may "
                    "disable audio, graphics, bluetooth or your keyboard "
                    "until you reboot.")
        if not messagebox.askyesno(
                "End process",
                "End %s (PID %d)?%s" % (r["name"], r["pid"], warn)):
            return
        try:
            res = subprocess.run(
                ["taskkill", "/PID", str(r["pid"]), "/F"],
                capture_output=True, text=True, creationflags=_NO_WIN)
            if res.returncode == 0:
                self._set_status("Ended %s (PID %d)." % (r["name"], r["pid"]))
            else:
                msg = (res.stderr or res.stdout or "").strip()
                if "Access is denied" in msg or "denied" in msg.lower():
                    msg += ("\n\nThis process runs as SYSTEM. Relaunch "
                            "MANIFEST as administrator to end it.")
                messagebox.showerror("Could not end process", msg)
        except Exception as e:
            messagebox.showerror("Error", str(e))
        self.refresh()

    def open_location(self):
        r = self._selected_row()
        if not r:
            return
        if not r["path"]:
            messagebox.showinfo("No file",
                                "This process has no on-disk image "
                                "(it lives in the kernel).")
            return
        try:
            subprocess.Popen('explorer /select,"%s"' % r["path"])
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def verify_selected(self):
        r = self._selected_row()
        if not r:
            return
        self._set_status("Checking signature for %s ..." % r["name"])
        self.update_idletasks()
        status, signer = verify_signature(r["path"])
        ok = status.lower() == "valid"
        icon = messagebox.showinfo if ok else messagebox.showwarning
        icon("Signature: %s" % status,
             "%s\n\nStatus : %s\nSigner : %s\n\n%s" % (
                 r["name"], status, signer,
                 "Valid Microsoft/vendor signature = genuine file."
                 if ok else
                 "Not a clean 'Valid' result. If this is an UNKNOWN "
                 "process in a user or temp folder, treat with suspicion."))
        self._on_select()

    def copy_pid(self):
        pid = self._selected_pid()
        if pid is None:
            return
        self.clipboard_clear()
        self.clipboard_append(str(pid))
        self._set_status("Copied PID %d to clipboard." % pid)

    def open_startup(self):
        # The real way to get a quieter boot: stop things auto-starting.
        try:
            os.system("start ms-settings:startupapps")
        except Exception:
            try:
                subprocess.Popen("taskmgr")
            except Exception:
                pass
        self._set_status("Opened Startup Apps - disable what you don't want "
                         "launching at boot.")

    # ---- filter presets ----------------------------------------------------
    def only_optional(self):
        for c in CAT_ORDER:
            self.filters[c].set(c in ("OEM", "YOU", "UNK"))
        self.render()

    def show_all(self):
        for c in CAT_ORDER:
            self.filters[c].set(True)
        self.render()

    # ---- refresh loop ------------------------------------------------------
    def toggle_auto(self):
        self._auto = not self._auto
        self.auto_btn.config(
            text="AUTO-REFRESH: %s" % ("ON" if self._auto else "OFF"))

    def _tick(self):
        if self._auto:
            self.refresh()
        self.after(REFRESH_SECONDS * 1000, self._tick)

    # ---- misc --------------------------------------------------------------
    def _set_status(self, text):
        self.status.config(text=text)


def main():
    if os.name != "nt":
        print("MANIFEST is a Windows tool (it reads processes via PowerShell).")
        # Still open the window so the layout can be inspected anywhere.
    app = Manifest()
    app.mainloop()


if __name__ == "__main__":
    main()
