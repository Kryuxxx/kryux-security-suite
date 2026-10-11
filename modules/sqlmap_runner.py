"""SQLMap Runner - LIVE Scans mit Safety-Consent (keine Fake-Scans).

Vertrag: TITLE + build(parent, ctx) -> tk.Frame.
Nutzt core.theme (COLORS, FONTS) und core.utils defensiv (mit Fallbacks).
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core.theme import COLORS as _COLORS, FONTS as _FONTS  # type: ignore
except Exception:
    _COLORS, _FONTS = {}, {}

try:
    from core.utils import install_hint as _install_hint, run_stream as _run_stream  # type: ignore
    from core.utils import which_tool as _which_tool  # type: ignore
except Exception:
    _install_hint = _run_stream = _which_tool = None


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


TITLE = "SQLMap"


def build(parent, ctx) -> tk.Frame:
    root = tk.Frame(parent, bg=BG)
    stop_event = threading.Event()
    state = {"busy": False, "full_log": []}

    def lab(prt, text, fg=None, font=None):
        return tk.Label(prt, text=text, bg=BG, fg=fg or FG, font=font or F_NORM)

    def btn(prt, text, cmd, fg=None):
        return tk.Button(prt, text=text, command=cmd, bg=PANEL, fg=fg or ACCENT,
                         activebackground=BORDER, activeforeground=ACCENT,
                         relief="groove", bd=1, font=F_NORM)

    def ent(prt, var, width=60):
        return tk.Entry(prt, textvariable=var, width=width, bg=ENTRY_BG, fg=FG, font=F_NORM,
                        insertbackground=ACCENT, relief="flat", highlightthickness=1,
                        highlightbackground=BORDER, highlightcolor=ACCENT)

    lab(root, "SQLMap Runner (nur eigenes Labor!)", fg=ACCENT, font=F_TITLE).pack(
        anchor="w", padx=8, pady=(8, 0))
    status = lab(root, "", fg=MUTED, font=F_SMALL)
    status.pack(anchor="w", padx=8)

    if which_tool("sqlmap") is None:
        status.config(text=f"[!] sqlmap fehlt -> {install_hint('sqlmap')}", fg=DANGER)
    else:
        status.config(text=f"[OK] sqlmap: {which_tool('sqlmap')}", fg=OK)

    form = tk.Frame(root, bg=BG)
    form.pack(fill="x", padx=8, pady=4)

    lab(form, "Target-URL:").grid(row=0, column=0, sticky="w")
    url_var = tk.StringVar(value="http://localhost:8080/vuln.php?id=1")
    ent(form, url_var).grid(row=0, column=1, columnspan=3, sticky="ew", padx=6, pady=2)

    lab(form, "Level:").grid(row=1, column=0, sticky="w")
    level_var = tk.StringVar(value="1")
    ttk.Combobox(form, textvariable=level_var, values=["1", "2", "3"],
                 width=5, state="readonly").grid(row=1, column=1, sticky="w", padx=6)
    lab(form, "Risk:").grid(row=1, column=2, sticky="w")
    risk_var = tk.StringVar(value="1")
    ttk.Combobox(form, textvariable=risk_var, values=["1", "2", "3"],
                 width=5, state="readonly").grid(row=1, column=3, sticky="w")

    lab(form, "Cookie:").grid(row=2, column=0, sticky="w")
    cookie_var = tk.StringVar(value="")
    ent(form, cookie_var).grid(row=2, column=1, columnspan=3, sticky="ew", padx=6, pady=2)

    lab(form, "Custom-Args:").grid(row=3, column=0, sticky="w")
    custom_var = tk.StringVar(value="")
    ent(form, custom_var).grid(row=3, column=1, columnspan=3, sticky="ew", padx=6, pady=2)
    form.columnconfigure(1, weight=1)

    checks = tk.Frame(root, bg=BG)
    checks.pack(fill="x", padx=8)
    vars_ = {}
    for name, default in [("batch", True), ("forms", False), ("crawl", False),
                          ("dbs", False), ("tables", False)]:
        v = tk.BooleanVar(value=default)
        vars_[name] = v
        tk.Checkbutton(checks, text=f"--{name}" + ("=2" if name == "crawl" else ""),
                       variable=v, bg=BG, fg=FG, selectcolor=PANEL,
                       activebackground=BG, activeforeground=ACCENT, font=F_NORM).pack(side="left", padx=4)

    consent_var = tk.BooleanVar(value=False)
    tk.Checkbutton(root, text="Ich teste nur mein eigenes Labor", variable=consent_var,
                   bg=BG, fg=WARN, selectcolor=PANEL, activebackground=BG,
                   activeforeground=WARN, font=F_NORM).pack(anchor="w", padx=8, pady=4)

    btns = tk.Frame(root, bg=BG)
    btns.pack(fill="x", padx=8, pady=2)

    paned = tk.PanedWindow(root, orient="vertical", bg=BORDER, sashwidth=3)
    paned.pack(fill="both", expand=True, padx=8, pady=4)
    f_raw = tk.Frame(paned, bg=BG)
    f_eval = tk.Frame(paned, bg=BG)
    lab(f_raw, "Live-Output:").pack(anchor="w")
    txt_raw = scrolledtext.ScrolledText(f_raw, height=12, bg=ENTRY_BG, fg=FG, font=F_NORM,
                                        insertbackground=ACCENT, relief="flat",
                                        highlightthickness=1, highlightbackground=BORDER)
    txt_raw.pack(fill="both", expand=True)
    lab(f_eval, "Auswertung:").pack(anchor="w")
    txt_eval = scrolledtext.ScrolledText(f_eval, height=6, bg=ENTRY_BG, fg=FG, font=F_NORM,
                                         insertbackground=ACCENT, relief="flat",
                                         highlightthickness=1, highlightbackground=BORDER)
    txt_eval.pack(fill="both", expand=True)
    paned.add(f_raw)
    paned.add(f_eval)

    def ui(fn, *a, **kw):
        root.after(0, lambda: fn(*a, **kw))

    def log_raw(msg):
        txt_raw.insert("end", msg + "\n")
        txt_raw.see("end")

    def build_cmd(extra=None):
        url = url_var.get().strip()
        cmd = ["sqlmap", "-u", url, "--level", level_var.get(), "--risk", risk_var.get()]
        if vars_["batch"].get():
            cmd.append("--batch")
        if vars_["forms"].get():
            cmd.append("--forms")
        if vars_["crawl"].get():
            cmd.append("--crawl=2")
        if vars_["dbs"].get():
            cmd.append("--dbs")
        if vars_["tables"].get():
            cmd.append("--tables")
        if cookie_var.get().strip():
            cmd += ["--cookie", cookie_var.get().strip()]
        if custom_var.get().strip():
            cmd += shlex.split(custom_var.get().strip())
        if extra:
            cmd += extra
        return cmd

    def check_safety():
        if not url_var.get().strip():
            messagebox.showwarning("Eingabe fehlt", "Bitte Target-URL eingeben.")
            return False
        if not consent_var.get():
            messagebox.showwarning("Safety-Block",
                                   "Start blockiert: Bitte 'Ich teste nur mein eigenes Labor' bestätigen.")
            ui(log_raw, "[!] Start blockiert: Consent-Checkbox fehlt.")
            return False
        if which_tool("sqlmap") is None:
            messagebox.showerror("sqlmap fehlt", f"Installieren:\n{install_hint('sqlmap')}")
            ui(log_raw, f"[!] sqlmap fehlt -> {install_hint('sqlmap')}")
            return False
        if state["busy"]:
            messagebox.showinfo("Läuft", "Scan läuft bereits. Erst stoppen.")
            return False
        return True

    def start_scan(cmd):
        stop_event.clear()
        state["busy"] = True
        state["full_log"] = []
        ui(log_raw, "$ " + " ".join(shlex.quote(c) for c in cmd))

        def worker():
            def on_line(line):
                state["full_log"].append(line)
                ui(log_raw, line)

            rc = run_stream(cmd, on_line=on_line, stop_event=stop_event)
            if rc == -9:
                ui(log_raw, "[*] Abgebrochen (Stop).")
                ui(analyze, True)
            else:
                ui(log_raw, f"[*] Fertig (Exit {rc}).")
                ui(analyze, False)
            state["busy"] = False

        threading.Thread(target=worker, daemon=True).start()

    def analyze(aborted=False):
        txt_eval.delete("1.0", "end")
        full = state["full_log"]
        txt_eval.insert("end", f"--- Auswertung ({'abgebrochen' if aborted else 'abgeschlossen'}, "
                               f"{len(full)} Zeilen) ---\n")
        hits_inj = [l for l in full if "injectable" in l.lower()]
        hits_vuln = [l for l in full if "vulnerable" in l.lower()]
        hits_not = [l for l in full if "not injectable" in l.lower()]
        if hits_inj:
            txt_eval.insert("end", f"[+] 'injectable' Treffer: {len(hits_inj)} -> Parameter verwundbar!\n")
            for h in hits_inj[:15]:
                txt_eval.insert("end", "    " + h.strip() + "\n")
        if hits_vuln:
            txt_eval.insert("end", f"[+] 'vulnerable' Treffer: {len(hits_vuln)}\n")
            for h in hits_vuln[:15]:
                txt_eval.insert("end", "    " + h.strip() + "\n")
        if hits_not and not hits_inj:
            txt_eval.insert("end", "[-] 'not injectable': keine Injection gefunden (stichprobenartig).\n")
        if not hits_inj and not hits_vuln and not hits_not:
            txt_eval.insert("end", "[?] Keine eindeutigen Keywords gefunden. Roh-Output manuell prüfen.\n")
        for kw in ("back-end dbms", "banner", "current database", "available databases"):
            for ln in full:
                if kw in ln.lower():
                    txt_eval.insert("end", f"  {ln.strip()}\n")
                    break
        txt_eval.see("end")

    def on_start():
        if check_safety():
            start_scan(build_cmd())

    def on_stop():
        stop_event.set()
        ui(log_raw, "[*] Stop angefordert ...")

    def on_clear():
        txt_raw.delete("1.0", "end")
        txt_eval.delete("1.0", "end")
        state["full_log"] = []

    def preset_dbms():
        custom_var.set("--banner --fingerprint")
        vars_["dbs"].set(False)
        if check_safety():
            start_scan(build_cmd())

    def preset_dbs():
        custom_var.set("")
        vars_["dbs"].set(True)
        if check_safety():
            start_scan(build_cmd())

    btn(btns, "Start", on_start).pack(side="left", padx=3)
    btn(btns, "Stop", on_stop, fg=DANGER).pack(side="left", padx=3)
    btn(btns, "Leeren", on_clear, fg=WARN).pack(side="left", padx=3)
    btn(btns, "Info: DBMS version", preset_dbms).pack(side="left", padx=8)
    btn(btns, "Datenbanken auflisten", preset_dbs).pack(side="left", padx=3)

    return root
