"""Firewall Manager – echte Verwaltung (ufw / firewall-cmd / iptables)."""
from __future__ import annotations

import re
import shutil
import threading
import tkinter as tk
from tkinter import ttk, messagebox

TITLE = "Firewall Manager"

# --- core.theme / core.utils (echte Suite-API, mit Fallback) ---
try:
    from core.theme import apply_dark, COLORS as _C  # type: ignore
except Exception:
    _C = {}

    def apply_dark(root):
        return ttk.Style(root)

if not isinstance(_C, dict):
    _C = {}
COLORS = {
    "bg": _C.get("bg", "#121417"),
    "bg2": _C.get("panel", "#1a1e24"),
    "card": _C.get("panel", "#1e242c"),
    "fg": _C.get("text", "#e8eaed"),
    "muted": _C.get("dim", "#9aa0a6"),
    "accent": _C.get("neon", "#00c853"),
    "warn": _C.get("amber", "#ffab00"),
    "crit": _C.get("red", "#ff5252"),
    "info": _C.get("cyan", "#40c4ff"),
}
apply_theme = apply_dark


def style_treeview(tv: ttk.Treeview) -> None:
    pass  # Basestyling kommt aus core.theme (apply_dark)

try:
    from core.utils import run_cmd  # type: ignore
except Exception:
    import subprocess as _sp

    def run_cmd(cmd, timeout=15, shell=False):
        try:
            p = _sp.run(cmd, shell=shell if isinstance(cmd, str) else False,
                        capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout or "", p.stderr or ""
        except Exception as e:
            return 1, "", str(e)

try:
    from core.utils import which_tool as _which_tool  # type: ignore
except Exception:
    _which_tool = None


def which(b: str) -> str:
    if _which_tool is not None:
        try:
            return _which_tool(b) or ""
        except Exception:
            pass
    return shutil.which(b) or ""


def detect_backend() -> str:
    if which("ufw"):
        return "ufw"
    if which("firewall-cmd"):
        return "firewalld"
    if which("iptables"):
        return "iptables"
    return "keins"


def pkexec_prefix() -> list[str]:
    if which("pkexec"):
        return ["pkexec"]
    return ["sudo", "-n"]  # -n: scheitert ehrlich statt zu hängen, Hinweis folgt


def parse_ufw_numbered(out: str) -> list[tuple[str, str, str]]:
    """Parst `ufw status numbered` -> [(Nr, To, Action/From)]."""
    rules = []
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*(\d+)\s*\]\s+(.+?)\s+(.+)", line)
        if m:
            rules.append((m.group(1).strip(), m.group(2).strip(), m.group(3).strip()))
    return rules


def build(parent, ctx) -> tk.Frame:
    apply_theme(parent)
    frame = ttk.Frame(parent, padding=10)
    backend = detect_backend()

    ttk.Label(frame, text=TITLE, style="Title.TLabel").pack(anchor="w")
    info_var = tk.StringVar(value=f"Backend: {backend}")
    ttk.Label(frame, textvariable=info_var, style="Muted.TLabel").pack(anchor="w", pady=(0, 6))

    out_var = tk.StringVar(value="Bereit.")
    ttk.Label(frame, textvariable=out_var, style="Muted.TLabel").pack(anchor="w")

    # --- Status + Regeln ---
    paned = ttk.Frame(frame)
    paned.pack(fill="both", expand=True, pady=4)

    left = ttk.LabelFrame(paned, text="Status", padding=6)
    left.pack(side="left", fill="both", expand=True, padx=(0, 4))
    txt_status = tk.Text(left, height=14, wrap="word", bg=COLORS["bg2"],
                         fg=COLORS["fg"], insertbackground=COLORS["fg"],
                         font=("Consolas", 9))
    txt_status.pack(fill="both", expand=True)

    right = ttk.LabelFrame(paned, text="Regeln (ufw numbered)", padding=6)
    right.pack(side="left", fill="both", expand=True, padx=(4, 0))
    tv = ttk.Treeview(right, columns=("nr", "to", "action"), show="headings", height=12)
    for c, w, t in (("nr", 50, "Nr"), ("to", 170, "To"), ("action", 220, "Action/From")):
        tv.heading(c, text=t)
        tv.column(c, width=w, anchor="w")
    tv.pack(fill="both", expand=True)
    style_treeview(tv)

    # --- Form: Regel hinzufügen ---
    form = ttk.LabelFrame(frame, text="Regel hinzufügen", padding=6)
    form.pack(fill="x", pady=4)
    action_var = tk.StringVar(value="allow")
    proto_var = tk.StringVar(value="tcp")
    port_var = tk.StringVar(value="22")
    from_var = tk.StringVar(value="")
    comment_var = tk.StringVar(value="")
    ttk.Label(form, text="Action:").grid(row=0, column=0, sticky="w")
    ttk.Combobox(form, textvariable=action_var, values=["allow", "deny"],
                 width=8, state="readonly").grid(row=0, column=1, padx=4)
    ttk.Label(form, text="Proto:").grid(row=0, column=2, sticky="w")
    ttk.Combobox(form, textvariable=proto_var, values=["tcp", "udp", "any"],
                 width=8, state="readonly").grid(row=0, column=3, padx=4)
    ttk.Label(form, text="Port:").grid(row=0, column=4, sticky="w")
    ttk.Entry(form, textvariable=port_var, width=8).grid(row=0, column=5, padx=4)
    ttk.Label(form, text="From-IP (opt):").grid(row=0, column=6, sticky="w")
    ttk.Entry(form, textvariable=from_var, width=16).grid(row=0, column=7, padx=4)
    ttk.Label(form, text="Kommentar:").grid(row=1, column=0, sticky="w", pady=4)
    ttk.Entry(form, textvariable=comment_var, width=30).grid(
        row=1, column=1, columnspan=4, sticky="we", padx=4, pady=4)
    ttk.Button(form, text="Hinzufügen",
               command=lambda: _thread(_add_rule)).grid(row=1, column=7, pady=4)

    # --- Löschen + Logging + Power ---
    bottom = ttk.Frame(frame)
    bottom.pack(fill="x", pady=4)
    del_var = tk.StringVar(value="")
    ttk.Label(bottom, text="Nr löschen:").pack(side="left")
    ttk.Entry(bottom, textvariable=del_var, width=6).pack(side="left", padx=4)
    ttk.Button(bottom, text="Löschen",
               command=lambda: _thread(_del_rule)).pack(side="left", padx=4)
    ttk.Label(bottom, text="Logging:").pack(side="left", padx=(12, 2))
    log_var = tk.StringVar(value="low")
    ttk.Combobox(bottom, textvariable=log_var,
                 values=["off", "low", "medium", "high"],
                 width=8, state="readonly").pack(side="left")
    ttk.Button(bottom, text="Setzen",
               command=lambda: _thread(_set_logging)).pack(side="left", padx=4)
    ttk.Button(bottom, text="Refresh",
               command=lambda: _thread(refresh)).pack(side="right", padx=2)
    ttk.Button(bottom, text="UFW enable",
               command=lambda: _thread(lambda: _power(True))).pack(side="right", padx=2)
    ttk.Button(bottom, text="UFW disable",
               command=lambda: _thread(lambda: _power(False))).pack(side="right", padx=2)

    def _thread(fn):
        threading.Thread(target=fn, daemon=True).start()

    def show(msg: str):
        def _do():
            out_var.set(msg[:300])
            txt_status.insert("end", msg + "\n")
            txt_status.see("end")
        parent.after(0, _do)

    def need_pkexec_note(cmd: list[str]) -> str:
        if cmd[0] == "sudo":
            return ("\nHinweis: kein pkexec gefunden – `sudo -n` fragt NICHT nach "
                    "Passwort. Bei Bedarf im Terminal ausführen.")
        return ("\nHinweis: Passwort-Abfrage erscheint ggf. in einem "
                "System-Dialog (pkexec).")

    def refresh():
        parent.after(0, lambda: tv.delete(*tv.get_children()))
        parent.after(0, lambda: txt_status.delete("1.0", "end"))
        be = detect_backend()
        parent.after(0, lambda: info_var.set(f"Backend: {be}"))
        if be == "ufw":
            rc, out, err = run_cmd(["ufw", "status", "verbose"], timeout=10)
            show((out or err or f"(rc={rc})").strip() or "Keine Ausgabe.")
            rc2, out2, err2 = run_cmd(["ufw", "status", "numbered"], timeout=10)
            if rc2 == 0:
                for nr, to, act in parse_ufw_numbered(out2):
                    parent.after(0, lambda n=nr, t=to, a=act:
                                 tv.insert("", "end", values=(n, t, a)))
            else:
                show(f"Regel-Liste fehlgeschlagen: {(err2 or out2)[:200]}")
        elif be == "firewalld":
            rc, out, err = run_cmd(["firewall-cmd", "--state"], timeout=10)
            show(f"firewalld state: {(out or err).strip()}")
            rc, out, err = run_cmd(["firewall-cmd", "--list-all"], timeout=10)
            show((out or err or "").strip() or "Keine Ausgabe.")
        elif be == "iptables":
            rc, out, err = run_cmd(
                ["iptables", "-L", "-n", "--line-numbers"], timeout=10)
            show((out or err or f"(rc={rc})").strip() or "Keine Ausgabe.")
        else:
            show("Kein Firewall-Backend gefunden (ufw/firewall-cmd/iptables).")

    def _priv(cmd: list[str], what: str):
        """Führt privilegierte Aktion aus, ehrliche Fehler statt Fake-Erfolg."""
        full = pkexec_prefix() + cmd
        show(f"$ {' '.join(full)}")
        rc, out, err = run_cmd(full, timeout=30)
        text = ((out or "") + ("\n" + err if err else "")).strip()
        if rc == 0:
            show(f"OK – {what}:\n{text[:1500] or '(keine Ausgabe)'}")
        else:
            show(f"FEHLER (rc={rc}) – {what} NICHT ausgeführt:\n"
                 f"{text[:1500] or 'keine Details'}"
                 f"{need_pkexec_note(full)}")
        refresh()

    def _add_rule():
        action, proto = action_var.get(), proto_var.get()
        port = port_var.get().strip()
        src = from_var.get().strip()
        comment = comment_var.get().strip()
        if not re.fullmatch(r"\d{1,5}", port) or not (1 <= int(port) <= 65535):
            parent.after(0, lambda: messagebox.showerror(
                "Firewall", "Ungültiger Port (1–65535)."))
            return
        cmd = ["ufw", action]
        if src:
            cmd += ["from", src]
        cmd += ["to", "any", "port", port]
        if proto != "any":
            cmd += ["proto", proto]
        if comment:
            cmd += ["comment", comment]
        _priv(cmd, "Regel hinzugefügt")

    def _del_rule():
        nr = del_var.get().strip()
        if not re.fullmatch(r"\d+", nr):
            parent.after(0, lambda: messagebox.showerror(
                "Firewall", "Bitte gültige Regel-Nummer eingeben."))
            return
        ok = messagebox.askyesno("Regel löschen",
                                 f"UFW-Regel Nr. {nr} wirklich löschen?")
        if not ok:
            return
        _priv(["ufw", "--force", "delete", nr], f"Regel {nr} gelöscht")

    def _set_logging():
        _priv(["ufw", "logging", log_var.get()], f"Logging={log_var.get()}")

    def _power(enable: bool):
        word = "enable" if enable else "disable"
        ok = messagebox.askyesno(
            "UFW", f"UFW wirklich {word}? SSH-Zugang kann verloren gehen!")
        if not ok:
            return
        flag = "--force" if enable else ""
        cmd = ["ufw", word] if not flag else ["ufw", "--force", word]
        _priv(cmd, f"UFW {word}")

    _thread(refresh)
    return frame
