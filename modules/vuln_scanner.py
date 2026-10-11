"""Vuln Scanner – echter lokaler Schwachstellen-Check (LIVE Systemdaten)."""
from __future__ import annotations

import os
import stat
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

TITLE = "Vuln Scanner"

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
apply_theme = apply_dark  # Alias: Module nutzen apply_theme()


def style_treeview(tv: ttk.Treeview) -> None:
    try:
        tv.tag_configure("KRITISCH", foreground=COLORS["crit"])
        tv.tag_configure("HOCH", foreground="#ff7043")
        tv.tag_configure("WARNUNG", foreground=COLORS["warn"])
        tv.tag_configure("MITTEL", foreground=COLORS["warn"])
        tv.tag_configure("INFO", foreground=COLORS["info"])
        tv.tag_configure("OK", foreground=COLORS["accent"])
    except tk.TclError:
        pass

try:
    from core.utils import run_cmd  # type: ignore
except Exception:
    def run_cmd(cmd, timeout=15, shell=False):
        try:
            p = subprocess.run(cmd, shell=shell if isinstance(cmd, str) else False,
                               capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout or "", p.stderr or ""
        except FileNotFoundError as e:
            return 127, "", f"Befehl nicht gefunden: {e}"
        except Exception as e:
            return 1, "", f"{type(e).__name__}: {e}"


def get_open_ports() -> list[dict]:
    """Echte liste lauschender TCP-Ports via `ss`, Fallback /proc/net/tcp."""
    import re
    import socket as _sock
    _services = {23: "telnet", 22: "ssh", 80: "http", 443: "https",
                 445: "smb", 139: "netbios-ssn", 3389: "rdp", 5900: "vnc",
                 6379: "redis", 27017: "mongodb", 11211: "memcached"}

    def _svc(port: int) -> str:
        if port in _services:
            return _services[port]
        try:
            return _sock.getservbyport(port)
        except OSError:
            return "unbekannt"

    rc, out, _ = run_cmd(["ss", "-tln"], timeout=10)
    if rc == 0 and out.strip():
        res, seen = [], set()
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("State"):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            m = re.search(r":(\d+)$", parts[4])
            if not m:
                continue
            try:
                port = int(m.group(1))
            except ValueError:
                continue
            addr = parts[4].rsplit(":", 1)[0]
            if (addr, port) not in seen:
                seen.add((addr, port))
                res.append({"addr": addr, "port": port, "service": _svc(port)})
        return sorted(res, key=lambda d: d["port"])
    # Fallback: /proc/net/tcp (nur LISTEN = 0A)
    res = []
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                rows = f.readlines()[1:]
        except (FileNotFoundError, PermissionError):
            continue
        for row in rows:
            p = row.split()
            if len(p) < 4 or p[3] != "0A":
                continue
            try:
                port = int(p[1].rsplit(":", 1)[1], 16)
            except (ValueError, IndexError):
                continue
            if all(r["port"] != port for r in res):
                res.append({"addr": "0.0.0.0", "port": port, "service": _svc(port)})
    return sorted(res, key=lambda d: d["port"])


# Port -> (Risiko, Empfehlung)
PORT_RISK = {
    23: ("KRITISCH", "Telnet überträgt Klartext – deaktivieren, SSH nutzen."),
    445: ("HOCH", "SMB – nur im LAN nötig, sonst schließen/blockieren."),
    139: ("HOCH", "NetBIOS – veraltet, deaktivieren falls ungenutzt."),
    3389: ("WARNUNG", "RDP – nur per VPN, starke Auth + Fail2ban."),
    5900: ("WARNUNG", "VNC – nur per SSH-Tunnel, starkes Passwort."),
    6379: ("WARNUNG", "Redis – nicht öffentlich, Auth + bind 127.0.0.1."),
    27017: ("WARNUNG", "MongoDB – Auth aktivieren, nicht öffentlich."),
    11211: ("WARNUNG", "Memcached – nie öffentlich (Amplification)."),
    21: ("WARNUNG", "FTP Klartext – SFTP/FTPS bevorzugen."),
    111: ("WARNUNG", "RPCBind – Angriffsfläche, falls ungenutzt schließen."),
    2049: ("WARNUNG", "NFS – Exports prüfen, auf LAN beschränken."),
    3306: ("WARNUNG", "MySQL – nicht öffentlich, starke Credentials."),
    5432: ("WARNUNG", "PostgreSQL – nicht öffentlich, starke Credentials."),
    2375: ("KRITISCH", "Docker-API unverschlüsselt – SOFORT schließen!"),
    22: ("INFO", "SSH – Key-Auth + Fail2ban empfohlen."),
    80: ("INFO", "HTTP – auf HTTPS umleiten."),
    443: ("INFO", "HTTPS – Zertifikat/TLS prüfen."),
}

RISK_DEDUCT = {"KRITISCH": 20, "HOCH": 12, "WARNUNG": 6, "MITTEL": 6, "INFO": 1}


def _classify_port(port: int, service: str):
    if port in PORT_RISK:
        return PORT_RISK[port]
    if service in ("telnet",):
        return ("KRITISCH", "Klartext-Protokoll – deaktivieren.")
    return ("INFO", "Prüfen, ob der Dienst benötigt wird.")


def build(parent, ctx) -> tk.Frame:
    apply_theme(parent)
    frame = ttk.Frame(parent, padding=10)
    findings: list[tuple[str, str, str]] = []  # (Bereich, Risiko, Detail)

    ttk.Label(frame, text=TITLE, style="Title.TLabel").pack(anchor="w")
    ttk.Label(frame, text="Echter lokaler Check – keine simulierten Daten.",
              style="Muted.TLabel").pack(anchor="w", pady=(0, 8))

    status_var = tk.StringVar(value="Bereit.")
    score_var = tk.StringVar(value="Score: –")

    top = ttk.Frame(frame)
    top.pack(fill="x", pady=(0, 6))
    btn_scan = ttk.Button(top, text="Vollscan starten")
    btn_scan.pack(side="left")
    ttk.Button(top, text="Report exportieren",
               command=lambda: _export()).pack(side="left", padx=6)
    ttk.Label(top, textvariable=score_var, font=("Segoe UI", 11, "bold")).pack(side="right")
    ttk.Label(frame, textvariable=status_var, style="Muted.TLabel").pack(anchor="w")

    # --- Sektion A: Ports ---
    sec_a = ttk.LabelFrame(frame, text="A · Offene Ports (Risiko-Analyse)", padding=6)
    sec_a.pack(fill="both", expand=False, pady=4)
    cols = ("port", "service", "risiko", "empfehlung")
    tv_ports = ttk.Treeview(sec_a, columns=cols, show="headings", height=6)
    for c, w, t in (("port", 70, "Port"), ("service", 110, "Service"),
                    ("risiko", 90, "Risiko"), ("empfehlung", 460, "Empfehlung")):
        tv_ports.heading(c, text=t)
        tv_ports.column(c, width=w, anchor="w")
    tv_ports.pack(fill="both", expand=True)
    style_treeview(tv_ports)

    # --- Sektion B: System-Checks ---
    sec_b = ttk.LabelFrame(frame, text="B · System-Checks (live)", padding=6)
    sec_b.pack(fill="both", expand=False, pady=4)
    txt_sys = tk.Text(sec_b, height=10, wrap="word",
                      bg=COLORS["bg2"], fg=COLORS["fg"],
                      insertbackground=COLORS["fg"], font=("Consolas", 9))
    txt_sys.pack(fill="both", expand=True)

    # --- Sektion C: Findings ---
    sec_c = ttk.LabelFrame(frame, text="C · Findings & Score (0–100)", padding=6)
    sec_c.pack(fill="both", expand=True, pady=4)
    tv_find = ttk.Treeview(sec_c, columns=("bereich", "risiko", "detail"),
                           show="headings", height=6)
    for c, w, t in (("bereich", 140, "Bereich"), ("risiko", 90, "Risiko"),
                    ("detail", 500, "Detail")):
        tv_find.heading(c, text=t)
        tv_find.column(c, width=w, anchor="w")
    tv_find.pack(fill="both", expand=True)
    style_treeview(tv_find)

    def ui_status(msg):
        parent.after(0, lambda: status_var.set(msg))

    def ui_sys_append(text):
        def _do():
            txt_sys.insert("end", text + "\n")
            txt_sys.see("end")
        parent.after(0, _do)

    def add_finding(bereich, risiko, detail):
        findings.append((bereich, risiko, detail))

        def _do():
            tv_find.insert("", "end", values=(bereich, risiko, detail), tags=(risiko,))
        parent.after(0, _do)

    # ---- Scan-Schritte (laufen im Thread) ----
    def step_ports():
        ui_status("A: Lese offene Ports (ss /proc)…")
        try:
            ports = get_open_ports()
        except Exception as e:
            ui_sys_append(f"[Ports] Fehler: {e}")
            add_finding("Ports", "INFO", f"Port-Abfrage fehlgeschlagen: {e}")
            return
        if not ports:
            ui_sys_append("[Ports] Keine lauschenden TCP-Ports gefunden (oder ss fehlt).")
            add_finding("Ports", "OK", "Keine offenen TCP-Ports erkannt.")
            return
        for entry in ports:
            try:
                port = int(entry.get("port"))
                service = str(entry.get("service", "unbekannt"))
                addr = str(entry.get("addr", ""))
            except (ValueError, AttributeError):
                continue
            risiko, empf = _classify_port(port, service)
            detail = f"Port {port}/{service} auf {addr}: {empf}"
            if risiko in ("KRITISCH", "HOCH", "WARNUNG"):
                add_finding("Ports", risiko, detail)
            parent.after(0, lambda p=port, s=service, r=risiko, e=empf:
                         tv_ports.insert("", "end", values=(p, s, r, e), tags=(r,)))

    def step_apt():
        ui_status("B1: Prüfe apt-Updates…")
        rc, out, err = run_cmd(["apt", "list", "--upgradable"], timeout=30)
        if rc != 0:
            msg = (err or out or "unbekannter Fehler").strip().splitlines()
            ui_sys_append(f"[APT] Nicht prüfbar: {msg[0] if msg else rc}")
            add_finding("Updates", "INFO", f"apt-Check nicht möglich ({msg[0] if msg else rc}).")
            return
        lines = [l for l in out.splitlines()
                 if l and not l.startswith("Listing")]
        ui_sys_append(f"[APT] {len(lines)} aktualisierbare Pakete.")
        for l in lines[:15]:
            ui_sys_append(f"  · {l[:120]}")
        if len(lines) >= 20:
            add_finding("Updates", "HOCH", f"{len(lines)} Pakete aktualisierbar – `sudo apt upgrade` empfohlen.")
        elif len(lines) >= 1:
            add_finding("Updates", "WARNUNG", f"{len(lines)} Pakete aktualisierbar.")
        else:
            add_finding("Updates", "OK", "System aktuell (keine upgradable Pakete).")

    def step_ufw():
        ui_status("B2: Prüfe UFW-Status…")
        rc, out, err = run_cmd(["ufw", "status", "verbose"], timeout=10)
        text = (out or err or "").strip()
        first = text.splitlines()[0] if text else "ufw nicht auslesbar"
        ui_sys_append(f"[UFW] {first[:140]}")
        if rc != 0 or "not installed" in text.lower() or "command not found" in (err or "").lower():
            add_finding("Firewall", "WARNUNG", "UFW-Status nicht lesbar (nicht installiert / keine Rechte).")
        elif "inactive" in text.lower():
            add_finding("Firewall", "WARNUNG", "UFW ist INAKTIV – Firewall aktivieren empfohlen.")
        elif "active" in text.lower():
            add_finding("Firewall", "OK", "UFW ist aktiv.")

    def step_ssh():
        ui_status("B3: Prüfe SSH-Berechtigungen…")
        ssh_dir = os.path.expanduser("~/.ssh")
        if not os.path.isdir(ssh_dir):
            ui_sys_append("[SSH] Kein ~/.ssh Verzeichnis – OK (kein Key-Material).")
            add_finding("SSH", "OK", "Kein ~/.ssh vorhanden.")
            return
        try:
            mode = stat.S_IMODE(os.stat(ssh_dir).st_mode)
        except OSError as e:
            add_finding("SSH", "INFO", f"~/.ssh nicht prüfbar: {e}")
            return
        ui_sys_append(f"[SSH] ~/.ssh Modus: {oct(mode)}")
        if mode & 0o077:
            add_finding("SSH", "HOCH", f"~/.ssh zu offen ({oct(mode)} statt 0700) – `chmod 700 ~/.ssh`.")
        else:
            add_finding("SSH", "OK", "~/.ssh Rechte OK (0700).")
        for name in ("id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys", "config"):
            p = os.path.join(ssh_dir, name)
            if os.path.isfile(p):
                try:
                    m = stat.S_IMODE(os.stat(p).st_mode)
                except OSError:
                    continue
                ui_sys_append(f"[SSH] {name}: {oct(m)}")
                if name == "authorized_keys" and m & 0o077:
                    add_finding("SSH", "WARNUNG", f"{name} zu offen ({oct(m)}) – sollte 0600 sein.")
                elif name.startswith("id_") and name != "id_rsa.pub" and m & 0o077:
                    add_finding("SSH", "HOCH", f"Privater Key {name} zu offen ({oct(m)}) – `chmod 600`.")
        # sshd_config global lesbar?
        for cfg in ("/etc/ssh/sshd_config",):
            if os.path.isfile(cfg):
                ui_sys_append(f"[SSH] {cfg} vorhanden.")

    def step_world_writable():
        ui_status("B4: Suche world-writable Dateien (/home, maxdepth 3)…")
        rc, out, err = run_cmd(
            ["find", "/home", "-maxdepth", "3", "-type", "f", "-perm", "-0002",
             "-print"], timeout=25)
        if rc != 0:
            ui_sys_append(f"[WW] find-Fehler: {(err or out)[:150]}")
            add_finding("Dateirechte", "INFO", "World-writable-Scan abgebrochen/fehlerhaft.")
            return
        files = [l for l in out.splitlines() if l][:20]
        ui_sys_append(f"[WW] {len(files)} Treffer (max. 20 gezeigt).")
        for f in files:
            ui_sys_append(f"  · {f}")
        if files:
            add_finding("Dateirechte", "WARNUNG",
                        f"{len(files)} world-writable Dateien unter /home (Tiefe 3).")
        else:
            add_finding("Dateirechte", "OK", "Keine world-writable Dateien (Tiefe 3).")

    def step_suid():
        ui_status("B5: Suche SUID-Binaries (/usr/bin)…")
        rc, out, err = run_cmd(
            ["find", "/usr/bin", "-maxdepth", "2", "-type", "f", "-perm", "-4000",
             "-print"], timeout=25)
        if rc != 0:
            ui_sys_append(f"[SUID] find-Fehler: {(err or out)[:150]}")
            add_finding("SUID", "INFO", "SUID-Scan fehlerhaft.")
            return
        bins = [l for l in out.splitlines() if l][:30]
        ui_sys_append(f"[SUID] {len(bins)} SUID-Dateien (max. 30 gezeigt).")
        unusual = [b for b in bins
                   if os.path.basename(b) not in
                   ("sudo", "su", "mount", "umount", "passwd", "chsh", "chfn",
                    "newgrp", "gpasswd", "pkexec", "fusermount3", "ntfs-3g")]
        for b in bins[:10]:
            ui_sys_append(f"  · {b}")
        if unusual:
            add_finding("SUID", "WARNUNG",
                        f"Auffällige SUID-Binaries: {', '.join(unusual[:5])}")
        else:
            add_finding("SUID", "OK", f"{len(bins)} SUID-Binaries, keine Auffälligkeit.")

    def compute_score():
        score = 100
        for _, risiko, _ in findings:
            score -= RISK_DEDUCT.get(risiko, 0)
        score = max(0, min(100, score))
        parent.after(0, lambda: score_var.set(f"Score: {score}/100"))
        if score >= 90:
            level = "OK – gute Basis-Hygiene."
        elif score >= 70:
            level = "WARNUNG – Härtung empfohlen."
        else:
            level = "KRITISCH – zeitnah härten!"
        ui_sys_append(f"[Score] {score}/100 – {level}")
        return score

    def full_scan():
        btn_scan.configure(state="disabled")
        findings.clear()
        for tv in (tv_ports, tv_find):
            parent.after(0, lambda t=tv: t.delete(*t.get_children()))
        parent.after(0, lambda: txt_sys.delete("1.0", "end"))
        parent.after(0, lambda: score_var.set("Score: …"))
        try:
            for step in (step_ports, step_apt, step_ufw, step_ssh,
                         step_world_writable, step_suid):
                step()
            compute_score()
            ui_status("Vollscan abgeschlossen.")
        except Exception as e:  # ehrlich melden
            ui_status(f"Scan abgebrochen: {e}")
            ui_sys_append(f"[FEHLER] {e}")
        finally:
            parent.after(0, lambda: btn_scan.configure(state="normal"))

    def _export():
        score_txt = score_var.get()
        if not findings:
            messagebox.showinfo("Report", "Keine Findings – erst Vollscan starten.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text", "*.txt")],
            initialfile="vuln_report.txt", title="Report speichern")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"Vuln-Scanner Report – {score_txt}\n{'=' * 50}\n")
                for b, r, d in findings:
                    f.write(f"[{r}] {b}: {d}\n")
            messagebox.showinfo("Report", f"Gespeichert:\n{path}")
        except OSError as e:
            messagebox.showerror("Report", f"Speichern fehlgeschlagen:\n{e}")

    btn_scan.configure(command=lambda: threading.Thread(
        target=full_scan, daemon=True).start())

    return frame
