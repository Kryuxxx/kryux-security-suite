"""KRYUX — Setup & Install: Tool-Versorgung auf jedem System.

Zeigt OS-Erkennung, Status aller Kern-Tools und öffnet pro Tool die
Installations-Anleitung (Kali-apt, Ubuntu-Alternativen, Go, Gem, Git, Docker).
Optional: Direkt-Installation via pkexec apt (nur wenn apt das Paket kennt).
"""
from __future__ import annotations
import threading
import tkinter as tk
from tkinter import ttk

from core.theme import COLORS, FONTS, card, pill
from core.utils import which_tool, run_cmd
from core.installer import detect_os, get_install_options, show_install_dialog

TITLE = "Setup & Install"

# Kern-Tools mit Prüfnamen (cmd) und apt-Paket (pkg)
KEY_TOOLS: list[tuple[str, str, str]] = [
    ("nmap", "nmap", "Port-Scanner"),
    ("nikto", "nikto", "Web-Schwachstellen (Ubuntu: Git!)"),
    ("sqlmap", "sqlmap", "SQL-Injection (Labor)"),
    ("msfconsole", "metasploit-framework", "Exploit-Framework"),
    ("gobuster", "gobuster", "Verzeichnis-Enum"),
    ("ffuf", "ffuf", "Web-Fuzzing"),
    ("hydra", "hydra", "Login-Tests (Labor)"),
    ("john", "john", "Passwort-Audit (eigene Hashes)"),
    ("hashcat", "hashcat", "GPU-Cracking (eigene Hashes)"),
    ("tshark", "tshark", "Paketanalyse (CLI)"),
    ("wireshark", "wireshark", "Paketanalyse (GUI)"),
    ("yara", "yara", "Malware-Regeln"),
    ("binwalk", "binwalk", "Firmware-Analyse"),
    ("theHarvester", "theharvester", "OSINT E-Mails/Subdomains"),
    ("amass", "amass", "Subdomain-Enum"),
    ("searchsploit", "exploitdb", "Exploit-Datenbank"),
    ("wpscan", "wpscan", "WordPress-Scan (Gem!)"),
    ("whatweb", "whatweb", "Web-Fingerprint"),
    ("ufw", "ufw", "Firewall"),
    ("tcpdump", "tcpdump", "Sniffer"),
    ("aircrack-ng", "aircrack-ng", "WLAN-Audit"),
    ("lynis", "lynis", "System-Audit"),
    ("rkhunter", "rkhunter", "Rootkit-Check"),
    ("crunch", "crunch", "Wortlisten-Generator"),
]


def build(parent: tk.Widget, ctx) -> tk.Frame:
    root = tk.Frame(parent, bg=COLORS["bg"])

    # --- OS-Karte ---
    top = card(root, "⬢ System & Versorgung",
               "Warum apt auf Ubuntu scheitert: Ubuntu-Repos enthalten keine Kali-Pakete.")
    try:
        import platform
        osline = f"{platform.system()} {platform.release()}  •  Erkannt: {detect_os()}  •  Python {platform.python_version()}"
    except Exception:
        osline = f"Erkannt: {detect_os()}"
    tk.Label(top, text=osline, bg=COLORS.get("card", COLORS["panel"]),
             fg=COLORS["cyan"], font=FONTS["mono"]).pack(anchor="w")
    tk.Label(top, text="Go-Tools brauchen:  export PATH=$PATH:~/go/bin   •   Pipx:  sudo apt install pipx",
             bg=COLORS.get("card", COLORS["panel"]),
             fg=COLORS["dim"], font=FONTS["small"]).pack(anchor="w", pady=(4, 0))

    # --- Tool-Tabelle ---
    body = card(root, "🔧 Kern-Tools — Status & Installation",
                "● = bereit   ○ = fehlt → „Anleitung“ öffnen (Ubuntu-Alternativen inklusive)")
    rows = tk.Frame(body, bg=COLORS.get("card", COLORS["panel"]))
    rows.pack(fill="x")

    out = tk.Text(body, bg="#03110b", fg=COLORS["neon"], font=FONTS["mono"],
                  height=8, wrap="word")
    out.pack(fill="x", pady=(8, 0))

    def log(msg: str):
        try:
            out.insert("end", msg + "\n")
            out.see("end")
        except Exception:
            pass
        try:
            ctx.log(msg)
        except Exception:
            pass

    def apt_install(pkg: str):
        def _run():
            log(f"[KRYUX] apt install {pkg} … (ggf. Passwort-Dialog)")
            rc, so, se = run_cmd(["pkexec", "apt", "install", "-y", pkg], timeout=600)
            log(so.strip()[-2000:] if so else "")
            if se.strip():
                log("[apt] " + se.strip()[-1500:])
            log(f"[KRYUX] Fertig (rc={rc}). Falls rc≠0: „Anleitung“ nutzen.")
            try:
                parent.after(0, refresh)
            except Exception:
                pass
        threading.Thread(target=_run, daemon=True).start()

    status_labels: dict[str, tk.Label] = {}

    def refresh():
        for cmd, _p, _d in KEY_TOOLS:
            try:
                ok = which_tool(cmd) is not None
                lbl = status_labels.get(cmd)
                if lbl is not None:
                    lbl.config(text="● bereit" if ok else "○ fehlt",
                               fg=COLORS.get("ok", COLORS["neon"]) if ok else COLORS["red"])
            except Exception:
                pass

    for cmd, pkg, desc in KEY_TOOLS:
        row = tk.Frame(rows, bg=COLORS.get("card", COLORS["panel"]))
        row.pack(fill="x", pady=1)
        ok = which_tool(cmd) is not None
        st = tk.Label(row, text="● bereit" if ok else "○ fehlt", width=9, anchor="w",
                      bg=COLORS.get("card", COLORS["panel"]),
                      fg=COLORS.get("ok", COLORS["neon"]) if ok else COLORS["red"],
                      font=FONTS["mono_bold"])
        st.pack(side="left")
        status_labels[cmd] = st
        tk.Label(row, text=f"{cmd:<14} {desc}", anchor="w",
                 bg=COLORS.get("card", COLORS["panel"]),
                 fg=COLORS["text"], font=FONTS["mono"]).pack(side="left", fill="x", expand=True)
        tk.Button(row, text="Anleitung",
                  command=lambda c=cmd: show_install_dialog(parent, c),
                  bg=COLORS["panel"], fg=COLORS["cyan"], font=FONTS["small"],
                  relief="groove").pack(side="right", padx=2)
        tk.Button(row, text="APT",
                  command=lambda p=pkg: apt_install(p),
                  bg=COLORS["panel"], fg=COLORS["neon"], font=FONTS["small"],
                  relief="groove").pack(side="right", padx=2)

    bot = tk.Frame(body, bg=COLORS.get("card", COLORS["panel"]))
    bot.pack(fill="x", pady=(8, 0))
    tk.Button(bot, text="↻ Status aktualisieren", command=refresh,
              bg=COLORS["panel"], fg=COLORS["neon"], font=FONTS["mono"],
              relief="groove").pack(side="left")
    tk.Label(bot, text="APT klappt nicht? → Anleitung zeigt Git/Go/Gem/Docker-Wege.",
             bg=COLORS.get("card", COLORS["panel"]),
             fg=COLORS["dim"], font=FONTS["small"]).pack(side="left", padx=10)
    return root
