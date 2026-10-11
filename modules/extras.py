"""Extras & Härtung — WLAN, USB, Backup-Check, SSH-Audit, Härtungs-Tipps.

Vertrag: TITLE + build(parent, ctx) -> tk.Frame. Alles live, Threading wo nötig.
"""

import hashlib
import os
import re
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText

TITLE = "Extras & Härtung"

try:
    from core.theme import COLORS, FONTS  # type: ignore
except Exception:
    COLORS = {}
    FONTS = {}

try:
    from core.utils import run_cmd as _core_run_cmd, which_tool as _core_which  # type: ignore
except Exception:
    _core_run_cmd = None
    _core_which = None

BG = COLORS.get("bg", "#050a08")
PANEL = COLORS.get("panel", "#0a1410")
ENTRY_BG = COLORS.get("entry_bg", "#03110b")
FG = COLORS.get("text", COLORS.get("fg", "#c9ffe2"))
MUTED = COLORS.get("dim", COLORS.get("muted", "#5f7a6e"))
ACCENT = COLORS.get("neon", COLORS.get("accent", "#00ff9c"))
ACCENT2 = COLORS.get("cyan", COLORS.get("accent2", "#00e5ff"))
OK = COLORS.get("ok", COLORS.get("neon", "#00ff9c"))
WARN = COLORS.get("amber", COLORS.get("warn", "#ffb300"))
DANGER = COLORS.get("red", COLORS.get("danger", "#ff3355"))

F_TITLE = FONTS.get("title", FONTS.get("TITLE", ("Consolas", 13, "bold")))
F_DEF = FONTS.get("mono", FONTS.get("NORMAL", ("Consolas", 10)))
F_SMALL = FONTS.get("small", FONTS.get("SMALL", ("Consolas", 9)))
F_BOLD = FONTS.get("bold", ("Consolas", 10, "bold"))


def _which(cmd):
    if _core_which is not None:
        try:
            return _core_which(cmd)
        except Exception:
            pass
    return shutil.which(cmd)


def _run(cmd, timeout=12):
    if _core_run_cmd is not None:
        try:
            return _core_run_cmd(cmd, timeout=timeout)
        except TypeError:
            return _core_run_cmd(cmd)
        except Exception as e:
            return 1, "", f"Fehler: {e}"
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout nach {timeout}s"
    except FileNotFoundError:
        return 127, "", f"Befehl nicht gefunden: {cmd[0]}"
    except Exception as e:
        return 1, "", f"Fehler: {e}"


def _human(n):
    try:
        n = float(n)
    except Exception:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024.0
    return f"{n:.1f} TB"


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _iter_files(root, max_files=5000):
    out = []
    for dirpath, _dn, filenames in os.walk(root):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            try:
                rel = os.path.relpath(full, root)
            except Exception:
                continue
            out.append((rel, full))
            if len(out) >= max_files:
                return out
    return out


def build(parent, ctx) -> tk.Frame:
    audit_cache = {}
    try:
        if isinstance(ctx, dict):
            audit_cache = ctx.setdefault("ssh_audit", {})
        elif ctx is not None and hasattr(ctx, "__dict__"):
            if not hasattr(ctx, "ssh_audit"):
                ctx.ssh_audit = {}
            audit_cache = ctx.ssh_audit
    except Exception:
        audit_cache = {}

    root = tk.Frame(parent, bg=BG)
    root.pack(fill="both", expand=True)
    root._alive = True
    root.bind("<Destroy>", lambda _e: setattr(root, "_alive", False))

    def alive():
        return getattr(root, "_alive", True)

    def _section(title):
        return tk.LabelFrame(root, text=f"  {title}  ", bg=PANEL, fg=FG,
                             font=F_BOLD, bd=1, relief="solid", labelanchor="nw")

    def _btn(par, txt, cmd, accent=False):
        return tk.Button(par, text=txt, command=cmd, font=F_DEF, relief="groove", bd=1,
                         cursor="hand2", bg="#0e2018" if accent else PANEL,
                         fg=ACCENT if accent else FG,
                         activebackground="#0e2018", activeforeground="#ffffff",
                         padx=10, pady=3)

    def _box(par, height=7):
        t = ScrolledText(par, height=height, bg=ENTRY_BG, fg=FG, font=F_SMALL,
                         relief="solid", bd=1, wrap="none", state="disabled")
        t.pack(fill="both", expand=True, padx=8, pady=(2, 8))
        return t

    def _set(t, text):
        if not alive():
            return
        try:
            t.configure(state="normal")
            t.delete("1.0", "end")
            t.insert("end", text)
            t.configure(state="disabled")
        except Exception:
            pass

    tk.Label(root, text="🧰 Extras & Härtung (live)", bg=BG, fg=FG,
             font=F_TITLE, anchor="w").pack(fill="x", padx=10, pady=(8, 2))

    # ---- 1. WLAN / Netz ------------------------------------------------
    s1 = _section("1 · WiFi / Netz (live)")
    s1.pack(fill="x", padx=10, pady=5)
    brow1 = tk.Frame(s1, bg=PANEL)
    brow1.pack(fill="x", padx=8, pady=(6, 0))
    wifi_box = _box(s1, height=8)

    def _wifi():
        lines = []
        if _which("nmcli"):
            for args in (["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "dev", "wifi", "list"],
                         ["nmcli", "con", "show"],
                         ["nmcli", "general", "status"]):
                rc, out, err = _run(args)
                lines.append(f"$ {' '.join(args)}  [exit {rc}]")
                lines.append((out or err or "(leer)").strip()[:4000])
                lines.append("")
        elif _which("iw"):
            rc, out, err = _run(["iw", "dev"])
            lines.append(f"$ iw dev  [exit {rc}]")
            lines.append((out or err or "(leer)").strip()[:4000])
        else:
            lines.append("nmcli/iw nicht gefunden.")
        rc, out, err = _run(["ip", "link", "show"])
        lines.append(f"$ ip link show  [exit {rc}]")
        lines.append((out or err or "(leer)").strip()[:4000])
        if not _which("nmcli"):
            lines.append("\nHinweis: 'ip link' zeigt Interfaces — für WLAN-Scan nmcli/iw installieren.")
        txt = "\n".join(lines)[:12000] or "(keine Daten)"
        root.after(0, lambda: _set(wifi_box, txt))

    _btn(brow1, "Aktualisieren",
         lambda: threading.Thread(target=_wifi, daemon=True).start(), accent=True).pack(side="left", pady=4)
    _set(wifi_box, "Lade WLAN/Netz …")

    # ---- 2. USB ---------------------------------------------------------
    s2 = _section("2 · USB-Geräte (live)")
    s2.pack(fill="x", padx=10, pady=5)
    brow2 = tk.Frame(s2, bg=PANEL)
    brow2.pack(fill="x", padx=8, pady=(6, 0))
    usb_box = _box(s2, height=6)

    def _usb():
        lines = []
        if _which("lsusb"):
            rc, out, err = _run(["lsusb"])
            lines.append(f"$ lsusb  [exit {rc}]")
            lines.append((out or err or "(leer)").strip()[:6000])
        else:
            lines.append("lsusb nicht gefunden — nutze /sys/bus/usb:")
            base = "/sys/bus/usb/devices"
            try:
                devs = sorted(os.listdir(base))
            except Exception as e:
                devs = []
                lines.append(f"Fehler: {e}")
            for d in devs[:40]:
                vals = {}
                for name in ("manufacturer", "product", "idVendor", "idProduct"):
                    try:
                        with open(os.path.join(base, d, name), encoding="utf-8", errors="replace") as f:
                            vals[name] = f.read().strip()
                    except Exception:
                        vals[name] = "?"
                lines.append(f"{d}: {vals['manufacturer']} {vals['product']} "
                             f"[{vals['idVendor']}:{vals['idProduct']}]")
            if not devs:
                lines.append("(keine Geräte gefunden)")
        txt = "\n".join(lines)[:10000]
        root.after(0, lambda: _set(usb_box, txt))

    _btn(brow2, "Aktualisieren",
         lambda: threading.Thread(target=_usb, daemon=True).start(), accent=True).pack(side="left", pady=4)
    _set(usb_box, "Lade USB-Geräte …")

    # ---- 3. Backup-Check -------------------------------------------------
    s3 = _section("3 · Backup-Check (Quelle vs. Backup)")
    s3.pack(fill="x", padx=10, pady=5)
    paths = tk.Frame(s3, bg=PANEL)
    paths.pack(fill="x", padx=8, pady=(6, 0))
    src_var = tk.StringVar(value="")
    dst_var = tk.StringVar(value="")
    tk.Label(paths, text="Quelle:", bg=PANEL, fg=FG, font=F_DEF).grid(row=0, column=0, sticky="w")
    tk.Entry(paths, width=36, bg=ENTRY_BG, fg=FG, insertbackground=ACCENT,
             font=F_DEF, textvariable=src_var).grid(row=0, column=1, padx=6, pady=2, sticky="ew")
    _btn(paths, "Quelle…",
         lambda: src_var.set(filedialog.askdirectory(title="Quellordner wählen") or src_var.get())
         ).grid(row=0, column=2, padx=2)
    tk.Label(paths, text="Backup:", bg=PANEL, fg=FG, font=F_DEF).grid(row=1, column=0, sticky="w")
    tk.Entry(paths, width=36, bg=ENTRY_BG, fg=FG, insertbackground=ACCENT,
             font=F_DEF, textvariable=dst_var).grid(row=1, column=1, padx=6, pady=2, sticky="ew")
    _btn(paths, "Backup…",
         lambda: dst_var.set(filedialog.askdirectory(title="Backup-Ordner wählen") or dst_var.get())
         ).grid(row=1, column=2, padx=2)
    paths.columnconfigure(1, weight=1)
    bstat = tk.Label(s3, text="Bereit.", bg=PANEL, fg=MUTED, font=F_SMALL, anchor="w")
    bstat.pack(fill="x", padx=8, pady=2)
    bak_box = _box(s3, height=8)
    _set(bak_box, "Quelle + Backup wählen, dann „Vergleich starten“.")

    def _bstat(txt, color=None):
        if alive():
            bstat.configure(text=txt, fg=color or FG)

    def _backup_worker(src, dst):
        try:
            root.after(0, lambda: _bstat("Sammle Dateien …"))
            src_files = dict(_iter_files(src))
            dst_files = dict(_iter_files(dst))
            only_src = sorted(set(src_files) - set(dst_files))
            only_dst = sorted(set(dst_files) - set(src_files))
            common = sorted(set(src_files) & set(dst_files))
            size_diff, hash_diff, hash_ok = [], [], 0
            sample = common[:20]
            for i, rel in enumerate(sample, 1):
                if i % 5 == 0:
                    root.after(0, lambda i=i, n=len(sample): _bstat(f"SHA256-Stichprobe {i}/{n} …"))
                try:
                    ss, ds = os.path.getsize(src_files[rel]), os.path.getsize(dst_files[rel])
                    if ss != ds:
                        size_diff.append(f"  ≠ Größe: {rel} ({_human(ss)} vs {_human(ds)})")
                        continue
                    if ss <= 50 * 1024 * 1024:
                        if _sha256(src_files[rel]) != _sha256(dst_files[rel]):
                            hash_diff.append(f"  ≠ Inhalt: {rel}")
                        else:
                            hash_ok += 1
                except Exception as e:
                    size_diff.append(f"  ! Fehler {rel}: {e}")
            lines = [f"Quelle : {src}  ({len(src_files)} Dateien)",
                     f"Backup : {dst}  ({len(dst_files)} Dateien)", ""]
            lines.append(f"⛔ Nur in Quelle (fehlt im Backup): {len(only_src)}")
            lines += [f"  - {r}" for r in only_src[:30]]
            if len(only_src) > 30:
                lines.append(f"  … +{len(only_src) - 30} weitere")
            lines.append(f"\nℹ Nur im Backup (gelöscht/extra): {len(only_dst)}")
            lines += [f"  - {r}" for r in only_dst[:15]]
            lines.append(f"\nSHA256-Stichprobe: {len(sample)} Dateien, {hash_ok} identisch, "
                         f"{len(hash_diff)} abweichend, {len(size_diff)} Größen-Diffs")
            lines += size_diff[:20] + hash_diff[:20]
            txt = "\n".join(lines)[:15000]
            root.after(0, lambda: (_set(bak_box, txt), _bstat("Fertig.", OK)))
        except Exception as e:
            root.after(0, lambda: (_bstat(f"Fehler: {e}", DANGER), _set(bak_box, f"Fehler: {e}")))

    def _backup_start():
        s, d = src_var.get().strip(), dst_var.get().strip()
        if not s or not os.path.isdir(s):
            _bstat("Bitte gültigen Quellordner wählen.", WARN)
            return
        if not d or not os.path.isdir(d):
            _bstat("Bitte gültigen Backup-Ordner wählen.", WARN)
            return
        _bstat("Vergleiche …")
        threading.Thread(target=_backup_worker, args=(s, d), daemon=True).start()

    brow3 = tk.Frame(s3, bg=PANEL)
    brow3.pack(fill="x", padx=8, pady=(0, 2))
    _btn(brow3, "Vergleich starten", _backup_start, accent=True).pack(side="left", pady=4)

    # ---- 4. SSH-Audit ----------------------------------------------------
    s4 = _section("4 · SSH-Audit (sshd_config + ~/.ssh-Rechte)")
    s4.pack(fill="x", padx=10, pady=5)
    brow4 = tk.Frame(s4, bg=PANEL)
    brow4.pack(fill="x", padx=8, pady=(6, 0))
    ssh_box = _box(s4, height=8)
    _set(ssh_box, "Führe Audit aus …")

    def _ssh_audit():
        res = {}
        lines = []
        cfg = "/etc/ssh/sshd_config"
        vals = {}
        try:
            with open(cfg, encoding="utf-8", errors="replace") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"(\w+)\s+(.*)", line)
                    if m:
                        vals[m.group(1)] = m.group(2).strip()
            for key in ("PermitRootLogin", "PasswordAuthentication", "PubkeyAuthentication",
                        "Port", "X11Forwarding", "MaxAuthTries"):
                lines.append(f"{key:22s}: {vals.get(key, '(Standard/nicht gesetzt)')}")
            res.update({k: vals.get(k, "") for k in ("PermitRootLogin", "PasswordAuthentication")})
        except FileNotFoundError:
            lines.append(f"{cfg} nicht gefunden (kein OpenSSH-Server installiert?).")
        except PermissionError:
            lines.append(f"{cfg} nicht lesbar (Root nötig) — Suite ggf. mit sudo für diesen Check starten.")
        except Exception as e:
            lines.append(f"Fehler beim Lesen: {e}")
        lines.append("")
        sshdir = os.path.expanduser("~/.ssh")
        res["sshdir"] = sshdir
        if os.path.isdir(sshdir):
            mode = oct(os.stat(sshdir).st_mode & 0o777)
            lines.append(f"~/.ssh: {sshdir}  Rechte {mode}  "
                         f"{'✔ ok (700)' if mode == '0o700' else '⚠ sollte 700 sein'}")
            res["dir_mode"] = mode
            for fn in ("id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys", "config", "known_hosts"):
                p = os.path.join(sshdir, fn)
                if os.path.exists(p):
                    m = oct(os.stat(p).st_mode & 0o777)
                    good = m == "0o600" or (fn == "known_hosts" and m in ("0o600", "0o644"))
                    lines.append(f"  {'✔' if good else '⚠'} {fn:16s} {m} (empfohlen 600)")
                    res[fn] = m
        else:
            lines.append("~/.ssh nicht vorhanden.")
            res["dir_mode"] = ""
        if _which("ufw"):
            rc, out, err = _run(["ufw", "status"])
            ufw = (out or err or "").strip().splitlines()
            lines.append("")
            lines.append("UFW: " + (ufw[0] if ufw else "(keine Ausgabe)"))
            res["ufw"] = "\n".join(ufw[:10])
        else:
            lines.append("\nUFW: nicht installiert.")
            res["ufw"] = ""
        try:
            if isinstance(audit_cache, dict):
                audit_cache.clear()
                audit_cache.update(res)
        except Exception:
            pass
        txt = "\n".join(lines)[:10000]
        root.after(0, lambda: _set(ssh_box, txt))

    _btn(brow4, "Audit ausführen",
         lambda: threading.Thread(target=_ssh_audit, daemon=True).start(), accent=True).pack(side="left", pady=4)

    # ---- 5. Härtungs-Tipps -----------------------------------------------
    s5 = _section("5 · Quick-Härtungs-Tipps (aus echten Checks generiert)")
    s5.pack(fill="x", padx=10, pady=(5, 10))
    brow5 = tk.Frame(s5, bg=PANEL)
    brow5.pack(fill="x", padx=8, pady=(6, 0))
    tip_box = _box(s5, height=10)
    _set(tip_box, "Klicke „Tipps generieren“ — Empfehlungen basieren auf SSH-Audit + UFW-Status oben.")

    def _gen_tips():
        try:
            a = dict(audit_cache) if isinstance(audit_cache, dict) else {}
        except Exception:
            a = {}
        tips = []
        prl = (a.get("PermitRootLogin") or "").lower()
        if not a:
            tips.append("ℹ SSH-Audit oben noch nicht gelaufen — generelle Empfehlungen (Audit für Präzisierung ausführen).")
        if not prl:
            tips.append("• PermitRootLogin nicht gesetzt/explizit prüfen → empfohlen: 'PermitRootLogin no'.")
        elif prl == "no":
            tips.append("✔ PermitRootLogin no — gut.")
        elif prl == "yes":
            tips.append("⛔ PermitRootLogin yes → auf 'no' setzen (/etc/ssh/sshd_config), dann 'sudo systemctl reload sshd'.")
        else:
            tips.append(f"• PermitRootLogin ist '{prl}' — 'no' ist am härtesten.")
        pwa = (a.get("PasswordAuthentication") or "").lower()
        if pwa == "no":
            tips.append("✔ PasswordAuthentication no (nur Keys) — gut.")
        elif pwa == "yes":
            tips.append("⛔ PasswordAuthentication yes → besser 'no' + Key-Login (PubkeyAuthentication yes).")
        else:
            tips.append("• PasswordAuthentication prüfen → empfohlen 'no' mit SSH-Keys + 2FA wo möglich.")
        dm = a.get("dir_mode", "")
        if dm == "0o700":
            tips.append("✔ ~/.ssh-Rechte 700 — gut.")
        elif dm:
            tips.append(f"⛔ ~/.ssh-Rechte {dm} → 'chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/authorized_keys'.")
        else:
            tips.append("• ~/.ssh-Rechte prüfen: 'chmod 700 ~/.ssh; chmod 600 ~/.ssh/id_*'.")
        ufw = a.get("ufw", "")
        if ufw:
            if "inactive" in ufw.lower():
                tips.append("⛔ UFW inaktiv → 'sudo ufw enable' + nur nötige Ports freigeben (z. B. 22/tcp limit).")
            elif "active" in ufw.lower():
                tips.append("✔ UFW aktiv — gut. Regeln mit 'sudo ufw status verbose' minimal halten.")
            else:
                tips.append("• UFW-Status prüfen: 'sudo ufw status verbose'.")
        else:
            tips.append("• UFW nicht gefunden/inaktiv → Firewall prüfen (ufw/firewalld/nft).")
        tips += ["• Updates: unattended-upgrades aktivieren; 'sudo apt update && sudo apt upgrade' regelmäßig.",
                 "• Fail2ban für SSH erwägen: 'sudo apt install fail2ban'.",
                 "• Backups (siehe Check oben) + Restore testen; 3-2-1-Regel.",
                 "• USB: unbekannte Sticks nie automatisch mounten/starten; lsusb im Blick behalten."]
        _set(tip_box, "\n".join(tips))

    _btn(brow5, "Tipps generieren", _gen_tips, accent=True).pack(side="left", pady=4)

    threading.Thread(target=_wifi, daemon=True).start()
    threading.Thread(target=_usb, daemon=True).start()
    threading.Thread(target=_ssh_audit, daemon=True).start()
    return root
