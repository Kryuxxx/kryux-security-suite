"""Web & Nikto Scanner - LIVE Checks (keine Fake-Scans).

Vertrag: TITLE + build(parent, ctx) -> tk.Frame.
Nutzt core.theme (COLORS, FONTS) und core.utils defensiv (mit Fallbacks).
"""

from __future__ import annotations

import http.client
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from urllib.parse import urlparse
from urllib.request import Request, urlopen

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
PANEL = _c("panel", "BG2", "panel", default="#161b22")
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
    """Delegiert an core.utils.run_stream, Fallback: eigene Popen-Schleife."""
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


TITLE = "Web & Nikto Scanner"

SENSITIVE_HINTS = ("/admin", "/.git", "/.env", "/wp-admin", "/server-status", "/phpmyadmin")


def _label(parent, text, fg=None, font=None):
    return tk.Label(parent, text=text, bg=BG, fg=fg or FG, font=font or F_NORM)


def _button(parent, text, command, fg=None):
    return tk.Button(parent, text=text, command=command, bg=PANEL, fg=fg or ACCENT,
                     activebackground=BORDER, activeforeground=ACCENT,
                     relief="groove", bd=1, font=F_NORM)


def _entry(parent, textvariable=None, width=50):
    return tk.Entry(parent, textvariable=textvariable, width=width, bg=ENTRY_BG, fg=FG,
                    font=F_NORM, insertbackground=ACCENT, relief="flat",
                    highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT)


def _output(parent, height=14):
    return scrolledtext.ScrolledText(parent, height=height, bg=ENTRY_BG, fg=FG, font=F_NORM,
                                     insertbackground=ACCENT, relief="flat",
                                     highlightthickness=1, highlightbackground=BORDER)


def build(parent, ctx) -> tk.Frame:
    root = tk.Frame(parent, bg=BG)
    stop_event = threading.Event()
    state = {"busy": False}

    _label(root, "Web & Nikto Scanner", fg=ACCENT, font=F_TITLE).pack(anchor="w", padx=8, pady=(8, 0))
    _label(root, "Nur eigene Systeme mit Erlaubnis!", fg=DANGER).pack(anchor="w", padx=8)

    top = tk.Frame(root, bg=BG)
    top.pack(fill="x", padx=8, pady=6)
    _label(top, "Ziel-URL:").pack(side="left")
    url_var = tk.StringVar(value="https://")
    _entry(top, textvariable=url_var, width=55).pack(side="left", padx=6, fill="x", expand=True)

    btns = tk.Frame(root, bg=BG)
    btns.pack(fill="x", padx=8, pady=4)

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=8, pady=6)
    tab_raw = tk.Frame(nb, bg=BG)
    tab_eval = tk.Frame(nb, bg=BG)
    nb.add(tab_raw, text="Roh-Output")
    nb.add(tab_eval, text="Auswertung")
    txt_raw = _output(tab_raw, height=16)
    txt_raw.pack(fill="both", expand=True)
    txt_eval = _output(tab_eval, height=16)
    txt_eval.pack(fill="both", expand=True)

    def ui(fn, *a, **kw):
        root.after(0, lambda: fn(*a, **kw))

    def log_raw(msg):
        txt_raw.insert("end", msg + "\n")
        txt_raw.see("end")

    def log_eval(msg):
        txt_eval.insert("end", msg + "\n")
        txt_eval.see("end")

    def get_url():
        u = url_var.get().strip()
        if not u:
            return ""
        if "://" not in u:
            u = "https://" + u
        return u

    # ---------- Nikto (live via run_stream) ----------
    def nikto_scan():
        url = get_url()
        if not url:
            messagebox.showwarning("Eingabe fehlt", "Bitte Ziel-URL eingeben.")
            return
        if state["busy"]:
            messagebox.showinfo("Läuft", "Es läuft bereits ein Scan. Erst stoppen.")
            return
        if which_tool("nikto") is None:
            ui(log_raw, f"[!] nikto nicht gefunden. Installieren: {install_hint('nikto')}")
            ui(log_eval, "[NIKTO] Nicht verfügbar. Andere Checks (Header/SSL/robots) laufen trotzdem.")
            ui(log_eval, f"Install: {install_hint('nikto')}")
            return
        stop_event.clear()
        state["busy"] = True
        ui(log_raw, f"$ nikto -h {url}")
        ui(log_eval, f"[NIKTO] Starte Live-Scan auf {url} ...")

        def worker():
            findings = []

            def on_line(line):
                ui(log_raw, line)
                low = line.lower()
                if any(k in low for k in ("osvdb", "vulnerable", "exploit", "xss", "sqli",
                                          "admin", "backup", ".git", ".env")):
                    findings.append(line)

            rc = run_stream(["nikto", "-h", url], on_line=on_line, stop_event=stop_event)
            if rc == -9:
                ui(log_eval, "[NIKTO] Abgebrochen (Stop).")
            else:
                ui(log_eval, f"[NIKTO] Fertig (Exit {rc}). {len(findings)} auffällige Zeilen.")
                for f in findings[:60]:
                    ui(log_eval, "  ! " + f)
                if not findings and rc == 0:
                    ui(log_eval, "[NIKTO] Keine OSVDB-Treffer im Output.")
            state["busy"] = False

        threading.Thread(target=worker, daemon=True).start()

    # ---------- Header-Check (live http.client) ----------
    def header_check():
        url = get_url()
        if not url:
            messagebox.showwarning("Eingabe fehlt", "Bitte Ziel-URL eingeben.")
            return
        ui(log_raw, f"[*] Header-Check: {url}")
        ui(log_eval, f"[HEADER] Prüfe {url} ...")

        def worker():
            try:
                p = urlparse(url)
                host, port = p.hostname, p.port
                use_ssl = (p.scheme or "https") == "https"
                if not host:
                    ui(log_eval, "[HEADER] Ungültige URL.")
                    return
                if port is None:
                    port = 443 if use_ssl else 80
                path = p.path or "/"
                conn_cls = http.client.HTTPSConnection if use_ssl else http.client.HTTPConnection
                kwargs = {"timeout": 12}
                if use_ssl:
                    kwargs["context"] = ssl._create_unverified_context()
                conn = conn_cls(host, port, **kwargs)
                try:
                    conn.request("HEAD", path, headers={"User-Agent": "Kryux-Security-Suite"})
                    resp = conn.getresponse()
                    if resp.status >= 400:
                        conn.request("GET", path, headers={"User-Agent": "Kryux-Security-Suite"})
                        resp = conn.getresponse()
                    status, headers = resp.status, {k.lower(): v for k, v in resp.getheaders()}
                    body_len = len(resp.read() or b"")
                finally:
                    conn.close()
                ui(log_raw, f"HTTP {status} von {host}; {len(headers)} Header, Body {body_len} Bytes")
                for k, v in headers.items():
                    ui(log_raw, f"  {k}: {v}")
                checks = [
                    ("strict-transport-security", "HSTS", use_ssl),
                    ("content-security-policy", "CSP", True),
                    ("x-frame-options", "X-Frame-Options (Clickjacking)", True),
                    ("x-content-type-options", "X-Content-Type-Options (nosniff)", True),
                    ("referrer-policy", "Referrer-Policy", True),
                ]
                ok = 0
                for hdr, name, relevant in checks:
                    if not relevant:
                        ui(log_eval, f"  [-] {name}: n/a (nur HTTPS relevant)")
                        continue
                    if hdr in headers:
                        ok += 1
                        ui(log_eval, f"  [OK] {name}: {headers[hdr][:100]}")
                    else:
                        ui(log_eval, f"  [WARN] {name} fehlt!")
                if ok >= 5:
                    ui(log_eval, "[HEADER] Bewertung: GUT (alle Security-Header gesetzt)")
                elif ok >= 3:
                    ui(log_eval, "[HEADER] Bewertung: MITTEL (einige Header fehlen)")
                else:
                    ui(log_eval, "[HEADER] Bewertung: SCHLECHT (wichtige Header fehlen)")
            except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
                ui(log_raw, f"[!] Header-Check Fehler: {e}")
                ui(log_eval, f"[HEADER] Fehler: {e}")

        threading.Thread(target=worker, daemon=True).start()

    # ---------- SSL-Check (live: ssl + openssl subprocess) ----------
    def ssl_check():
        url = get_url()
        if not url:
            messagebox.showwarning("Eingabe fehlt", "Bitte Ziel-URL eingeben.")
            return
        p = urlparse(url)
        if (p.scheme or "https") != "https" or not p.hostname:
            ui(log_eval, "[SSL] Nur für https://-URLs sinnvoll.")
            return
        host, port = p.hostname, p.port or 443
        ui(log_raw, f"[*] SSL-Check: {host}:{port}")
        ui(log_eval, f"[SSL] Hole Zertifikat von {host}:{port} ...")

        def worker():
            try:
                pem = ssl.get_server_certificate((host, port), timeout=12)
            except Exception as e:
                ui(log_raw, f"[!] Zertifikat-Abruf fehlgeschlagen: {e}")
                ui(log_eval, f"[SSL] Fehler: {e}")
                return
            ui(log_raw, "[*] Zertifikat erhalten, prüfe Ablaufdatum via openssl ...")
            try:
                with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
                    f.write(pem)
                    tmp = f.name
                try:
                    cp = subprocess.run(
                        ["openssl", "x509", "-noout", "-dates", "-subject", "-issuer", "-in", tmp],
                        capture_output=True, text=True, timeout=15)
                finally:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                out = (cp.stdout or "") + (cp.stderr or "")
                ui(log_raw, out.strip())
                m = re.search(r"notAfter=(.+)", out)
                if not m:
                    ui(log_eval, "[SSL] Ablaufdatum nicht parsbar.")
                    return
                from datetime import datetime
                datestr = m.group(1).strip()
                exp = None
                for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %e %H:%M:%S %Y %Z"):
                    try:
                        exp = datetime.strptime(datestr, fmt)
                        break
                    except ValueError:
                        continue
                if exp is None:
                    ui(log_eval, f"[SSL] notAfter={datestr} (Format unbekannt)")
                    return
                days = (exp - datetime.utcnow()).days
                ui(log_eval, f"[SSL] Läuft ab: {exp:%Y-%m-%d} (in ca. {days} Tagen)")
                if days < 0:
                    ui(log_eval, "[SSL] KRITISCH: Zertifikat ABGELAUFEN!")
                elif days < 30:
                    ui(log_eval, "[SSL] WARNUNG: läuft in <30 Tagen ab -> erneuern!")
                else:
                    ui(log_eval, "[SSL] OK: Laufzeit ausreichend.")
            except FileNotFoundError:
                ui(log_raw, f"[!] openssl fehlt: {install_hint('openssl')}")
                ui(log_eval, "[SSL] openssl nicht installiert.")
            except Exception as e:
                ui(log_raw, f"[!] SSL-Check Fehler: {e}")
                ui(log_eval, f"[SSL] Fehler: {e}")

        threading.Thread(target=worker, daemon=True).start()

    # ---------- robots.txt / sitemap (live urllib) ----------
    def robots_check():
        url = get_url()
        if not url:
            messagebox.showwarning("Eingabe fehlt", "Bitte Ziel-URL eingeben.")
            return
        p = urlparse(url)
        base = f"{p.scheme or 'https'}://{p.hostname}{':' + str(p.port) if p.port else ''}/"

        def worker():
            from urllib.parse import urljoin
            for name in ("robots.txt", "sitemap.xml"):
                target = urljoin(base, name)
                ui(log_raw, f"[*] hole {target}")
                try:
                    req = Request(target, headers={"User-Agent": "Kryux-Security-Suite"})
                    with urlopen(req, timeout=12) as r:
                        body = r.read().decode("utf-8", "replace")
                    ui(log_raw, f"[HTTP {r.status}] {target} ({len(body)} Zeichen)")
                    ui(log_raw, body[:3000])
                    ui(log_eval, f"[{name}] gefunden (HTTP {r.status}), {len(body)} Zeichen.")
                    if name == "robots.txt":
                        sens = [s for s in SENSITIVE_HINTS if s in body]
                        dis = [ln.strip() for ln in body.splitlines()
                               if ln.strip().lower().startswith("disallow:")]
                        ui(log_eval, f"  Disallow-Einträge: {len(dis)}")
                        for d in dis[:20]:
                            ui(log_eval, f"    {d}")
                        if sens:
                            ui(log_eval, f"  [WARN] Sensitive Pfade erwähnt: {', '.join(sens)} "
                                         "-> prüfen (Admin/Git/Env nicht exponieren!)")
                        else:
                            ui(log_eval, "  Keine kritischen Pfade (/admin/.git/.env) in robots.txt gefunden.")
                except Exception as e:
                    ui(log_raw, f"[-] {target}: {e}")
                    ui(log_eval, f"[{name}] nicht abrufbar: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def stop():
        stop_event.set()
        ui(log_raw, "[*] Stop angefordert ...")

    def clear():
        txt_raw.delete("1.0", "end")
        txt_eval.delete("1.0", "end")

    for txt, cmd, fg in [("Nikto-Scan", nikto_scan, ACCENT),
                         ("Header-Check", header_check, ACCENT),
                         ("SSL-Check", ssl_check, ACCENT),
                         ("robots/sitemap", robots_check, ACCENT),
                         ("Stop", stop, DANGER),
                         ("Leeren", clear, WARN)]:
        _button(btns, txt, cmd, fg=fg).pack(side="left", padx=3)

    _label(root, "Hinweis: Alle Checks laufen live im Thread, keine Fake-Daten.",
           fg=MUTED, font=F_SMALL).pack(anchor="w", padx=8, pady=(0, 6))
    return root
