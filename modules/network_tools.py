"""Netzwerk Tools - Ping-Sweep, Traceroute, DNS, Banner, Header (alles live)."""
import concurrent.futures
import http.client
import ipaddress
import re
import shutil
import socket
import subprocess
import threading
import tkinter as tk
from tkinter import scrolledtext
import urllib.parse

TITLE = "Netzwerk Tools"

try:
    from core.theme import COLORS, FONTS  # type: ignore
except Exception:
    COLORS = {
        "BG": "#0a0e14",
        "BG2": "#11151c",
        "FG": "#c9d1d9",
        "ACCENT": "#00ff41",
        "ACCENT2": "#00c8ff",
        "RED": "#ff3b3b",
        "YELLOW": "#ffcc00",
        "GRAY": "#8b949e",
        "BORDER": "#1f6f2e",
    }
    FONTS = {
        "TITLE": ("Consolas", 13, "bold"),
        "NORMAL": ("Consolas", 10),
        "SMALL": ("Consolas", 9),
        "MONO": ("Consolas", 9),
    }

BANNER_PORTS = [80, 443, 22, 21, 25, 3306]


def _ctx_log(ctx, msg):
    try:
        if ctx is not None and hasattr(ctx, "log"):
            ctx.log(msg)
    except Exception:
        pass


def _run_bg(ctx, func):
    try:
        if ctx is not None and hasattr(ctx, "run_bg"):
            ctx.run_bg(func)
            return
    except Exception:
        pass
    threading.Thread(target=func, daemon=True).start()


def ping_once(host, timeout=1):
    cmd = ["ping", "-c", "1", "-W", str(timeout), host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        if r.returncode == 0:
            m = re.search(r"time[=<]([\d.]+)", r.stdout)
            return True, (m.group(1) + " ms" if m else "alive")
        return False, r.stdout.strip().splitlines()[-1][:100] if r.stdout.strip() else "timeout"
    except Exception as e:
        return False, str(e)[:100]


def build(parent, ctx):
    bg = COLORS.get("BG", "#0a0e14")
    bg2 = COLORS.get("BG2", "#11151c")
    fg = COLORS.get("FG", "#c9d1d9")
    acc = COLORS.get("ACCENT", "#00ff41")
    red = COLORS.get("RED", "#ff3b3b")
    gry = COLORS.get("GRAY", "#8b949e")

    frame = tk.Frame(parent, bg=bg)
    frame._alive = True
    frame.bind("<Destroy>", lambda _e: setattr(frame, "_alive", False))
    stop_flag = {"stop": False}

    top = tk.Frame(frame, bg=bg)
    top.pack(fill="x", padx=8, pady=6)
    tk.Label(top, text="Target (IP / Host / Netz):", bg=bg, fg=fg,
             font=FONTS.get("NORMAL", ("Consolas", 10))).pack(side="left")
    target_e = tk.Entry(top, width=34, bg=bg2, fg=fg, insertbackground=fg,
                        font=FONTS.get("MONO", ("Consolas", 10)))
    target_e.insert(0, "127.0.0.1")
    target_e.pack(side="left", padx=6)
    tk.Button(top, text="Stop", bg=bg2, fg=red, font=FONTS.get("NORMAL", ("Consolas", 10)),
              command=lambda: stop_flag.update(stop=True)).pack(side="right")
    status_var = tk.StringVar(value="Bereit.")
    tk.Label(frame, textvariable=status_var, bg=bg, fg=gry,
             font=FONTS.get("SMALL", ("Consolas", 9)), anchor="w").pack(fill="x", padx=8)

    out = scrolledtext.ScrolledText(frame, height=20, bg="#05070a", fg=acc,
                                    font=FONTS.get("MONO", ("Consolas", 9)),
                                    insertbackground=acc)
    out.pack(fill="both", expand=True, padx=8, pady=4)

    def append(txt):
        try:
            if frame._alive:
                out.insert("end", txt)
                out.see("end")
        except Exception:
            pass

    def set_status(t):
        try:
            if frame._alive:
                status_var.set(t)
        except Exception:
            pass

    def header(title):
        append(f"\n===== {title} =====\n")

    def target():
        return target_e.get().strip()

    # ---- 1. Ping-Sweep ---------------------------------------------------------
    def ping_sweep():
        t = target()
        if not t:
            set_status("Bitte Target angeben.")
            return
        stop_flag["stop"] = False
        try:
            net = ipaddress.ip_network(t, strict=False)
            hosts = list(net.hosts())[:256]
            if not hosts:
                hosts = [ipaddress.ip_address(t)]
        except ValueError:
            # Einzelhost
            header(f"Ping: {t}")
            ok, info = ping_once(t)
            append(f"{t}: {'ALIVE' if ok else 'DOWN'} ({info})\n")
            set_status(f"Ping {'alive' if ok else 'down'}: {t}")
            _ctx_log(ctx, f"Ping {t}: {'alive' if ok else 'down'}")
            return
        header(f"Ping-Sweep: {net} ({len(hosts)} Hosts)")
        set_status("Ping-Sweep laeuft ...")
        _ctx_log(ctx, f"Ping-Sweep gestartet: {net}")

        def worker():
            alive = []
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                    futs = {ex.submit(ping_once, str(h)): str(h) for h in hosts}
                    for fut in concurrent.futures.as_completed(futs):
                        if stop_flag["stop"] or not frame._alive:
                            ex.shutdown(wait=False, cancel_futures=True)
                            frame.after(0, lambda: append("[ABBRUCH]\n"))
                            return
                        h = futs[fut]
                        try:
                            ok, info = fut.result()
                        except Exception as e:
                            ok, info = False, str(e)
                        if ok:
                            alive.append(h)
                            frame.after(0, append, f"[+] {h} ALIVE ({info})\n")
                frame.after(0, lambda: (append(f"--- {len(alive)} Hosts aktiv ---\n"),
                                        set_status(f"Sweep fertig: {len(alive)} aktiv.")))
                _ctx_log(ctx, f"Ping-Sweep fertig: {len(alive)} aktiv.")
            except Exception as e:
                frame.after(0, lambda: append(f"FEHLER: {e}\n"))
        threading.Thread(target=worker, daemon=True).start()

    # ---- 2. Traceroute ------------------------------------------------------------
    def traceroute():
        t = target()
        if not t:
            set_status("Bitte Target angeben.")
            return
        stop_flag["stop"] = False
        header(f"Traceroute: {t}")
        set_status("Traceroute laeuft ...")

        def worker():
            exe = shutil.which("traceroute")
            if exe:
                try:
                    proc = subprocess.Popen([exe, "-n", "-w", "2", "-m", "20", t],
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            text=True, bufsize=1)
                    for line in proc.stdout:
                        if stop_flag["stop"]:
                            try:
                                proc.terminate()
                            except Exception:
                                pass
                            frame.after(0, lambda: append("[ABBRUCH]\n"))
                            return
                        frame.after(0, append, line)
                    proc.wait(timeout=60)
                    frame.after(0, lambda: set_status("Traceroute fertig."))
                    _ctx_log(ctx, f"Traceroute fertig: {t}")
                    return
                except Exception as e:
                    frame.after(0, lambda: append(f"traceroute-Fehler: {e}\nFallback: TTL-Ping ...\n"))
            else:
                frame.after(0, lambda: append("traceroute nicht gefunden - Fallback: ping mit TTL\n"))
            # Fallback: ping -t TTL (Linux: ping -t ttl)
            for ttl in range(1, 21):
                if stop_flag["stop"]:
                    frame.after(0, lambda: append("[ABBRUCH]\n"))
                    return
                try:
                    r = subprocess.run(["ping", "-c", "1", "-W", "2", "-t", str(ttl), t],
                                       capture_output=True, text=True, timeout=6)
                    line = (r.stdout.strip().splitlines()[:3] + [""])[:3]
                    frame.after(0, append, f"TTL={ttl}: {(' | '.join(line))[:160]}\n")
                    if r.returncode == 0 and "time=" in r.stdout:
                        # Ziel erreicht ist nicht sicher unterscheidbar -> weiter bis 20? Abbruch bei direktem Treffer:
                        pass
                except Exception as e:
                    frame.after(0, append, f"TTL={ttl} Fehler: {e}\n")
            frame.after(0, lambda: set_status("Traceroute-Fallback fertig."))
        threading.Thread(target=worker, daemon=True).start()

    # ---- 3. DNS-Lookup --------------------------------------------------------------
    def dns_lookup():
        t = target()
        if not t:
            set_status("Bitte Target angeben.")
            return
        stop_flag["stop"] = False
        header(f"DNS-Lookup: {t}")
        set_status("DNS laeuft ...")

        def worker():
            try:
                try:
                    name, aliases, addrs = socket.gethostbyname_ex(t)
                    frame.after(0, append, f"gethostbyname_ex:\n  Name: {name}\n  Aliase: {aliases}\n  Adressen: {addrs}\n")
                except socket.gaierror as e:
                    # evtl. IP -> Reverse
                    try:
                        rev = socket.gethostbyaddr(t)
                        frame.after(0, append, f"Reverse-DNS: {rev[0]} (Aliase {rev[1]}, IPs {rev[2]})\n")
                    except Exception:
                        frame.after(0, append, f"socket-DNS-Fehler: {e}\n")
                if shutil.which("nslookup"):
                    try:
                        r = subprocess.run(["nslookup", t], capture_output=True, text=True, timeout=10)
                        frame.after(0, append, f"\n--- nslookup ---\n{r.stdout[:3000]}{r.stderr[:500]}\n")
                    except Exception as e:
                        frame.after(0, append, f"nslookup-Fehler: {e}\n")
                else:
                    frame.after(0, lambda: append("(nslookup nicht installiert)\n"))
                frame.after(0, lambda: set_status("DNS fertig."))
                _ctx_log(ctx, f"DNS-Lookup fertig: {t}")
            except Exception as e:
                frame.after(0, lambda: append(f"FEHLER: {e}\n"))
        threading.Thread(target=worker, daemon=True).start()

    # ---- 4. Banner-Grabber --------------------------------------------------------------
    def banner_grab():
        t = target()
        if not t:
            set_status("Bitte Target angeben.")
            return
        stop_flag["stop"] = False
        header(f"Banner-Grabber: {t} Ports {BANNER_PORTS}")
        set_status("Banner-Grab laeuft ...")

        def worker():
            try:
                try:
                    ip = socket.gethostbyname(t)
                except Exception as e:
                    frame.after(0, lambda: append(f"DNS-Fehler: {e}\n"))
                    return
                for p in BANNER_PORTS:
                    if stop_flag["stop"]:
                        frame.after(0, lambda: append("[ABBRUCH]\n"))
                        return
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    try:
                        s.connect((ip, p))
                        payload = b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % t.encode() if p in (80, 443, 8080) else b"\r\n"
                        try:
                            s.sendall(payload)
                        except Exception:
                            pass
                        try:
                            data = s.recv(1024)
                        except Exception:
                            data = b""
                        txt = data.decode(errors="ignore").strip().replace("\n", " | ")[:300]
                        frame.after(0, append, f"[+] {p}/tcp OPEN  Banner: {txt or '(kein Banner)'}\n")
                    except Exception as e:
                        frame.after(0, append, f"[-] {p}/tcp closed ({str(e)[:60]})\n")
                    finally:
                        try:
                            s.close()
                        except Exception:
                            pass
                frame.after(0, lambda: set_status("Banner-Grab fertig."))
                _ctx_log(ctx, f"Banner-Grab fertig: {t}")
            except Exception as e:
                frame.after(0, lambda: append(f"FEHLER: {e}\n"))
        threading.Thread(target=worker, daemon=True).start()

    # ---- 5. Header-Check ------------------------------------------------------------------
    def header_check():
        t = target()
        if not t:
            set_status("Bitte Target angeben (Host oder URL).")
            return
        stop_flag["stop"] = False
        header(f"Security-Header-Check: {t}")
        set_status("Header-Check laeuft ...")

        def worker():
            try:
                raw = t if "://" in t else f"http://{t}"
                u = urllib.parse.urlparse(raw)
                host = u.hostname or t
                port = u.port or (443 if u.scheme == "https" else 80)
                path = u.path or "/"
                use_https = (u.scheme == "https") or port == 443
                import ssl
                if use_https:
                    ctx_ssl = ssl.create_default_context()
                    conn = http.client.HTTPSConnection(host, port, timeout=6, context=ctx_ssl)
                else:
                    conn = http.client.HTTPConnection(host, port, timeout=6)
                try:
                    conn.request("HEAD", path, headers={"User-Agent": "KryuxSOC/1.0"})
                    resp = conn.getresponse()
                    headers = dict(resp.getheaders())
                    frame.after(0, append, f"Status: {resp.status} {resp.reason}\n")
                    for k, v in headers.items():
                        frame.after(0, append, f"{k}: {v}\n")
                    checks = {
                        "Strict-Transport-Security": "HSTS fehlt (HTTPS-Hardening)",
                        "Content-Security-Policy": "CSP fehlt (XSS-Risiko)",
                        "X-Frame-Options": "Clickjacking-Schutz fehlt",
                        "X-Content-Type-Options": "MIME-Sniffing-Schutz fehlt",
                        "Referrer-Policy": "Referrer-Policy fehlt",
                        "Permissions-Policy": "Permissions-Policy fehlt",
                    }
                    lower = {k.lower(): v for k, v in headers.items()}
                    frame.after(0, lambda: append("\n--- Bewertung ---\n"))
                    for hname, warn in checks.items():
                        if hname.lower() in lower:
                            frame.after(0, append, f"[OK] {hname} vorhanden\n")
                        else:
                            frame.after(0, append, f"[WARN] {warn} ({hname})\n")
                    server = headers.get("Server", "") or headers.get("server", "")
                    if server:
                        frame.after(0, append, f"Hinweis: Server-Banner '{server}' verraten ggf. Version.\n")
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
                frame.after(0, lambda: set_status("Header-Check fertig."))
                _ctx_log(ctx, f"Header-Check fertig: {t}")
            except Exception as e:
                frame.after(0, lambda: (append(f"FEHLER: {e}\n"), set_status(f"Fehler: {e}")))
        threading.Thread(target=worker, daemon=True).start()

    btnrow = tk.Frame(frame, bg=bg)
    btnrow.pack(fill="x", padx=8, pady=4)
    for label, fn in (("Ping-Sweep", ping_sweep), ("Traceroute", traceroute),
                      ("DNS-Lookup", dns_lookup), ("Banner-Grabber", banner_grab),
                      ("Header-Check", header_check)):
        tk.Button(btnrow, text=label, bg=bg2, fg=acc, font=FONTS.get("SMALL", ("Consolas", 9)),
                  command=lambda f=fn: _run_bg(ctx, f)).pack(side="left", padx=3)
    tk.Button(btnrow, text="Leeren", bg=bg2, fg=gry, font=FONTS.get("SMALL", ("Consolas", 9)),
              command=lambda: (out.delete("1.0", "end"), set_status("Bereit."))).pack(side="right")
    return frame
