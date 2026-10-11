"""Nmap Scanner - echte Nmap-Einbindung + TCP-Connect-Fallback."""
import concurrent.futures
import re
import shutil
import socket
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog

TITLE = "Nmap Scanner"

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

try:
    from core.utils import which_tool as _which_tool  # type: ignore
except Exception:
    _which_tool = None


def which_tool(name):
    if _which_tool is not None:
        try:
            return _which_tool(name)
        except Exception:
            pass
    return shutil.which(name)


PROFILE_ARGS = {
    "Quick (-F)": ["-F"],
    "Standard (-sV)": ["-sV"],
    "Full (-sS -sV -O)": ["-sS", "-sV", "-O"],
    "Aggressiv (-A)": ["-A"],
    "UDP (-sU)": ["-sU"],
}

RISKY = {
    21: "FTP (Klartext)",
    23: "TELNET (Klartext! kritisch)",
    445: "SMB (ransomware-relevant)",
    3389: "RDP (Bruteforce-Ziel)",
    3306: "MySQL (offen = riskant)",
    5432: "PostgreSQL (offen = riskant)",
    6379: "Redis (oft ohne Auth!)",
    27017: "MongoDB (oft ohne Auth!)",
}


def parse_ports(spec, max_ports=4096):
    """'1-1024', '80,443,8080', '22' -> sortierte Portliste (live, kein Fake)."""
    ports = set()
    for part in (spec or "").replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                raise ValueError(f"Ungueltiger Bereich: {part}")
            if lo < 1 or hi > 65535 or lo > hi:
                raise ValueError(f"Ungueltiger Bereich: {part}")
            if hi - lo > max_ports:
                raise ValueError(f"Bereich zu gross (max {max_ports} Ports): {part}")
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"Ungueltiger Port: {part}")
            if not 1 <= p <= 65535:
                raise ValueError(f"Port ausserhalb 1-65535: {part}")
            ports.add(p)
    if not ports:
        raise ValueError("Keine Ports angegeben.")
    if len(ports) > max_ports:
        raise ValueError(f"Zu viele Ports (max {max_ports}).")
    return sorted(ports)


def tcp_probe(host, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        try:
            s.settimeout(1.0)
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(256)
        except Exception:
            banner = b""
        return True, banner.decode(errors="ignore").strip().splitlines()[0] if banner else ""
    except Exception:
        return False, ""
    finally:
        try:
            s.close()
        except Exception:
            pass


def _ctx_log(ctx, msg):
    try:
        if ctx is not None and hasattr(ctx, "log"):
            ctx.log(msg)
    except Exception:
        pass


def build(parent, ctx):
    bg = COLORS.get("BG", "#0a0e14")
    bg2 = COLORS.get("BG2", "#11151c")
    fg = COLORS.get("FG", "#c9d1d9")
    acc = COLORS.get("ACCENT", "#00ff41")
    acc2 = COLORS.get("ACCENT2", "#00c8ff")
    red = COLORS.get("RED", "#ff3b3b")
    yel = COLORS.get("YELLOW", "#ffcc00")
    gry = COLORS.get("GRAY", "#8b949e")

    frame = tk.Frame(parent, bg=bg)
    frame._alive = True
    frame.bind("<Destroy>", lambda _e: setattr(frame, "_alive", False))
    stop_flag = {"stop": False}

    def lbl(m, t, **kw):
        return tk.Label(m, text=t, bg=bg, fg=kw.pop("fg", fg),
                        font=FONTS.get(kw.pop("font_key", "NORMAL"), ("Consolas", 10)), **kw)

    # ---- Eingabezeile --------------------------------------------------------
    form = tk.LabelFrame(frame, text=" Ziel & Optionen ", bg=bg, fg=acc,
                         font=FONTS.get("TITLE", ("Consolas", 11, "bold")))
    form.pack(fill="x", padx=8, pady=6)

    lbl(form, "Target:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
    target_e = tk.Entry(form, width=26, bg=bg2, fg=fg, insertbackground=fg,
                        font=FONTS.get("MONO", ("Consolas", 10)))
    target_e.insert(0, "127.0.0.1")
    target_e.grid(row=0, column=1, padx=4, pady=4)

    lbl(form, "Ports:").grid(row=0, column=2, sticky="e", padx=4)
    ports_e = tk.Entry(form, width=18, bg=bg2, fg=fg, insertbackground=fg,
                       font=FONTS.get("MONO", ("Consolas", 10)))
    ports_e.insert(0, "1-1024")
    ports_e.grid(row=0, column=3, padx=4)

    lbl(form, "Profil:").grid(row=0, column=4, sticky="e", padx=4)
    profil_c = ttk.Combobox(form, values=list(PROFILE_ARGS.keys()), width=20, state="readonly")
    profil_c.set("Standard (-sV)")
    profil_c.grid(row=0, column=5, padx=4)

    lbl(form, "Timing:").grid(row=1, column=0, sticky="e", padx=4)
    timing_c = ttk.Combobox(form, values=["T0", "T1", "T2", "T3", "T4", "T5"], width=6, state="readonly")
    timing_c.set("T4")
    timing_c.grid(row=1, column=1, sticky="w", padx=4)

    flags = {}
    for i, (key, label) in enumerate((("Pn", "-Pn (kein Ping)"), ("sV", "-sV Version"),
                                      ("O", "-O OS-Erkennung"), ("sC", "-sC Skripte"))):
        v = tk.BooleanVar(value=(key == "sV"))
        cb = tk.Checkbutton(form, text=label, variable=v, bg=bg, fg=fg, selectcolor=bg2,
                            activebackground=bg, activeforeground=fg,
                            font=FONTS.get("SMALL", ("Consolas", 9)))
        cb.grid(row=1, column=2 + i, sticky="w", padx=4)
        flags[key] = v

    lbl(form, "Zusatz-Args:").grid(row=2, column=0, sticky="e", padx=4, pady=4)
    extra_e = tk.Entry(form, width=60, bg=bg2, fg=fg, insertbackground=fg,
                       font=FONTS.get("MONO", ("Consolas", 10)))
    extra_e.grid(row=2, column=1, columnspan=4, sticky="we", padx=4)
    form.columnconfigure(1, weight=1)

    # ---- Nmap-Verfuegbarkeit ---------------------------------------------------
    nmap_path = which_tool("nmap")
    warn_var = tk.StringVar()
    warn_lbl = tk.Label(frame, textvariable=warn_var, bg=bg, fg=red,
                        font=FONTS.get("SMALL", ("Consolas", 9)), anchor="w", justify="left")
    warn_lbl.pack(fill="x", padx=8)

    btns = tk.Frame(frame, bg=bg)
    btns.pack(fill="x", padx=8, pady=4)
    btn_nmap = tk.Button(btns, text="Nmap-Scan starten", bg=bg2, fg=acc,
                         font=FONTS.get("NORMAL", ("Consolas", 10)))
    btn_nmap.pack(side="left", padx=(0, 6))
    btn_fallback = tk.Button(btns, text="Fallback-Scan starten (kein Nmap)", bg=bg2, fg=acc2,
                             font=FONTS.get("NORMAL", ("Consolas", 10)))
    btn_fallback.pack(side="left", padx=6)
    btn_stop = tk.Button(btns, text="Stop", bg=bg2, fg=red,
                         font=FONTS.get("NORMAL", ("Consolas", 10)),
                         command=lambda: stop_flag.update(stop=True))
    btn_stop.pack(side="left", padx=6)
    btn_save = tk.Button(btns, text="Speichern (.txt)", bg=bg2, fg=fg,
                         font=FONTS.get("SMALL", ("Consolas", 9)))
    btn_save.pack(side="right")
    status_var = tk.StringVar(value="Bereit.")
    lbl(frame, "", font_key="SMALL").pack()  # spacer klein
    tk.Label(frame, textvariable=status_var, bg=bg, fg=gry,
             font=FONTS.get("SMALL", ("Consolas", 9)), anchor="w").pack(fill="x", padx=8)

    if not nmap_path:
        warn_var.set("NMAP NICHT GEFUNDEN - Nmap-Scan deaktiviert. "
                     "Installieren: sudo apt install nmap  |  Fallback-Scan unten nutzen.")
        btn_nmap.configure(state="disabled",
                           disabledforeground=gry,
                           text="Nmap-Scan starten (nmap fehlt!)")
        try:
            btn_nmap.configure(cursor="X_cursor")
        except Exception:
            pass
    else:
        warn_var.set(f"nmap gefunden: {nmap_path}")

    # ---- Output + Auswertung ---------------------------------------------------
    paned = tk.Frame(frame, bg=bg)
    paned.pack(fill="both", expand=True, padx=8, pady=4)
    out = scrolledtext.ScrolledText(paned, height=12, bg="#05070a", fg=acc,
                                    font=FONTS.get("MONO", ("Consolas", 9)),
                                    insertbackground=acc)
    out.pack(side="left", fill="both", expand=True, padx=(0, 4))
    res_tree = ttk.Treeview(paned, columns=("port", "state", "info"), show="headings", height=12)
    for c, w in (("port", 70), ("state", 90), ("info", 220)):
        res_tree.heading(c, text=c.upper())
        res_tree.column(c, width=w, anchor="w")
    res_tree.pack(side="left", fill="both", expand=True, padx=(4, 0))

    def append(txt):
        try:
            if frame._alive:
                out.insert("end", txt)
                out.see("end")
        except Exception:
            pass

    def set_status(txt):
        try:
            if frame._alive:
                status_var.set(txt)
        except Exception:
            pass

    def evaluate_nmap(text):
        for r in res_tree.get_children():
            res_tree.delete(r)
        found = re.findall(r"^(\d+)/(tcp|udp)\s+(\w+)\s*(.*)$", text, re.M)
        opens = [f for f in found if f[2].lower() == "open"]
        for port, proto, state, info in opens:
            res_tree.insert("", "end", values=(f"{port}/{proto}", state, info.strip()[:80]))
        risks = []
        for port, proto, state, info in opens:
            if int(port) in RISKY:
                risks.append(f"Port {port}/{proto}: {RISKY[int(port)]}")
        summary = f"\n\n--- AUSWERTUNG: {len(opens)} offene Ports ---"
        if risks:
            summary += "\n[!] RISIKO-HINWEISE:\n - " + "\n - ".join(risks)
        else:
            summary += "\nKeine bekannten Standard-Risikoports offen." if opens else "\nKeine offenen Ports gefunden."
        append(summary + "\n")
        _ctx_log(ctx, f"Nmap-Auswertung: {len(opens)} offene Ports.")
        set_status(f"Fertig: {len(opens)} offene Ports.")

    # ---- Nmap live --------------------------------------------------------------
    def start_nmap():
        if not which_tool("nmap"):
            set_status("nmap fehlt - Fallback nutzen.")
            return
        target = target_e.get().strip()
        if not target:
            set_status("Bitte Target angeben.")
            return
        stop_flag["stop"] = False
        try:
            ports = parse_ports(ports_e.get())
            port_arg = ",".join(map(str, ports)) if len(ports) <= 200 else None
        except ValueError as e:
            set_status(f"Port-Fehler: {e}")
            return
        args = [which_tool("nmap") or "nmap", f"-{timing_c.get()}"]
        args += PROFILE_ARGS.get(profil_c.get(), ["-sV"])
        if flags["Pn"].get() and "-Pn" not in args:
            args.append("-Pn")
        if flags["sV"].get() and "-sV" not in args:
            args.append("-sV")
        if flags["O"].get() and "-O" not in args:
            args.append("-O")
        if flags["sC"].get() and "-sC" not in args:
            args.append("-sC")
        if port_arg:
            args += ["-p", port_arg]
        extra = extra_e.get().strip().split()
        args += extra
        args.append(target)
        out.delete("1.0", "end")
        for r in res_tree.get_children():
            res_tree.delete(r)
        append("$ " + " ".join(args) + "\n")
        set_status("Nmap laeuft ... (Stop moeglich)")
        _ctx_log(ctx, "Nmap-Scan gestartet: " + target)
        btn_nmap.configure(state="disabled")
        btn_fallback.configure(state="disabled")

        def worker():
            full = []
            try:
                proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)
                while True:
                    if stop_flag["stop"]:
                        try:
                            proc.terminate()
                        except Exception:
                            pass
                        frame.after(0, lambda: append("\n[ABBRUCH durch User]\n"))
                        break
                    line = proc.stdout.readline()
                    if not line:
                        if proc.poll() is not None:
                            break
                        continue
                    full.append(line)
                    frame.after(0, append, line)
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                text = "".join(full)
                frame.after(0, evaluate_nmap, text)
            except Exception as e:
                frame.after(0, lambda: (append(f"\nFEHLER: {e}\n"), set_status(f"Fehler: {e}")))
            finally:
                frame.after(0, lambda: (btn_nmap.configure(state="normal" if which_tool("nmap") else "disabled"),
                                        btn_fallback.configure(state="normal")) if frame._alive else None)
        threading.Thread(target=worker, daemon=True).start()

    # ---- Fallback TCP-Connect ----------------------------------------------------
    def start_fallback():
        target = target_e.get().strip()
        if not target:
            set_status("Bitte Target angeben.")
            return
        try:
            host_ip = socket.gethostbyname(target)
        except Exception as e:
            set_status(f"DNS-Fehler: {e}")
            return
        try:
            ports = parse_ports(ports_e.get())
        except ValueError as e:
            set_status(f"Port-Fehler: {e}")
            return
        stop_flag["stop"] = False
        out.delete("1.0", "end")
        for r in res_tree.get_children():
            res_tree.delete(r)
        append(f"### Fallback (kein Nmap): TCP-Connect-Scan auf {target} ({host_ip}), {len(ports)} Ports ###\n")
        set_status("Fallback-Scan laeuft ...")
        _ctx_log(ctx, f"Fallback-Scan gestartet: {target} ({len(ports)} Ports)")
        btn_nmap.configure(state="disabled")
        btn_fallback.configure(state="disabled")
        results = []

        def worker():
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
                    futs = {ex.submit(tcp_probe, host_ip, p): p for p in ports}
                    for fut in concurrent.futures.as_completed(futs):
                        if stop_flag["stop"]:
                            ex.shutdown(wait=False, cancel_futures=True)
                            frame.after(0, lambda: append("\n[ABBRUCH durch User]\n"))
                            break
                        p = futs[fut]
                        try:
                            is_open, banner = fut.result()
                        except Exception:
                            is_open, banner = False, ""
                        if is_open:
                            results.append((p, banner))
                            frame.after(0, append, f"OPEN  {p}/tcp  {banner[:80]}\n".rstrip() + "\n")
                            frame.after(0, lambda pp=p, bb=banner: res_tree.insert(
                                "", "end", values=(f"{pp}/tcp", "open", bb[:80])))
                def finish():
                    append(f"\n--- FALLBACK-AUSWERTUNG: {len(results)} offene Ports ---\n")
                    for p, _ in sorted(results):
                        if p in RISKY:
                            append(f"[!] Port {p}: {RISKY[p]}\n")
                    if not results:
                        append("Keine offenen Ports im Bereich gefunden.\n")
                    set_status(f"Fallback fertig: {len(results)} offene Ports.")
                    _ctx_log(ctx, f"Fallback fertig: {len(results)} offene Ports auf {target}.")
                    btn_nmap.configure(state="normal" if which_tool("nmap") else "disabled")
                    btn_fallback.configure(state="normal")
                frame.after(0, finish)
            except Exception as e:
                frame.after(0, lambda: (append(f"\nFEHLER: {e}\n"), set_status(f"Fehler: {e}"),
                                        btn_fallback.configure(state="normal")))
        threading.Thread(target=worker, daemon=True).start()

    def save_txt():
        try:
            path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Text", "*.txt")])
            if not path:
                return
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"Target: {target_e.get().strip()}\nProfil: {profil_c.get()}\n\n")
                f.write(out.get("1.0", "end"))
            set_status(f"Gespeichert: {path}")
            _ctx_log(ctx, f"Scan gespeichert: {path}")
        except Exception as e:
            set_status(f"Speicher-Fehler: {e}")

    btn_nmap.configure(command=lambda: threading.Thread(target=start_nmap, daemon=True).start())
    btn_fallback.configure(command=lambda: threading.Thread(target=start_fallback, daemon=True).start())
    btn_save.configure(command=save_txt)
    return frame
