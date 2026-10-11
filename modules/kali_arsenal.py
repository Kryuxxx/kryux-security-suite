"""Kali Arsenal — Web/Netz/Passwort/WiFi/Forensik/OSINT/Exploit-DB Runner (live, kein Fake)."""
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext

TITLE = "Kali Arsenal"

try:
    from core.theme import COLORS, FONTS
except Exception:
    COLORS = {"bg": "#050a08", "panel": "#0a1410", "sidebar": "#060d0b",
              "neon": "#00ff9c", "cyan": "#00e5ff", "amber": "#ffb300",
              "red": "#ff3355", "text": "#c9ffe2", "dim": "#5f7a6e"}
    FONTS = {"logo": ("Consolas", 18, "bold"), "title": ("Consolas", 13, "bold"),
             "mono": ("Consolas", 10), "small": ("Consolas", 9)}

try:
    from core.utils import which_tool, run_stream, run_cmd, install_hint  # type: ignore
except Exception:
    def which_tool(n):
        try:
            return shutil.which(n)
        except Exception:
            return None

    def install_hint(n):
        return f"sudo apt install {n}"

    def run_cmd(cmd, timeout=30):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout or "", p.stderr or ""
        except FileNotFoundError as e:
            return 127, "", f"[KRYUX] Nicht gefunden: {e}"
        except Exception as e:
            return -1, "", f"[KRYUX] Fehler: {e}"

    class _H:
        def __init__(self):
            self._ev = threading.Event()
            self.process = None
            self.rc = None
        def stop(self):
            self._ev.set()
            try:
                if self.process and self.process.poll() is None:
                    self.process.terminate()
            except Exception:
                pass
        @property
        def stopped(self):
            return self._ev.is_set()

    def run_stream(cmd, on_line, on_done=None, stop_event=None):
        h = _H()
        def tgt():
            try:
                h.process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                             stderr=subprocess.STDOUT, text=True, bufsize=1)
            except FileNotFoundError:
                try:
                    on_line(f"[KRYUX] Nicht gefunden: {' '.join(cmd)} — {install_hint(cmd[0] if cmd else '?')}")
                except Exception:
                    pass
                h.rc = 127
                if on_done:
                    try:
                        on_done(127)
                    except Exception:
                        pass
                return
            rc = -1
            try:
                for raw in h.process.stdout:
                    if h.stopped:
                        break
                    try:
                        on_line(raw.rstrip("\n"))
                    except Exception:
                        pass
                try:
                    rc = h.process.wait(timeout=5)
                except Exception:
                    rc = -9 if h.stopped else -1
            except Exception:
                rc = -1
            h.rc = rc
            if on_done:
                try:
                    on_done(rc)
                except Exception:
                    pass
        if on_done is None and stop_event is not None:
            tgt()
            return h.rc
        threading.Thread(target=tgt, daemon=True).start()
        return h


# --- 8. Tab: Katalog + Installer (alles mit Fallback, nie abstürzen) ---
try:
    from modules.kali_catalog import TOOLS as CATALOG, CATEGORIES as CATS  # type: ignore
except Exception:
    try:
        from .kali_catalog import TOOLS as CATALOG, CATEGORIES as CATS  # type: ignore
    except Exception:
        CATALOG = []
        CATS = []

try:
    from core.installer import show_install_dialog  # type: ignore
except Exception:
    try:
        from .installer import show_install_dialog  # type: ignore
    except Exception:
        try:
            from installer import show_install_dialog  # type: ignore
        except Exception:
            show_install_dialog = None  # type: ignore


def _c(k, fb):
    try:
        return COLORS.get(k, fb)
    except Exception:
        return fb


def _f(k, fb):
    try:
        return FONTS.get(k, fb)
    except Exception:
        return fb


def _log(ctx, msg):
    try:
        if ctx is not None and hasattr(ctx, "log"):
            ctx.log(msg)
    except Exception:
        pass


def _default_iface():
    """Ermittelt live das Default-Interface, Fallback eth0 (kein Fake)."""
    try:
        rc, out, _ = run_cmd(["ip", "route", "show", "default"], timeout=5)
        if rc == 0 and out:
            for line in out.splitlines():
                parts = line.split()
                if "dev" in parts:
                    i = parts.index("dev")
                    if i + 1 < len(parts):
                        return parts[i + 1].strip()
    except Exception:
        pass
    return "eth0"


def tool_card(parent, out, alive, ctx, name, desc, bins, make_cmd,
              fields=None, consent=False, note="", help_only=False):
    """Generische Tool-Karte: Status, Parameter, Start/Stop, Live-Output ins Tab-Textfeld.

    bins: str oder Liste zu prüfender Binaries. make_cmd(vals)->list|None (ValueError bei Fehler).
    fields: Liste von (key, label, default, width?, values?) — values!=None => Combobox.
    """
    if isinstance(bins, str):
        bins = [bins]
    bg, panel = _c("bg", "#050a08"), _c("panel", "#0a1410")
    neon, dim = _c("neon", "#00ff9c"), _c("dim", "#5f7a6e")
    txt, red, amber = _c("text", "#c9ffe2"), _c("red", "#ff3355"), _c("amber", "#ffb300")

    card = tk.Frame(parent, bg=panel, highlightbackground=dim, highlightthickness=1)
    card.pack(fill="x", padx=6, pady=4)

    # --- Kopf: Name + Status ---
    top = tk.Frame(card, bg=panel)
    top.pack(fill="x", padx=6, pady=(4, 0))
    tk.Label(top, text=name, bg=panel, fg=neon, font=_f("mono", ("Consolas", 10, "bold"))).pack(side="left")
    missing = [b for b in bins if not which_tool(b)]
    st = tk.Label(top, bg=panel, font=_f("small", ("Consolas", 9)))
    st.pack(side="left", padx=8)
    if not missing:
        st.configure(text="● installiert", fg="#00ff41")
    else:
        st.configure(text=f"○ fehlt: {', '.join(missing)} → {install_hint(missing[0])}", fg=red)
    consent_var = tk.BooleanVar(value=False)
    if consent or help_only and "Labor" in (note + desc):
        pass
    if consent:
        tk.Checkbutton(top, text="Labor-Consent", variable=consent_var, bg=panel, fg=amber,
                       selectcolor=panel, activebackground=panel, activeforeground=amber,
                       font=_f("small", ("Consolas", 9))).pack(side="right")

    # --- Beschreibung + Hinweis ---
    tk.Label(card, text=desc, bg=panel, fg=dim, font=_f("small", ("Consolas", 9)),
             anchor="w", justify="left").pack(fill="x", padx=6)
    if note:
        tk.Label(card, text=note, bg=panel, fg=amber, font=_f("small", ("Consolas", 9)),
                 anchor="w", justify="left", wraplength=900).pack(fill="x", padx=6)
    if consent:
        tk.Label(card, text="Nur eigene Systeme / Labor!", bg=panel, fg=red,
                 font=_f("small", ("Consolas", 9)), anchor="w").pack(fill="x", padx=6)

    # --- Controls ---
    ctl = tk.Frame(card, bg=panel)
    ctl.pack(fill="x", padx=6, pady=(2, 5))
    widgets = {}
    for spec in (fields or []):
        key, lab, default = spec[0], spec[1], spec[2]
        width = spec[3] if len(spec) > 3 else 28
        values = spec[4] if len(spec) > 4 else None
        tk.Label(ctl, text=lab + ":", bg=panel, fg=txt,
                 font=_f("small", ("Consolas", 9))).pack(side="left", padx=(0, 2))
        if values:
            cb = ttk.Combobox(ctl, values=list(values), width=min(width, 18), state="readonly")
            try:
                cb.set(default)
            except Exception:
                pass
            cb.pack(side="left", padx=(0, 8))
            widgets[key] = cb
        else:
            e = tk.Entry(ctl, width=width, bg="#03110b", fg=txt, insertbackground=neon,
                         font=_f("mono", ("Consolas", 10)), relief="groove")
            e.insert(0, default)
            e.pack(side="left", padx=(0, 8))
            widgets[key] = e

    holder = {"h": None}

    def append(s):
        try:
            if alive():
                out.configure(state="normal")
                out.insert("end", s + "\n")
                out.see("end")
                out.configure(state="disabled")
        except Exception:
            pass

    def do_start():
        if missing:
            append(f"$ {' '.join(bins)} — BLOCKIERT: nicht installiert → {install_hint(missing[0])}")
            return
        if consent and not consent_var.get():
            append(f"[{name}] BLOCKIERT: bitte Labor-Consent anhaken (nur eigene Systeme / Labor!).")
            return
        try:
            vals = {}
            for k, w in widgets.items():
                try:
                    vals[k] = w.get().strip()
                except Exception:
                    vals[k] = ""
            cmd = make_cmd(vals)
        except ValueError as e:
            append(f"[{name}] Parameterfehler: {e}")
            return
        except Exception as e:
            append(f"[{name}] Fehler: {e}")
            return
        if not cmd:
            append(f"[{name}] Abgebrochen: Parameter unvollständig.")
            return
        append(f"$ {' '.join(cmd)}")
        _log(ctx, f"{name}: {' '.join(cmd)}")
        btn_start.configure(state="disabled")

        def on_line(line):
            try:
                out.after(0, lambda: append(line))
            except Exception:
                pass

        def on_done(rc):
            def fin():
                append(f"[{name}] fertig (rc={rc}).")
                try:
                    btn_start.configure(state="normal")
                except Exception:
                    pass
            try:
                out.after(0, fin)
            except Exception:
                pass
        try:
            h = run_stream(cmd, on_line, on_done)
            holder["h"] = h
        except Exception as e:
            append(f"[{name}] Startfehler: {e}")
            try:
                btn_start.configure(state="normal")
            except Exception:
                pass

    def do_stop():
        h = holder.get("h")
        try:
            if h is not None and hasattr(h, "stop"):
                h.stop()
                append(f"[{name}] Stop gesendet ...")
            else:
                append(f"[{name}] Nichts zu stoppen.")
        except Exception as e:
            append(f"[{name}] Stop-Fehler: {e}")

    btn_start = tk.Button(ctl, text="Start", bg=panel, fg=neon, activebackground="#0e2018",
                          activeforeground="#fff", font=_f("mono", ("Consolas", 10)),
                          relief="groove", command=lambda: threading.Thread(target=do_start, daemon=True).start())
    btn_start.pack(side="left", padx=4)
    tk.Button(ctl, text="Stop", bg=panel, fg=red, activebackground="#0e2018",
              activeforeground="#fff", font=_f("mono", ("Consolas", 10)),
              relief="groove", command=do_stop).pack(side="left", padx=4)
    return card


def _new_tab(nb, title, alive):
    """Erzeugt Tab mit Karten-Container + gemeinsamem Live-Output, gibt (body, out) zurück."""
    bg = _c("bg", "#050a08")
    tab = tk.Frame(nb, bg=bg)
    nb.add(tab, text=title)
    body = tk.Frame(tab, bg=bg)
    body.pack(fill="both", expand=True)
    cards = tk.Frame(body, bg=bg)
    cards.pack(fill="x", padx=4, pady=2)
    tk.Label(body, text="Live-Output:", bg=bg, fg=_c("neon", "#00ff9c"),
             font=_f("small", ("Consolas", 9)), anchor="w").pack(fill="x", padx=8)
    out = scrolledtext.ScrolledText(body, height=10, bg="#03110b", fg=_c("neon", "#00ff9c"),
                                    insertbackground=_c("neon", "#00ff9c"),
                                    font=_f("mono", ("Consolas", 10)), state="disabled")
    out.pack(fill="both", expand=True, padx=8, pady=(0, 8))
    return cards, out


def _build_all_tools_tab(nb, alive, ctx):
    """8. Tab 'Alle Tools': Volltextsuche über CATALOG (max 200 Treffer, Detail + Runner)."""
    bg = _c("bg", "#050a08")
    panel = _c("panel", "#0a1410")
    neon = _c("neon", "#00ff9c")
    dim = _c("dim", "#5f7a6e")
    txt = _c("text", "#c9ffe2")
    red = _c("red", "#ff3355")
    amber = _c("amber", "#ffb300")

    tab = tk.Frame(nb, bg=bg)
    nb.add(tab, text="Alle Tools \U0001F50D")

    if not CATALOG:
        tk.Label(tab, text="Katalog nicht verfügbar (modules/kali_catalog.py fehlt oder leer).",
                 bg=bg, fg=red, font=_f("mono", ("Consolas", 10))).pack(padx=8, pady=12)
        return tab

    # --- Oben: Suche + Kategorie + Count ---
    top = tk.Frame(tab, bg=bg)
    top.pack(fill="x", padx=8, pady=(6, 2))
    tk.Label(top, text="Suche:", bg=bg, fg=txt, font=_f("small", ("Consolas", 9))).pack(side="left")
    search_var = tk.StringVar()
    search_entry = tk.Entry(top, textvariable=search_var, width=34, bg="#03110b", fg=txt,
                            insertbackground=neon, font=_f("mono", ("Consolas", 10)), relief="groove")
    search_entry.pack(side="left", padx=(4, 10))
    tk.Label(top, text="Kategorie:", bg=bg, fg=txt, font=_f("small", ("Consolas", 9))).pack(side="left")
    try:
        cat_values = ["Alle"] + list(CATS or [])
    except Exception:
        cat_values = ["Alle"]
    cat_var = tk.StringVar(value="Alle")
    cat_combo = ttk.Combobox(top, textvariable=cat_var, values=cat_values, width=22, state="readonly")
    cat_combo.pack(side="left", padx=(4, 10))
    count_lbl = tk.Label(top, text="", bg=bg, fg=dim, font=_f("small", ("Consolas", 9)))
    count_lbl.pack(side="left")

    # --- Mitte: Treeview ---
    mid = tk.Frame(tab, bg=bg)
    mid.pack(fill="both", expand=True, padx=8, pady=4)
    cols = ("tool", "kat", "status", "cmd")
    tree = ttk.Treeview(mid, columns=cols, show="headings", height=10)
    tree.heading("tool", text="Tool")
    tree.heading("kat", text="Kategorie")
    tree.heading("status", text="Status")
    tree.heading("cmd", text="Kommando")
    tree.column("tool", width=150, anchor="w")
    tree.column("kat", width=170, anchor="w")
    tree.column("status", width=60, anchor="center")
    tree.column("cmd", width=220, anchor="w")
    sb = ttk.Scrollbar(mid, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")

    # --- Detailbereich ---
    det = tk.Frame(tab, bg=panel, highlightbackground=dim, highlightthickness=1)
    det.pack(fill="x", padx=8, pady=4)
    det_title = tk.Label(det, text="Kein Tool ausgewählt", bg=panel, fg=neon,
                         font=_f("mono", ("Consolas", 10, "bold")), anchor="w")
    det_title.pack(fill="x", padx=6, pady=(4, 0))
    det_desc = tk.Label(det, text="", bg=panel, fg=dim, font=_f("small", ("Consolas", 9)),
                        anchor="w", justify="left", wraplength=1000)
    det_desc.pack(fill="x", padx=6)
    det_stat = tk.Label(det, text="", bg=panel, fg=txt, font=_f("small", ("Consolas", 9)), anchor="w")
    det_stat.pack(fill="x", padx=6)
    row = tk.Frame(det, bg=panel)
    row.pack(fill="x", padx=6, pady=(2, 2))
    tk.Label(row, text="Args:", bg=panel, fg=txt, font=_f("small", ("Consolas", 9))).pack(side="left")
    args_entry = tk.Entry(row, width=30, bg="#03110b", fg=txt, insertbackground=neon,
                          font=_f("mono", ("Consolas", 10)), relief="groove")
    args_entry.insert(0, "--help")
    args_entry.pack(side="left", padx=(4, 8))
    btn_row = tk.Frame(det, bg=panel)
    btn_row.pack(fill="x", padx=6, pady=(0, 5))
    btn_start = tk.Button(btn_row, text="\u25B6 Start", bg=panel, fg=neon, relief="groove",
                          font=_f("mono", ("Consolas", 10)))
    btn_start.pack(side="left", padx=4)
    btn_stop = tk.Button(btn_row, text="\u23F9 Stop", bg=panel, fg=red, relief="groove",
                         font=_f("mono", ("Consolas", 10)))
    btn_stop.pack(side="left", padx=4)
    btn_help = tk.Button(btn_row, text="? Hilfe", bg=panel, fg=txt, relief="groove",
                         font=_f("mono", ("Consolas", 10)))
    btn_help.pack(side="left", padx=4)
    if show_install_dialog is None:
        tk.Label(btn_row, text="Install-Dialog n/a (core/installer fehlt)", bg=panel, fg=amber,
                 font=_f("small", ("Consolas", 9))).pack(side="left", padx=8)
        btn_install = None
    else:
        btn_install = tk.Button(btn_row, text="\u2699 Install\u2026", bg=panel, fg=amber, relief="groove",
                                font=_f("mono", ("Consolas", 10)))
        btn_install.pack(side="left", padx=4)

    tk.Label(tab, text="Nur eigene Systeme / Labor \u2014 du bist verantwortlich.",
             bg=bg, fg=red, font=_f("small", ("Consolas", 9)), anchor="w").pack(fill="x", padx=8)

    # --- Output ---
    tk.Label(tab, text="Live-Output:", bg=bg, fg=neon,
             font=_f("small", ("Consolas", 9)), anchor="w").pack(fill="x", padx=8)
    out = scrolledtext.ScrolledText(tab, height=8, bg="#03110b", fg=neon,
                                    insertbackground=neon, font=_f("mono", ("Consolas", 10)),
                                    state="disabled")
    out.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    MAX_LINES = 3000
    state = {"sel": None, "handle": None, "shown": []}

    def _append(s):
        try:
            if not alive():
                return
            out.configure(state="normal")
            out.insert("end", s + "\n")
            try:
                n = int(out.index("end-1c").split(".")[0])
                if n > MAX_LINES:
                    out.delete("1.0", f"{n - MAX_LINES}.0")
            except Exception:
                pass
            out.see("end")
            out.configure(state="disabled")
        except Exception:
            pass

    def _status_of(entry):
        try:
            cmd = str((entry or {}).get("cmd", "")).split()[0] if (entry or {}).get("cmd") else str((entry or {}).get("name", ""))
            return ("\u25CF installiert", "#00ff41") if which_tool(cmd) else ("\u25CB fehlt", red)
        except Exception:
            return ("\u25CB ?", dim)

    def _refresh():
        try:
            q = search_var.get().strip().lower()
        except Exception:
            q = ""
        try:
            cf = cat_var.get()
        except Exception:
            cf = "Alle"
        hits = []
        try:
            for e in (CATALOG or []):
                try:
                    nm = str(e.get("name", ""))
                    ds = str(e.get("desc", ""))
                    ct = str(e.get("cat", ""))
                except Exception:
                    continue
                if cf and cf != "Alle" and ct != cf:
                    continue
                if q and (q not in nm.lower() and q not in ds.lower()):
                    continue
                hits.append(e)
                if len(hits) >= 200:
                    break
        except Exception:
            hits = []
        state["shown"] = hits
        try:
            tree.delete(*tree.get_children())
        except Exception:
            pass
        for e in hits:
            try:
                st_txt, _fg = _status_of(e)
                tree.insert("", "end", values=(e.get("name", ""), e.get("cat", ""),
                                               st_txt, e.get("cmd", "")))
            except Exception:
                continue
        try:
            total = len(CATALOG or [])
            count_lbl.configure(text=f"{len(hits)} Treffer (max 200 von {total})")
        except Exception:
            pass

    def _select(_evt=None):
        try:
            sel = tree.selection()
            if not sel:
                return
            idx = tree.index(sel[0])
            shown = state.get("shown", [])
            if idx < 0 or idx >= len(shown):
                return
            e = shown[idx]
            state["sel"] = e
            nm = str(e.get("name", "?"))
            ds = str(e.get("desc", ""))
            cm = str(e.get("cmd", nm))
            st_txt, fg = _status_of(e)
            det_title.configure(text=nm)
            det_desc.configure(text=f"{ds}\nKommando: {cm}")
            det_stat.configure(text=f"Status: {st_txt}  ·  {install_hint(cm.split()[0]) if st_txt.startswith(chr(0x25CB)) else cm}")
            try:
                det_stat.configure(fg=fg)
            except Exception:
                pass
            if not args_entry.get().strip():
                args_entry.delete(0, "end")
                args_entry.insert(0, "-h")
        except Exception:
            pass

    def _run(extra_args=None):
        e = state.get("sel")
        if not e:
            _append("[Alle Tools] Bitte zuerst ein Tool aus der Liste wählen (Doppelklick).")
            return
        nm = str(e.get("name", "?"))
        cmdbase = str(e.get("cmd", nm) or nm).split()[0]
        try:
            argstr = " ".join(extra_args) if extra_args is not None else args_entry.get().strip()
        except Exception:
            argstr = ""
        cmd = [cmdbase] + (argstr.split() if argstr else [])
        if not which_tool(cmdbase):
            try:
                hint = install_hint(cmdbase)
            except Exception:
                hint = f"sudo apt install {cmdbase}"
            _append(f"$ {' '.join(cmd)} \u2014 BLOCKIERT: '{cmdbase}' nicht gefunden \u2192 {hint}")
            if show_install_dialog is not None:
                try:
                    show_install_dialog(tab, cmdbase)
                except Exception as ex:
                    _append(f"[Alle Tools] Install-Dialog-Fehler: {ex}")
            else:
                _append("[Alle Tools] Install-Dialog nicht verfügbar (core/installer fehlt).")
            return
        _append(f"$ {' '.join(cmd)}")
        _log(ctx, f"Alle Tools/{nm}: {' '.join(cmd)}")
        try:
            btn_start.configure(state="disabled")
        except Exception:
            pass

        def on_line(line):
            try:
                tab.after(0, lambda: _append(line))
            except Exception:
                pass

        def on_done(rc):
            def fin():
                _append(f"[{nm}] fertig (rc={rc}).")
                try:
                    btn_start.configure(state="normal")
                except Exception:
                    pass
            try:
                tab.after(0, fin)
            except Exception:
                pass

        def tgt():
            try:
                h = run_stream(cmd, on_line, on_done)
                state["handle"] = h
            except Exception as ex:
                try:
                    tab.after(0, lambda: _append(f"[{nm}] Startfehler: {ex}"))
                    tab.after(0, lambda: btn_start.configure(state="normal"))
                except Exception:
                    pass
        threading.Thread(target=tgt, daemon=True).start()

    def _stop():
        h = state.get("handle")
        try:
            if h is not None and hasattr(h, "stop"):
                h.stop()
                _append("[Alle Tools] Stop gesendet ...")
            else:
                _append("[Alle Tools] Nichts zu stoppen.")
        except Exception as ex:
            _append(f"[Alle Tools] Stop-Fehler: {ex}")

    def _install():
        e = state.get("sel")
        if not e:
            _append("[Alle Tools] Bitte zuerst ein Tool wählen.")
            return
        nm = str(e.get("name", "?"))
        cmdbase = str(e.get("cmd", nm) or nm).split()[0]
        if show_install_dialog is None:
            _append("[Alle Tools] Install-Dialog nicht verfügbar (core/installer fehlt).")
            return
        try:
            show_install_dialog(tab, cmdbase)
        except Exception as ex:
            _append(f"[Alle Tools] Install-Dialog-Fehler: {ex}")

    btn_start.configure(command=lambda: threading.Thread(target=_run, daemon=True).start())
    btn_stop.configure(command=_stop)
    btn_help.configure(command=lambda: threading.Thread(
        target=lambda: _run(extra_args=["--help"]), daemon=True).start())
    if btn_install is not None:
        btn_install.configure(command=_install)
    try:
        search_entry.bind("<KeyRelease>", lambda _e: _refresh())
        cat_combo.bind("<<ComboboxSelected>>", lambda _e: _refresh())
        tree.bind("<<TreeviewSelect>>", _select)
        tree.bind("<Double-1>", _select)
    except Exception:
        pass
    _refresh()
    return tab


def build(parent, ctx):
    bg = _c("bg", "#050a08")
    frame = tk.Frame(parent, bg=bg)
    _alive = {"v": True}
    frame.bind("<Destroy>", lambda _e: _alive.__setitem__("v", False))
    alive = lambda: _alive["v"]
    try:
        tk.Label(frame, text="Kali Arsenal — Live-Runner (kein Fake)",
                 bg=bg, fg=_c("neon", "#00ff9c"),
                 font=_f("title", ("Consolas", 13, "bold"))).pack(anchor="w", padx=8, pady=(6, 0))
        tk.Label(frame, text="Jeder Start prüft which_tool · fehlt ein Tool → Install-Hinweis, kein Output-Fake.",
                 bg=bg, fg=_c("dim", "#5f7a6e"), font=_f("small", ("Consolas", 9))).pack(anchor="w", padx=8)
    except Exception:
        pass
    nb = ttk.Notebook(frame)
    nb.pack(fill="both", expand=True, padx=6, pady=6)
    dif = _default_iface()

    # ---- 1. Web Enum ----
    c, o = _new_tab(nb, "Web Enum", alive)
    tool_card(c, o, alive, ctx, "gobuster", "Verzeichnis-Enumeration (dir).",
              "gobuster", lambda v: (["gobuster", "dir", "-u", v["u"], "-w", v["w"]] if v["u"] and v["w"]
                                     else (_ for _ in ()).throw(ValueError("URL + Wortliste nötig"))),
              [("u", "URL", "http://127.0.0.1", 24), ("w", "Wortliste", "/usr/share/wordlists/dirb/common.txt", 30)])
    tool_card(c, o, alive, ctx, "ffuf", "Fuzzing von Pfaden/Parametern.",
              "ffuf", lambda v: (["ffuf", "-u", v["u"], "-w", v["w"]] if v["u"] and v["w"]
                                 else (_ for _ in ()).throw(ValueError("URL/FUZZ + Wortliste nötig"))),
              [("u", "URL/FUZZ", "http://127.0.0.1/FUZZ", 26), ("w", "Wortliste", "/usr/share/wordlists/dirb/common.txt", 30)])
    tool_card(c, o, alive, ctx, "dirb", "Klassischer Web-Content-Scanner.",
              "dirb", lambda v: (["dirb", v["u"]] if v["u"]
                                 else (_ for _ in ()).throw(ValueError("URL nötig"))),
              [("u", "URL", "http://127.0.0.1", 30)])
    tool_card(c, o, alive, ctx, "whatweb", "Web-Technologie-Fingerprinter.",
              "whatweb", lambda v: (["whatweb", v["u"]] if v["u"]
                                    else (_ for _ in ()).throw(ValueError("URL nötig"))),
              [("u", "URL", "http://127.0.0.1", 30)])
    tool_card(c, o, alive, ctx, "wpscan", "WordPress-Schwachstellen-Scan.",
              "wpscan", lambda v: (["wpscan", "--url", v["u"], "--enumerate", "vp"] if v["u"]
                                   else (_ for _ in ()).throw(ValueError("URL nötig"))),
              [("u", "URL", "http://127.0.0.1", 30)],
              note="Hinweis: Voll-Scan braucht API-Token (--api-token TOKEN). Nur eigene Systeme / Labor!")
    tool_card(c, o, alive, ctx, "katana", "Crawler (Tiefe 2).",
              "katana", lambda v: (["katana", "-u", v["u"], "-d", "2"] if v["u"]
                                   else (_ for _ in ()).throw(ValueError("URL nötig"))),
              [("u", "URL", "http://127.0.0.1", 30)])

    # ---- 2. Netz & Spoof ----
    c, o = _new_tab(nb, "Netz & Spoof", alive)
    tool_card(c, o, alive, ctx, "netdiscover", "ARP-Host-Discovery im Subnetz.",
              "netdiscover", lambda v: (["netdiscover", "-r", v["c"]] if v["c"]
                                        else (_ for _ in ()).throw(ValueError("CIDR nötig, z.B. 192.168.1.0/24"))),
              [("c", "CIDR", "192.168.1.0/24", 22)], note="Hinweis: braucht Root (sudo).")
    tool_card(c, o, alive, ctx, "tcpdump", "Paketmitschnitt (50 Pakete).",
              "tcpdump", lambda v: (["tcpdump", "-c", "50", "-n", "-i", v["i"]] if v["i"]
                                    else (_ for _ in ()).throw(ValueError("Interface nötig"))),
              [("i", "Interface", dif, 14)], note="Hinweis: braucht Root (sudo).")
    tool_card(c, o, alive, ctx, "tshark", "Paketmitschnitt via TShark (50 Pakete).",
              "tshark", lambda v: (["tshark", "-c", "50", "-i", v["i"]] if v["i"]
                                   else (_ for _ in ()).throw(ValueError("Interface nötig"))),
              [("i", "Interface", dif, 14)], note="Hinweis: braucht Root (sudo).")
    tool_card(c, o, alive, ctx, "hping3", "SYN-Pakete an Port (nur Labor!).",
              "hping3", lambda v: (["hping3", "-S", "-p", v["p"], "-c", "4", v["t"]]
                                   if v["t"] and v["p"] else (_ for _ in ()).throw(ValueError("Target + Port nötig"))),
              [("t", "Target", "127.0.0.1", 18), ("p", "Port", "80", 8)],
              consent=True, note="Hinweis: nur eigenes Labor, kann als Angriff gewertet werden!")
    tool_card(c, o, alive, ctx, "responder (Info)", "LLMNR/NBT-NS-Poisoning — NUR Hilfe, kein Auto-Start.",
              "responder", lambda v: ["responder", "-h"],
              [("i", "Interface", dif, 14)],
              note="WARNUNG: nur eigenes Labor! Start zeigt nur `responder -h`. Echter Einsatz: sudo responder -I INTERFACE")

    # ---- 3. Passwort ----
    c, o = _new_tab(nb, "Passwort", alive)
    tool_card(c, o, alive, ctx, "hydra", "Online-Login-Guessing (Consent-Pflicht!).",
              "hydra", lambda v: (["hydra", "-l", v["u"], "-P", v["w"], v["t"], v["s"]]
                                  if v["u"] and v["w"] and v["t"] and v["s"]
                                  else (_ for _ in ()).throw(ValueError("User + Wortliste + Target + Service nötig"))),
              [("u", "User", "root", 10), ("w", "Wortliste", "/usr/share/wordlists/rockyou.txt", 26),
               ("t", "Target", "127.0.0.1", 16), ("s", "Service", "ssh", 10, ["ssh", "ftp", "http-get", "telnet", "smb"])],
              consent=True)
    tool_card(c, o, alive, ctx, "medusa", "Paralleler Login-Bruter (Labor!).",
              "medusa", lambda v: (["medusa", "-u", v["u"], "-P", v["w"], "-h", v["t"], "-M", "ssh"]
                                   if v["u"] and v["w"] and v["t"]
                                   else (_ for _ in ()).throw(ValueError("User + Wortliste + Target nötig"))),
              [("u", "User", "root", 10), ("w", "Wortliste", "/usr/share/wordlists/rockyou.txt", 26),
               ("t", "Target", "127.0.0.1", 16)], consent=True)
    tool_card(c, o, alive, ctx, "john", "Offline-Cracker: john --wordlist WL HASHFILE.",
              "john", lambda v: (["john", f"--wordlist={v['w']}", v["f"]] if v["f"] and v["w"]
                                 else (_ for _ in ()).throw(ValueError("Hashdatei + Wortliste nötig"))),
              [("f", "Hashdatei", "/tmp/hash.txt", 20), ("w", "Wortliste", "/usr/share/wordlists/rockyou.txt", 26)],
              note="Auswertung danach: john --show HASHFILE (einfach 2x starten).")
    tool_card(c, o, alive, ctx, "hashcat", "GPU/Offline-Cracker (Modus, --force).",
              "hashcat", lambda v: (["hashcat", "-m", v["m"], v["f"], v["w"], "--force"]
                                    if v["f"] and v["w"] and v["m"]
                                    else (_ for _ in ()).throw(ValueError("Hashdatei + Wortliste + Modus nötig"))),
              [("m", "Modus", "0", 6), ("f", "Hashdatei", "/tmp/hash.txt", 20),
               ("w", "Wortliste", "/usr/share/wordlists/rockyou.txt", 26)])
    tool_card(c, o, alive, ctx, "crunch", "Wortlisten-Generator (begrenzt!).",
              "crunch", lambda v: (["crunch", v["a"], v["b"], v["ch"], "-o", v["o"]]
                                   if v["a"] and v["b"] and v["ch"] and v["o"]
                                   else (_ for _ in ()).throw(ValueError("Min Max Zeichen Output nötig"))),
              [("a", "Min", "1", 5), ("b", "Max", "4", 5), ("ch", "Zeichen", "abc123", 10),
               ("o", "Out", "/tmp/crunch.txt", 20)],
              note="Hinweis: max 6 Stellen wählen — sonst riesiger Output!")

    # ---- 4. WiFi ----
    c, o = _new_tab(nb, "WiFi", alive)
    _wifi_warn = "Root-Warnung: braucht Root + Monitor-Mode. Kein Auto-Angriff — nur Anzeige/Mitschnitt."
    tool_card(c, o, alive, ctx, "airmon-ng", "Monitor-Mode-Check.",
              "airmon-ng", lambda v: ["airmon-ng", "check"], note=_wifi_warn)
    tool_card(c, o, alive, ctx, "airodump-ng", "WLAN-Mitschnitt auf Interface.",
              "airodump-ng", lambda v: (["airodump-ng", v["i"]] if v["i"]
                                        else (_ for _ in ()).throw(ValueError("Interface nötig"))),
              [("i", "Interface", "wlan0mon", 14)], note=_wifi_warn)
    tool_card(c, o, alive, ctx, "aireplay-ng (Hilfe)", "Deauth/Replay — NUR Hilfe.",
              "aireplay-ng", lambda v: ["aireplay-ng", "--help"], note=_wifi_warn + " Nur Hilfe, kein Angriff.")
    tool_card(c, o, alive, ctx, "wifite", "WLAN-Audit-Framework — NUR Hilfe.",
              "wifite", lambda v: ["wifite", "--help"], note=_wifi_warn + " Hinweis: braucht Monitor-Mode.")
    tool_card(c, o, alive, ctx, "kismet", "WLAN-Detektor — NUR Hilfe.",
              "kismet", lambda v: ["kismet", "--help"], note=_wifi_warn)
    tool_card(c, o, alive, ctx, "wash", "WPS-Scan auf Interface.",
              "wash", lambda v: (["wash", "-i", v["i"]] if v["i"]
                                 else (_ for _ in ()).throw(ValueError("Interface nötig"))),
              [("i", "Interface", "wlan0mon", 14)], note=_wifi_warn)

    # ---- 5. Forensik ----
    c, o = _new_tab(nb, "Forensik", alive)
    tool_card(c, o, alive, ctx, "yara", "Malware-Regel-Match auf Datei/Verzeichnis.",
              "yara", lambda v: (["yara", v["r"], v["t"]] if v["r"] and v["t"]
                                 else (_ for _ in ()).throw(ValueError("Regeldatei + Ziel nötig"))),
              [("r", "Regeldatei", "/tmp/rule.yar", 20), ("t", "Ziel", "/tmp/sample.bin", 20)])
    tool_card(c, o, alive, ctx, "binwalk", "Firmware-Analyse + Extraktion.",
              "binwalk", lambda v: (["binwalk", "-e", v["f"]] if v["f"]
                                    else (_ for _ in ()).throw(ValueError("Datei nötig"))),
              [("f", "Datei", "/tmp/firmware.bin", 24)], note="Hinweis: nur mit Kopie arbeiten!")
    tool_card(c, o, alive, ctx, "steghide", "Stego-Info + Extrakt mit Passwort.",
              ["steghide"], lambda v: (["steghide", "info", v["f"]] if v["m"] == "info"
                                        else ["steghide", "extract", "-sf", v["f"], "-p", v["p"], "-f"]
                                        if v["f"] else (_ for _ in ()).throw(ValueError("Datei nötig"))),
              [("f", "Datei", "/tmp/bild.jpg", 20), ("p", "Passwort", "", 12),
               ("m", "Modus", "info", 8, ["info", "extract"])])
    tool_card(c, o, alive, ctx, "bulk-extractor", "Feature-Extraktion aus Image.",
              "bulk_extractor", lambda v: (["bulk_extractor", "-o", v["o"], v["i"]]
                                           if v["o"] and v["i"]
                                           else (_ for _ in ()).throw(ValueError("Outdir + Image nötig"))),
              [("o", "Outdir", "/tmp/bulk_out", 18), ("i", "Image", "/tmp/image.dd", 20)])
    tool_card(c, o, alive, ctx, "strings (Fallback)", "strings DATEI | head — immer verfügbar wenn strings da.",
              "strings", lambda v: (["strings", v["f"]] if v["f"]
                                    else (_ for _ in ()).throw(ValueError("Datei nötig"))),
              [("f", "Datei", "/tmp/sample.bin", 24)], note="Fallback wenn xxd/Forensik-Tools fehlen.")

    # ---- 6. OSINT ----
    c, o = _new_tab(nb, "OSINT", alive)
    tool_card(c, o, alive, ctx, "theHarvester", "E-Mails/Subdomains zu Domain.",
              "theHarvester", lambda v: (["theHarvester", "-d", v["d"], "-b", "all", "-l", "50"] if v["d"]
                                         else (_ for _ in ()).throw(ValueError("Domain nötig"))),
              [("d", "Domain", "example.com", 22)])
    tool_card(c, o, alive, ctx, "amass", "Passives Subdomain-Enum.",
              "amass", lambda v: (["amass", "enum", "-passive", "-d", v["d"]] if v["d"]
                                  else (_ for _ in ()).throw(ValueError("Domain nötig"))),
              [("d", "Domain", "example.com", 22)])
    tool_card(c, o, alive, ctx, "subfinder", "Schnelles passives Subdomain-Enum.",
              "subfinder", lambda v: (["subfinder", "-d", v["d"], "-silent"] if v["d"]
                                      else (_ for _ in ()).throw(ValueError("Domain nötig"))),
              [("d", "Domain", "example.com", 22)])
    tool_card(c, o, alive, ctx, "sublist3r", "Subdomain-Enum via Suchmaschinen.",
              "sublist3r", lambda v: (["sublist3r", "-d", v["d"]] if v["d"]
                                      else (_ for _ in ()).throw(ValueError("Domain nötig"))),
              [("d", "Domain", "example.com", 22)])
    tool_card(c, o, alive, ctx, "sherlock", "Username-Suche (Timeout 10).",
              "sherlock", lambda v: (["sherlock", v["u"], "--timeout", "10"] if v["u"]
                                     else (_ for _ in ()).throw(ValueError("Username nötig"))),
              [("u", "Username", "testuser", 20)])
    tool_card(c, o, alive, ctx, "spiderfoot", "OSINT-Framework — NUR Hilfe.",
              "spiderfoot", lambda v: ["spiderfoot", "-h"],
              note="Hinweis: Vollbetrieb via Web-UI (spiderfoot -l 127.0.0.1:5001).")

    # ---- 7. Exploit-DB & Sonst ----
    c, o = _new_tab(nb, "Exploit-DB & Sonst", alive)
    tool_card(c, o, alive, ctx, "searchsploit", "Exploit-DB-Suche (Keyword oder -p EDB-ID).",
              "searchsploit", lambda v: (["searchsploit", "-p", v["k"]] if v["m"] == "-p"
                                         else ["searchsploit", v["k"]]
                                         if v["k"] else (_ for _ in ()).throw(ValueError("Keyword/ID nötig"))),
              [("k", "Keyword/ID", "apache", 18), ("m", "Modus", "Suche", 8, ["Suche", "-p"])])
    tool_card(c, o, alive, ctx, "msfvenom (Payloads)", "Listet verfügbare Payloads (live).",
              "msfvenom", lambda v: ["msfvenom", "--list", "payloads"],
              note="Hinweis: Payload-Erzeugung nur im Labor — kein Schadcode-Einsatz!")
    tool_card(c, o, alive, ctx, "macchanger", "MAC anzeigen / randomisieren (Root+Consent).",
              "macchanger", lambda v: (["macchanger", "-s", v["i"]] if v["m"] == "zeigen"
                                       else ["macchanger", "-r", v["i"]]
                                       if v["i"] else (_ for _ in ()).throw(ValueError("Interface nötig"))),
              [("i", "Interface", dif, 14), ("m", "Modus", "zeigen", 8, ["zeigen", "random"])],
              consent=True, note="Hinweis: Random braucht Root (sudo).")
    tool_card(c, o, alive, ctx, "netcat-Listener (Hilfe)", "nc -lvnp PORT — nur Anzeige, kein Auto-Listen.",
              ["nc", "netcat", "ncat"], lambda v: (["nc", "-h"] if which_tool("nc")
                                                  else ["ncat", "--help"] if which_tool("ncat")
                                                  else ["netcat", "-h"]),
              [("p", "Port", "4444", 8)], note="WARNUNG: Listener nur im eigenen Labor! Beispiel: nc -lvnp 4444")
    tool_card(c, o, alive, ctx, "lynis", "System-Audit (quick).",
              "lynis", lambda v: ["lynis", "audit", "system", "--quick"],
              note="Hinweis: braucht Root für vollen Audit.")
    tool_card(c, o, alive, ctx, "rkhunter", "Rootkit-Check (dauert lang).",
              "rkhunter", lambda v: ["rkhunter", "--check", "--skip-keypress"],
               note="Hinweis: Check dauert mehrere Minuten, Stop-Button nutzbar.")
    # ---- 8. Alle Tools (Katalog-Volltextsuche, ergänzt — Tabs 1-7 unverändert) ----
    try:
        _build_all_tools_tab(nb, alive, ctx)
    except Exception as _e:
        try:
            _log(ctx, f"Alle-Tools-Tab Fehler: {_e}")
        except Exception:
            pass
    return frame
