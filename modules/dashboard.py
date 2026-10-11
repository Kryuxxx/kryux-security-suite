"""SOC Dashboard - Live-Systemuebersicht (keine Fake-Daten, deutsch)."""
import re, socket, threading, time, tkinter as tk
from tkinter import ttk
import urllib.request
TITLE = "SOC Dashboard"
try:
    from core.utils import sys_stats  # type: ignore
except Exception:
    def sys_stats():
        import getpass as _g, shutil as _s
        d = {"hostname": "?", "user": "?", "uptime": "?", "load": "?",
             "cpu": 0.0, "ram": 0.0, "disk": 0.0, "cpu_percent": 0.0,
             "ram_percent": 0.0, "disk_percent": 0.0, "uptime_str": "?"}
        try: d["hostname"] = socket.gethostname()
        except Exception: pass
        try: d["user"] = _g.getuser()
        except Exception: pass
        try:
            s = int(float(open("/proc/uptime").read().split()[0]))
            m, s = divmod(s, 60); h, m = divmod(m, 60); dd, h = divmod(h, 24)
            d["uptime"] = d["uptime_str"] = f"{dd}d {h:02d}:{m:02d}" if dd else f"{h:02d}:{m:02d}"
        except Exception: pass
        try: d["load"] = " ".join(open("/proc/loadavg").read().split()[:3])
        except Exception: pass
        try:
            def _t():
                v = list(map(int, open("/proc/stat").readline().split()[1:8]))
                return sum(v), v[3]
            a, ia = _t(); time.sleep(0.15); b, ib = _t()
            d["cpu"] = d["cpu_percent"] = round((1 - (ib - ia) / max(1, b - a)) * 100, 1)
        except Exception: pass
        try:
            mi = {}
            for ln in open("/proc/meminfo").read().splitlines():
                k, _, v = ln.partition(":"); mi[k.strip()] = int(v.strip().split()[0])
            d["ram"] = d["ram_percent"] = round((1 - mi["MemAvailable"] / mi["MemTotal"]) * 100, 1)
        except Exception: pass
        try:
            du = _s.disk_usage("/"); d["disk"] = d["disk_percent"] = round(du.used / du.total * 100, 1)
        except Exception: pass
        return d
try:
    from core.utils import get_interfaces  # type: ignore
except Exception:
    def get_interfaces():
        import subprocess as _p
        try:
            o = _p.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=5)
            if o.returncode == 0:
                r = []
                for ln in o.stdout.splitlines():
                    c = ln.split(); nm = c[1].rstrip(":") if len(c) > 1 else "?"
                    ad = c[3] if len(c) > 3 else "?"
                    r.append({"name": nm, "ip": ad, "mac": "?", "state": "up", "iface": nm, "addr": ad})
                if r: return r
        except Exception: pass
        try:
            ip = socket.gethostbyname(socket.gethostname())
            return [{"name": "host", "ip": ip, "mac": "?", "state": "?", "iface": "host", "addr": ip}]
        except Exception: return []
try:
    from core.utils import get_open_ports  # type: ignore
except Exception:
    def get_open_ports():
        import subprocess as _p
        for cmd in (["ss", "-tulpn"], ["netstat", "-tulpn"]):
            try:
                o = _p.run(cmd, capture_output=True, text=True, timeout=5)
                if o.returncode == 0 and o.stdout.strip():
                    r = []
                    for ln in o.stdout.splitlines()[1:]:
                        c = ln.split()
                        if len(c) >= 5:
                            m = re.search(r'\(\("([^"]+)"', ln)
                            r.append({"proto": c[0], "local": c[4], "process": m.group(1) if m else ""})
                    return r
            except Exception: continue
        return []
try:
    from core.utils import get_connections  # type: ignore
except Exception:
    def get_connections(count=50):
        import subprocess as _p
        for cmd in (["ss", "-tunp"], ["netstat", "-tunp"]):
            try:
                o = _p.run(cmd, capture_output=True, text=True, timeout=5)
                if o.returncode == 0 and o.stdout.strip():
                    r = []
                    for ln in o.stdout.splitlines()[1:]:
                        c = ln.split()
                        if len(c) >= 5:
                            m = re.search(r'\(\("([^"]+)"', ln)
                            r.append({"proto": c[0], "state": c[1] if len(c) > 1 else "",
                                      "local": c[4] if len(c) > 4 else "", "peer": c[5] if len(c) > 5 else "",
                                      "process": m.group(1) if m else ""})
                        if len(r) >= count: break
                    return r
            except Exception: continue
        return []
try:
    from core.utils import net_io  # type: ignore
except Exception:
    def net_io():
        rx = tx = 0
        try:
            for ln in open("/proc/net/dev").read().splitlines()[2:]:
                if ":" not in ln: continue
                f = ln.split(":", 1)[1].split(); rx += int(f[0]); tx += int(f[8])
        except Exception: pass
        return {"rx": rx, "tx": tx}
try:
    from core.utils import tail_log  # type: ignore
except Exception:
    def tail_log(n=25):
        import subprocess as _p
        if isinstance(n, str): n = 25
        for q in ("/var/log/syslog", "/var/log/auth.log", "/var/log/messages"):
            try:
                o = _p.run(["tail", "-n", str(n), q], capture_output=True, text=True, timeout=5)
                if o.returncode == 0 and o.stdout.strip(): return f"### {q}\n" + o.stdout
            except Exception: continue
        return "Kein Log lesbar."
try:
    from core.utils import which_tool  # type: ignore
except Exception:
    def which_tool(name):
        import shutil as _s
        try: return _s.which(name)
        except Exception: return None
try:
    from core.theme import COLORS, FONTS  # type: ignore
except Exception:
    COLORS = {"bg": "#060b0d", "panel": "#0c1416", "card": "#101a1d", "border": "#1f2f34",
              "neon": "#00ffa3", "cyan": "#38e1ff", "amber": "#ffb300", "red": "#ff4d6d",
              "ok": "#00e676", "text": "#d4f5e5", "dim": "#647f76"}
    FONTS = {"logo": ("Consolas", 19, "bold"), "big": ("Consolas", 22, "bold"),
             "title": ("Consolas", 13, "bold"), "mono": ("Consolas", 10),
             "mono_bold": ("Consolas", 10, "bold"), "small": ("Consolas", 9)}
try:
    from core.theme import card as _theme_card  # type: ignore
except Exception: _theme_card = None
try:
    from core.theme import pill as _theme_pill  # type: ignore
except Exception: _theme_pill = None
try:
    from core.theme import draw_line_chart as _theme_draw  # type: ignore
except Exception: _theme_draw = None
def _C(*names, default="#d4f5e5"):
    low = {str(k).lower(): v for k, v in COLORS.items()}
    for n in names:
        if n in COLORS: return COLORS[n]
        if str(n).lower() in low: return low[str(n).lower()]
    return default
def _F(*names):
    low = {str(k).lower(): v for k, v in FONTS.items()}
    for n in names:
        if n in FONTS: return FONTS[n]
        if str(n).lower() in low: return low[str(n).lower()]
    return ("Consolas", 10)
def _card(parent, title="", subtitle=""):
    if _theme_card is not None:
        try: return _theme_card(parent, title=title) if not subtitle else _theme_card(parent, title=title, subtitle=subtitle)
        except Exception: pass
    card, bd, ne = _C("card", "panel"), _C("border", "dim"), _C("neon", "ok")
    outer = tk.Frame(parent, bg=card, highlightbackground=bd, highlightthickness=1)
    outer.pack(fill="x", padx=8, pady=5)
    if title: tk.Label(outer, text=title, bg=card, fg=ne, font=_F("title")).pack(anchor="w", padx=10, pady=(7, 0))
    if subtitle: tk.Label(outer, text=subtitle, bg=card, fg=_C("dim"), font=_F("small")).pack(anchor="w", padx=10)
    body = tk.Frame(outer, bg=card); body.pack(fill="x", padx=10, pady=(3, 9))
    return body
def _pill(parent, text, kind="ok"):
    if _theme_pill is not None:
        try: return _theme_pill(parent, text, kind=kind)
        except Exception: pass
    fg = {"ok": _C("ok", "neon"), "warn": _C("amber"), "danger": _C("red"),
          "info": _C("cyan"), "muted": _C("dim")}.get(kind, _C("text"))
    return tk.Label(parent, text=f" {text} ", bg=_C("card", "panel"), fg=fg, font=_F("small"), relief="groove", borderwidth=1)
def _paint(canvas, seriess, max_val=100.0):
    try:
        canvas.delete("all")
        w = canvas.winfo_width() or 280; h = canvas.winfo_height() or 90
        bd = _C("border", "dim")
        for i in (1, 2, 3):
            y = h * i / 4; canvas.create_line(0, y, w, y, fill=bd)
        mv = max(float(max_val), 1.0)
        for series, col in seriess:
            if not series: continue
            n = len(series); pts = []
            for i, v in enumerate(series):
                x = (i / max(n - 1, 1)) * (w - 4) + 2
                y = h - 4 - (min(max(float(v), 0), mv) / mv) * (h - 10)
                pts.extend([x, y])
            if len(pts) >= 4:
                canvas.create_line(*pts, fill=col, width=2)
                canvas.create_oval(pts[-2] - 3, pts[-1] - 3, pts[-2] + 3, pts[-1] + 3, fill=col, outline="")
    except Exception: pass
def _paint_single(canvas, series, color, max_val=100.0):
    if _theme_draw is not None:
        try: _theme_draw(canvas, list(series), max_val=max_val, line=color); return
        except Exception: pass
    _paint(canvas, [(series, color)], max_val)
def _ctx_log(ctx, msg):
    try:
        if ctx is not None and hasattr(ctx, "log"): ctx.log(msg)
    except Exception: pass
def _run_bg(ctx, func):
    try:
        if ctx is not None and hasattr(ctx, "run_bg"): ctx.run_bg(func); return
    except Exception: pass
    threading.Thread(target=func, daemon=True).start()
def _alive(w):
    try: return w is not None and w.winfo_exists()
    except Exception: return False
def _num(d, *keys, default=0.0):
    for k in keys:
        try:
            if isinstance(d, dict) and k in d and d[k] not in (None, ""): return float(d[k])
        except Exception: continue
    return float(default)
def _str(d, *keys, default="?"):
    for k in keys:
        try:
            if isinstance(d, dict) and d.get(k) not in (None, ""): return str(d.get(k))
        except Exception: continue
    return default
def _port_of(local):
    m = re.search(r":(\d+)\s*$", str(local or ""))
    return int(m.group(1)) if m else -1
_RISK_HIGH = {21: "FTP", 139: "NetBIOS", 445: "SMB", 3389: "RDP", 5900: "VNC", 6379: "Redis", 27017: "MongoDB", 11211: "Memcached"}
def _risk_of(port):
    if port == 23: return ("KRITISCH", "danger", "Telnet (unverschluesselt)")
    if port in _RISK_HIGH: return ("HOCH", "warn", _RISK_HIGH[port])
    return ("INFO", "muted", "")
def _level_color(v):
    try: v = float(v)
    except Exception: return _C("dim")
    if v < 60: return _C("ok", "neon")
    if v < 85: return _C("amber")
    return _C("red")
def build(parent, ctx) -> tk.Frame:
    bg, card, fg = _C("bg"), _C("card", "panel"), _C("text", "fg")
    neon, cyan, amber = _C("neon", "ok"), _C("cyan", "accent2"), _C("amber", "yellow")
    dim = _C("dim", "gray")
    frame = tk.Frame(parent, bg=bg)
    head = _card(frame, title="System", subtitle="Live-Hostinfo + externe IP")
    hv = {k: tk.StringVar(value="...") for k in ("host", "user", "up", "load", "ext")}
    row = tk.Frame(head, bg=card); row.pack(fill="x")
    for i, (k, cap) in enumerate((("host", "Hostname"), ("user", "User"), ("up", "Uptime"), ("load", "Load"), ("ext", "Ext. IP"))):
        tk.Label(row, text=cap + ":", bg=card, fg=cyan, font=_F("small")).grid(row=0, column=i * 2, sticky="e", padx=(6, 2), pady=3)
        tk.Label(row, textvariable=hv[k], bg=card, fg=fg, font=_F("mono", "normal")).grid(row=0, column=i * 2 + 1, sticky="w", padx=(0, 10))
    kpis = _card(frame, title="Kennzahlen", subtitle="Live, farbcodiert (<60 ok, <85 warn, sonst kritisch)")
    krow = tk.Frame(kpis, bg=card); krow.pack(fill="x")
    kvals, klabs = {}, {}
    for i, (k, cap) in enumerate((("cpu", "CPU %"), ("ram", "RAM %"), ("disk", "Disk %"), ("net", "Netz KB/s"))):
        cell = tk.Frame(krow, bg=card); cell.grid(row=0, column=i, sticky="ew", padx=8); krow.grid_columnconfigure(i, weight=1)
        tk.Label(cell, text=cap, bg=card, fg=dim, font=_F("small")).pack(anchor="w")
        v = tk.Label(cell, text="--", bg=card, fg=fg, font=_F("big", "title")); v.pack(anchor="w")
        s = tk.Label(cell, text="", bg=card, fg=dim, font=_F("small")); s.pack(anchor="w")
        kvals[k], klabs[k] = v, s
    charts = _card(frame, title="Live-Verlauf", subtitle="60 Samples, Refresh 2s")
    crow = tk.Frame(charts, bg=card); crow.pack(fill="x")
    canvases = {}
    for i, (k, cap) in enumerate((("cpu", "CPU %"), ("ram", "RAM %"), ("net", "Netz RX/TX KB/s"))):
        cell = tk.Frame(crow, bg=card); cell.grid(row=0, column=i, sticky="ew", padx=6); crow.grid_columnconfigure(i, weight=1)
        tk.Label(cell, text=cap, bg=card, fg=dim, font=_F("small")).pack(anchor="w")
        cv = tk.Canvas(cell, height=90, bg=bg, highlightbackground=_C("border", "dim"), highlightthickness=1)
        cv.pack(fill="x"); canvases[k] = cv
    hist = {"cpu": [], "ram": [], "rx": [], "tx": []}
    prev = {"rx": None, "tx": None}; rates = {"rx": 0.0, "tx": 0.0}
    risk = _card(frame, title="Risiko", subtitle="Echte offene Ports (ss), kein Fake")
    rrow = tk.Frame(risk, bg=card); rrow.pack(fill="x")
    rcounts = tk.Frame(rrow, bg=card); rcounts.pack(side="left", padx=(0, 12))
    rwarn = tk.Frame(rrow, bg=card); rwarn.pack(side="left", fill="x", expand=True)
    pills = {}
    for k in ("KRITISCH", "HOCH", "INFO"):
        p = _pill(rcounts, f"{k}: 0", kind={"KRITISCH": "danger", "HOCH": "warn"}.get(k, "muted"))
        p.pack(side="left", padx=4); pills[k] = p
    warn_var = tk.StringVar(value="Noch keine Daten.")
    tk.Label(rwarn, textvariable=warn_var, bg=card, fg=fg, font=_F("small"), justify="left", wraplength=600).pack(anchor="w")
    tabs = _card(frame, title="Netzwerk", subtitle="Interfaces, Ports, Verbindungen (Top 15)")
    tbar = tk.Frame(tabs, bg=card); tbar.pack(fill="x", pady=(0, 4))
    auto_var = tk.BooleanVar(value=True)
    tk.Checkbutton(tbar, text="Auto-Refresh (2s)", variable=auto_var, bg=card, fg=neon,
                   selectcolor=card, activebackground=card, activeforeground=neon, font=_F("small")).pack(side="left")
    tk.Button(tbar, text="Aktualisieren", bg=bg, fg=neon, relief="groove", font=_F("small"),
              command=lambda: _run_bg(ctx, refresh_once)).pack(side="right")
    status_var = tk.StringVar(value="Bereit.")
    cols3 = tk.Frame(tabs, bg=card); cols3.pack(fill="x")
    def _mk_tree(m, cols):
        f = tk.Frame(m, bg=card); f.pack(side="left", fill="both", expand=True, padx=3)
        t = ttk.Treeview(f, columns=cols, show="headings", height=7)
        for c in cols: t.heading(c, text=c); t.column(c, width=110, anchor="w")
        sb = ttk.Scrollbar(f, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
        return t
    if_tree = _mk_tree(cols3, ("Name", "IP", "MAC", "State"))
    port_tree = _mk_tree(cols3, ("Proto", "Lokal", "Prozess"))
    conn_tree = _mk_tree(cols3, ("Proto", "Lokal", "Peer", "State"))
    logc = _card(frame, title="Log-Vorschau", subtitle="tail_log, 25 Zeilen, live filterbar")
    srow = tk.Frame(logc, bg=card); srow.pack(fill="x", pady=(0, 4))
    tk.Label(srow, text="Suche:", bg=card, fg=dim, font=_F("small")).pack(side="left")
    search_var = tk.StringVar(value="")
    tk.Entry(srow, textvariable=search_var, bg=bg, fg=fg, insertbackground=neon,
             font=_F("mono", "normal"), relief="groove").pack(side="left", fill="x", expand=True, padx=6)
    log_txt = tk.Text(logc, height=10, bg=bg, fg=fg, insertbackground=neon, font=_F("mono", "normal"), relief="flat")
    log_txt.pack(fill="both", expand=True)
    log_cache = {"text": ""}
    tk.Label(frame, textvariable=status_var, bg=bg, fg=dim, font=_F("small"), anchor="w").pack(fill="x", padx=8, pady=(0, 6))
    def _set_txt(w, txt):
        try:
            w.configure(state="normal"); w.delete("1.0", "end"); w.insert("1.0", txt); w.configure(state="disabled")
        except Exception: pass
    def _fill_tree(tree, rows):
        try:
            for r in tree.get_children(): tree.delete(r)
            for r in rows: tree.insert("", "end", values=r)
        except Exception: pass
    def apply_log_filter(*_):
        if not _alive(frame): return
        try:
            q = search_var.get().strip().lower(); txt = log_cache["text"] or ""
            if q: txt = "\n".join(l for l in txt.splitlines() if q in l.lower())
            _set_txt(log_txt, txt or "(kein Treffer)")
        except Exception: pass
    try: search_var.trace_add("write", apply_log_filter)
    except Exception: pass
    def refresh_once():
        try: s = sys_stats()
        except Exception: s = {}
        try: io = net_io()
        except Exception: io = {"rx": 0, "tx": 0}
        try: ifaces = list(get_interfaces() or [])
        except Exception: ifaces = []
        try: ports = list(get_open_ports() or [])
        except Exception: ports = []
        try: conns = list(get_connections(50) or [])[:15]
        except Exception: conns = []
        try: logs = str(tail_log(25))
        except Exception:
            try: logs = str(tail_log(n=25))
            except Exception as e: logs = f"Log-Fehler: {e}"
        def apply():
            if not _alive(frame): return
            try:
                cpu = _num(s, "cpu_percent", "cpu"); ram = _num(s, "ram_percent", "ram"); dsk = _num(s, "disk_percent", "disk")
                hv["host"].set(_str(s, "hostname", default="?")); hv["user"].set(_str(s, "user", default="?"))
                hv["up"].set(_str(s, "uptime_str", "uptime", default="?"))
                lg = s.get("loadavg") if isinstance(s, dict) else None
                hv["load"].set(" ".join(f"{x:.2f}" for x in lg) if lg else _str(s, "load", default="?"))
                rx, tx = io.get("rx", 0), io.get("tx", 0)
                if prev["rx"] is not None:
                    rates["rx"] = max(0.0, (rx - prev["rx"]) / 2 / 1024)
                    rates["tx"] = max(0.0, (tx - prev["tx"]) / 2 / 1024)
                prev["rx"], prev["tx"] = rx, tx
                for k, v in (("cpu", cpu), ("ram", ram), ("disk", dsk)):
                    if _alive(kvals[k]): kvals[k].configure(text=f"{v:.1f} %", fg=_level_color(v))
                if _alive(kvals["net"]):
                    kvals["net"].configure(text=f"{rates['rx']:.0f}/{rates['tx']:.0f}", fg=fg)
                    klabs["net"].configure(text="RX/TX KB/s")
                klabs["cpu"].configure(text="Auslastung"); klabs["ram"].configure(text="Belegt")
                klabs["disk"].configure(text=f"{_str(s, 'disk_used_gb', default='')} / {_str(s, 'disk_total_gb', default='')} GB" if isinstance(s, dict) and "disk_total_gb" in s else "/")
                for k, v in (("cpu", cpu), ("ram", ram)): hist[k].append(float(v)); hist[k] = hist[k][-60:]
                hist["rx"].append(rates["rx"]); hist["tx"].append(rates["tx"])
                hist["rx"] = hist["rx"][-60:]; hist["tx"] = hist["tx"][-60:]
                if _alive(canvases["cpu"]): _paint_single(canvases["cpu"], hist["cpu"], neon, 100.0)
                if _alive(canvases["ram"]): _paint_single(canvases["ram"], hist["ram"], cyan, 100.0)
                if _alive(canvases["net"]):
                    _paint(canvases["net"], [(hist["rx"], neon), (hist["tx"], amber)], max(hist["rx"] + hist["tx"] + [1.0]))
                kc = kh = ki = 0; warns = []
                for p in ports:
                    local = p.get("local", "") if isinstance(p, dict) else str(p)
                    pn = _port_of(local)
                    if pn < 0: ki += 1; continue
                    lvl, _, svc = _risk_of(pn)
                    if lvl == "KRITISCH": kc += 1; warns.append((0, f"KRITISCH Port {pn} ({svc}) {local}"))
                    elif lvl == "HOCH": kh += 1; warns.append((1, f"HOCH Port {pn} ({svc}) {local}"))
                    else: ki += 1
                try:
                    pills["KRITISCH"].configure(text=f"KRITISCH: {kc}")
                    pills["HOCH"].configure(text=f"HOCH: {kh}")
                    pills["INFO"].configure(text=f"INFO: {ki}")
                except Exception: pass
                warns.sort(); top3 = [w for _, w in warns[:3]]
                warn_var.set(" | ".join(top3) if top3 else (f"{len(ports)} offene Ports, keine riskanten Dienste." if ports else "Keine offenen Ports (ss leer)."))
                _fill_tree(if_tree, [(r.get("name", r.get("iface", "?")) if isinstance(r, dict) else str(r),
                    r.get("ip", r.get("addr", "?")) if isinstance(r, dict) else "",
                    r.get("mac", "?") if isinstance(r, dict) else "",
                    r.get("state", "?") if isinstance(r, dict) else "") for r in ifaces])
                _fill_tree(port_tree, [(p.get("proto", "?"), p.get("local", "?"), p.get("process", "")) if isinstance(p, dict) else (str(p), "", "") for p in ports[:30]])
                _fill_tree(conn_tree, [(c.get("proto", "?"), c.get("local", "?"), c.get("peer", "?"), c.get("state", "")) if isinstance(c, dict) else (str(c), "", "", "") for c in conns])
                log_cache["text"] = logs; apply_log_filter()
                status_var.set(f"Aktualisiert {time.strftime('%H:%M:%S')} | Ports: {len(ports)} | Conn: {len(conns)}")
            except Exception: pass
        try: frame.after(0, apply)
        except Exception: pass
        _ctx_log(ctx, "Dashboard aktualisiert.")
    def fetch_ext_ip():
        try:
            req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "KryuxSOC/1.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                ip = r.read().decode().strip() or "offline"
        except Exception: ip = "offline"
        try:
            if _alive(frame): frame.after(0, lambda: hv["ext"].set(ip) if _alive(frame) else None)
        except Exception: pass
    def tick():
        try:
            if not _alive(frame): return
        except Exception: return
        try:
            if auto_var.get(): _run_bg(ctx, refresh_once)
        except Exception: pass
        try:
            if _alive(frame): frame.after(2000, tick)
        except Exception: pass
    _run_bg(ctx, refresh_once); _run_bg(ctx, fetch_ext_ip)
    try: frame.after(2000, tick)
    except Exception: pass
    return frame
