"""Forensik – Live-Features: Prozesse, Hashes, Metadaten, Logs, Timeline."""
from __future__ import annotations

import hashlib
import os
import re
import stat
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

TITLE = "Forensik"

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
    try:
        tv.tag_configure("SUSPECT", foreground=COLORS["crit"])
    except tk.TclError:
        pass

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


def tail_log(path: str, lines: int = 200) -> str:
    """Letzte N Zeilen einer Logdatei bzw. dmesg (ehrliche Fehlertexte)."""
    from collections import deque as _dq
    if path.strip().lower() == "dmesg":
        rc, out, err = run_cmd(["dmesg", "--ctime"], timeout=10)
        if rc != 0:
            rc, out, err = run_cmd(["dmesg"], timeout=10)
        if rc == 0 and out:
            return "\n".join(out.splitlines()[-lines:])
        return f"dmesg nicht lesbar: {err or 'unbekannter Fehler'}"
    try:
        with open(path, "r", errors="replace") as f:
            return "".join(_dq(f, maxlen=lines))
    except FileNotFoundError:
        return f"Datei nicht gefunden: {path}"
    except PermissionError:
        return f"Keine Leseberechtigung für: {path} (ggf. als Root starten)"
    except Exception as e:
        return f"Fehler beim Lesen von {path}: {e}"


def human_size(num: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


SUSPECT_RE = re.compile(r"keylog|min[e3]r|xmrig|stratum|mimikatz|meterpreter|reverse.?shell",
                        re.IGNORECASE)
BRUTE_RE = re.compile(r"Failed (?:password|login).*?from (\d+\.\d+\.\d+\.\d+)",
                      re.IGNORECASE)
IP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
LOG_HINT_RE = re.compile(r"Failed|failure|error|denied|blocked|refused|invalid",
                         re.IGNORECASE)


def _dark_text(parent, height=12) -> tk.Text:
    return tk.Text(parent, height=height, wrap="none", bg=COLORS["bg2"],
                   fg=COLORS["fg"], insertbackground=COLORS["fg"],
                   font=("Consolas", 9))


def build(parent, ctx) -> tk.Frame:
    apply_theme(parent)
    frame = ttk.Frame(parent, padding=10)
    ttk.Label(frame, text=TITLE, style="Title.TLabel").pack(anchor="w")
    ttk.Label(frame, text="Live-Systemdaten, nur Anzeige – keine Änderungen.",
              style="Muted.TLabel").pack(anchor="w", pady=(0, 6))

    nb = ttk.Notebook(frame)
    nb.pack(fill="both", expand=True)

    def _thread(fn):
        threading.Thread(target=fn, daemon=True).start()

    # ============ TAB: Prozesse ============
    tab_ps = ttk.Frame(nb, padding=6)
    nb.add(tab_ps, text="Prozesse")
    ps_search = tk.StringVar()
    ttk.Frame(tab_ps).pack(fill="x")  # Abstand
    bar = ttk.Frame(tab_ps)
    bar.pack(fill="x", pady=(0, 4))
    ttk.Label(bar, text="Suche:").pack(side="left")
    ttk.Entry(bar, textvariable=ps_search, width=30).pack(side="left", padx=4)
    ps_status = tk.StringVar(value="Bereit.")
    ttk.Button(bar, text="Snapshot laden",
               command=lambda: _thread(load_ps)).pack(side="left", padx=4)
    ttk.Label(bar, textvariable=ps_status, style="Muted.TLabel").pack(side="right")
    tv_ps = ttk.Treeview(tab_ps, columns=("pid", "user", "cpu", "mem", "cmd"),
                         show="headings", height=16)
    for c, w, t in (("pid", 70, "PID"), ("user", 110, "User"),
                    ("cpu", 70, "%CPU"), ("mem", 70, "%MEM"),
                    ("cmd", 560, "Befehl")):
        tv_ps.heading(c, text=t)
        tv_ps.column(c, width=w, anchor="w")
    tv_ps.pack(fill="both", expand=True)
    style_treeview(tv_ps)
    try:
        tv_ps.tag_configure("SUSPECT", foreground=COLORS["crit"])
    except tk.TclError:
        pass
    ps_cache: list[str] = []

    def load_ps():
        parent.after(0, lambda: ps_status.set("Lade ps aux…"))
        rc, out, err = run_cmd(["ps", "-aux"], timeout=15)
        if rc != 0:
            parent.after(0, lambda: ps_status.set(f"Fehler: {(err or out)[:120]}"))
            return
        ps_cache.clear()
        ps_cache.extend(out.splitlines())
        parent.after(0, render_ps)

    def render_ps(*_):
        q = ps_search.get().lower()
        tv_ps.delete(*tv_ps.get_children())
        lines = ps_cache[1:] if ps_cache else []
        if q:
            lines = [l for l in lines if q in l.lower()]
        for line in lines[:2000]:
            p = line.split(None, 10)
            if len(p) < 11:
                continue
            user, pid, cpu, mem, cmd = p[0], p[1], p[2], p[3], p[10]
            tag = "SUSPECT" if SUSPECT_RE.search(cmd) else ""
            tv_ps.insert("", "end", values=(pid, user, cpu, mem, cmd[:220]),
                         tags=(tag,) if tag else ())
        n_sus = sum(1 for l in lines if SUSPECT_RE.search(l))
        ps_status.set(f"{len(lines)} Prozesse, {n_sus} verdächtig markiert (nur Anzeige).")

    ps_search.trace_add("write", render_ps)

    # ============ TAB: Hashes ============
    tab_h = ttk.Frame(nb, padding=6)
    nb.add(tab_h, text="Datei-Hashes")
    h_path = tk.StringVar()
    h_expect = tk.StringVar()
    h_status = tk.StringVar(value="Keine Datei gewählt.")
    ttk.Button(tab_h, text="Datei wählen…",
               command=lambda: _pick_hash()).pack(anchor="w")
    ttk.Label(tab_h, textvariable=h_path, style="Muted.TLabel").pack(anchor="w")
    row = ttk.Frame(tab_h)
    row.pack(fill="x", pady=4)
    ttk.Label(row, text="Erwarteter Hash:").pack(side="left")
    ttk.Entry(row, textvariable=h_expect, width=70).pack(side="left", padx=4)
    txt_h = _dark_text(tab_h, height=10)
    txt_h.pack(fill="both", expand=True, pady=4)
    ttk.Label(tab_h, textvariable=h_status, style="Muted.TLabel").pack(anchor="w")

    def _pick_hash():
        p = filedialog.askopenfilename(title="Datei für Hash wählen")
        if p:
            h_path.set(p)
            _thread(lambda: hash_file(p))

    def hash_file(path: str):
        parent.after(0, lambda: h_status.set("Berechne…"))
        md5, sha = hashlib.md5(), hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    md5.update(chunk)
                    sha.update(chunk)
        except OSError as e:
            parent.after(0, lambda: h_status.set(f"Fehler: {e}"))
            return
        d5, s256 = md5.hexdigest(), sha.hexdigest()
        exp = h_expect.get().strip().lower()
        verdict = ""
        if exp:
            verdict = ("MATCH ✓" if exp in (d5, s256)
                       else "KEIN MATCH ✗ (Datei abweichend/unerwartet)")
        def _do():
            txt_h.delete("1.0", "end")
            txt_h.insert("end", f"Datei:  {path}\nMD5:    {d5}\nSHA256: {s256}\n")
            if verdict:
                txt_h.insert("end", f"Vergleich: {verdict}\n")
            h_status.set("Fertig." + (f" {verdict}" if verdict else ""))
        parent.after(0, _do)

    # ============ TAB: Metadaten ============
    tab_m = ttk.Frame(nb, padding=6)
    nb.add(tab_m, text="Metadaten")
    m_status = tk.StringVar(value="Keine Datei gewählt.")
    ttk.Button(tab_m, text="Datei wählen…",
               command=lambda: _pick_meta()).pack(anchor="w")
    txt_m = _dark_text(tab_m, height=14)
    txt_m.pack(fill="both", expand=True, pady=4)
    ttk.Label(tab_m, textvariable=m_status, style="Muted.TLabel").pack(anchor="w")

    def _pick_meta():
        p = filedialog.askopenfilename(title="Datei für Metadaten wählen")
        if p:
            _thread(lambda: meta_of(p))

    def meta_of(path: str):
        try:
            st = os.stat(path)
        except OSError as e:
            parent.after(0, lambda: m_status.set(f"Fehler: {e}"))
            return
        lines = [
            f"Pfad:   {path}",
            f"Größe:  {st.st_size} B ({human_size(st.st_size)})",
            f"Modus:  {oct(stat.S_IMODE(st.st_mode))}",
            f"UID/GID:{st.st_uid}/{st.st_gid}",
            f"MTIME:  {time.ctime(st.st_mtime)}",
            f"ATIME:  {time.ctime(st.st_atime)}",
            f"CTIME:  {time.ctime(st.st_ctime)}",
        ]
        try:
            with open(path, "rb") as f:
                head = f.read(4096)
            if head[:2] == b"\xff\xd8":
                lines.append("Typ-Hinweis: JPEG (Magic Bytes FFD8).")
                # EXIF-Basis: "Exif" + ASCII-Tags grob extrahieren
                ascii_tags = re.findall(rb"[ -~]{4,}", head)
                exif = [t.decode("ascii", "replace") for t in ascii_tags
                        if any(k in t for k in (b"Exif", b"Canon", b"NIKON", b"SONY"))]
                lines.append("EXIF-Hinweise: " + ("; ".join(exif[:5]) or "keine lesbaren Tags im Header"))
            elif head.startswith(b"%PDF"):
                lines.append("Typ-Hinweis: PDF.")
                try:
                    with open(path, "rb") as f:
                        raw = f.read(200000)
                    for key in (b"/Author", b"/Creator", b"/Producer",
                                b"/Title", b"/CreationDate"):
                        m = re.search(key + rb"\s*\((.*?)\)", raw)
                        if m:
                            lines.append(f"{key.decode()}: {m.group(1)[:120].decode('latin1', 'replace')}")
                except OSError:
                    pass
            else:
                lines.append(f"Magic: {head[:8].hex(' ')} (kein JPEG/PDF-Header)")
        except OSError as e:
            lines.append(f"Header nicht lesbar: {e}")
        parent.after(0, lambda: (txt_m.delete("1.0", "end"),
                                 txt_m.insert("end", "\n".join(lines) + "\n"),
                                 m_status.set("Fertig.")))

    # ============ TAB: Logs ============
    tab_l = ttk.Frame(nb, padding=6)
    nb.add(tab_l, text="Logs")
    log_path = tk.StringVar(value="/var/log/syslog")
    log_search = tk.StringVar(value="Failed|error|DENIED|blocked")
    log_status = tk.StringVar(value="Bereit.")
    lbar = ttk.Frame(tab_l)
    lbar.pack(fill="x", pady=(0, 4))
    ttk.Combobox(lbar, textvariable=log_path,
                 values=["/var/log/syslog", "/var/log/auth.log",
                         "/var/log/kern.log", "dmesg"],
                 width=24).pack(side="left")
    ttk.Entry(lbar, textvariable=log_search, width=30).pack(side="left", padx=4)
    ttk.Button(lbar, text="Laden",
               command=lambda: _thread(load_log)).pack(side="left", padx=4)
    ttk.Label(lbar, textvariable=log_status, style="Muted.TLabel").pack(side="right")
    txt_l = _dark_text(tab_l, height=16)
    txt_l.pack(fill="both", expand=True)

    def load_log():
        path = log_path.get().strip()
        try:
            pat = re.compile(log_search.get() or ".*", re.IGNORECASE)
        except re.error as e:
            parent.after(0, lambda: log_status.set(f"Regex-Fehler: {e}"))
            return
        content = tail_log(path, lines=500)
        if content.startswith(("Datei nicht", "Keine Lese", "Fehler")):
            parent.after(0, lambda: (txt_l.delete("1.0", "end"),
                                     txt_l.insert("end", content + "\n"),
                                     log_status.set(content[:120])))
            return
        hits = [l for l in content.splitlines() if pat.search(l)]
        counts: dict[str, int] = {}
        for l in content.splitlines():
            m = BRUTE_RE.search(l) or IP_RE.search(l if "Failed" in l else "")
            if m:
                counts[m.group(1)] = counts.get(m.group(1), 0) + 1
        top = sorted(counts.items(), key=lambda kv: -kv[1])[:10]
        def _do():
            txt_l.delete("1.0", "end")
            txt_l.insert("end", f"Quelle: {path} | Treffer: {len(hits)}\n")
            if top:
                txt_l.insert("end", "Brute-Force-Verdacht pro IP:\n")
                for ip, c in top:
                    txt_l.insert("end", f"  {ip}: {c}x Failed\n")
            txt_l.insert("end", "-" * 60 + "\n")
            for l in hits[-300:]:
                txt_l.insert("end", l[:300] + "\n")
            log_status.set(f"{len(hits)} Treffer, {len(counts)} IPs mit Failed-Login.")
        parent.after(0, _do)

    # ============ TAB: Timeline ============
    tab_t = ttk.Frame(nb, padding=6)
    nb.add(tab_t, text="Timeline")
    tl_status = tk.StringVar(value="Kein Ordner gewählt.")
    ttk.Button(tab_t, text="Ordner wählen…",
               command=lambda: _pick_dir()).pack(anchor="w")
    tv_tl = ttk.Treeview(tab_t, columns=("mtime", "size", "path"),
                         show="headings", height=16)
    for c, w, t in (("mtime", 160, "Geändert"), ("size", 90, "Größe"),
                    ("path", 530, "Pfad")):
        tv_tl.heading(c, text=t)
        tv_tl.column(c, width=w, anchor="w")
    tv_tl.pack(fill="both", expand=True, pady=4)
    style_treeview(tv_tl)
    ttk.Label(tab_t, textvariable=tl_status, style="Muted.TLabel").pack(anchor="w")

    def _pick_dir():
        d = filedialog.askdirectory(title="Ordner für Timeline wählen")
        if d:
            _thread(lambda: timeline(d))

    def timeline(root: str):
        parent.after(0, lambda: tl_status.set(f"Scanne {root} (Tiefe ≤ 4)…"))
        found: list[tuple[float, int, str]] = []
        base_depth = root.rstrip(os.sep).count(os.sep)
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                depth = dirpath.count(os.sep) - base_depth
                if depth > 4:
                    dirnames[:] = []
                    continue
                for name in filenames:
                    p = os.path.join(dirpath, name)
                    try:
                        st = os.stat(p)
                        found.append((st.st_mtime, st.st_size, p))
                    except OSError:
                        continue
                    if len(found) >= 5000:
                        dirnames[:] = []
                        break
        except Exception as e:
            parent.after(0, lambda: tl_status.set(f"Fehler: {e}"))
            return
        found.sort(reverse=True)
        top100 = found[:100]
        def _do():
            tv_tl.delete(*tv_tl.get_children())
            for mt, sz, p in top100:
                tv_tl.insert("", "end", values=(
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mt)),
                    human_size(sz), p[:220]))
            tl_status.set(f"{len(found)} Dateien, neueste {len(top100)} gezeigt.")
        parent.after(0, _do)

    _thread(load_ps)
    return frame
