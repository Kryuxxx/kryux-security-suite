#!/usr/bin/env python3
"""KRYUX // SECURITY SUITE — Hauptprogramm.

Moderne Hacker-GUI (Dark-Neon, Cards, Pills, Scroll überall), 15 Live-Module.
Nur Standardlib + tkinter. Keine Fake-Daten: alles via core.utils live.
Nur eigene Systeme / mit Erlaubnis testen!
"""
import sys
import threading
import tkinter as tk
from tkinter import ttk
from datetime import datetime

from core.theme import COLORS, FONTS, BANNER, apply_dark, ScrollableFrame
from core.utils import which_tool

# Module imports (alle: TITLE + build(parent, ctx))
from modules import dashboard, nmap_scanner, web_scanner, sqlmap_runner
from modules import metasploit, vuln_scanner, firewall_manager, forensics
from modules import network_tools, password_crypto, kali_arsenal
from modules import setup_install, engagement, terminal, extras

MODULES = [
    dashboard, nmap_scanner, web_scanner, sqlmap_runner,
    metasploit, vuln_scanner, firewall_manager, forensics,
    network_tools, password_crypto, kali_arsenal, setup_install,
    engagement, terminal, extras,
]

TOOLS = ["nmap", "nikto", "sqlmap", "msfconsole", "ufw", "gobuster",
         "ffuf", "hydra", "john", "hashcat", "tshark", "yara", "binwalk",
         "theHarvester", "amass", "searchsploit", "wpscan", "whatweb"]


class Ctx(dict):
    """App-Kontext: dict-kompatibel + log/run_bg für Module."""
    def __init__(self, status_cb):
        super().__init__()
        self._status_cb = status_cb

    def log(self, msg: str):
        try:
            self._status_cb(str(msg))
        except Exception:
            print(msg)

    def run_bg(self, func, *a, **k):
        t = threading.Thread(target=func, args=a, kwargs=k, daemon=True)
        t.start()
        return t


class KryuxApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("KRYUX // SECURITY SUITE — Ultimate Cyber Defense")
        root.geometry("1380x860")
        root.minsize(1120, 720)
        apply_dark(root)

        self.ctx = Ctx(self.set_status)
        self.frames = {}
        self.current = None

        # --- Sidebar (scrollbar, mit Suche) ---
        side_wrap = tk.Frame(root, bg=COLORS["sidebar"], width=272,
                             highlightbackground=COLORS.get("border", COLORS["dim"]),
                             highlightthickness=1)
        side_wrap.pack(side="left", fill="y")
        side_wrap.pack_propagate(False)
        self.side_scroll = ScrollableFrame(side_wrap, bg=COLORS["sidebar"])
        self.side_scroll.pack(fill="both", expand=True)
        self.sidebar = self.side_scroll.inner

        main_col = tk.Frame(root, bg=COLORS["bg"])
        main_col.pack(side="left", fill="both", expand=True)

        # --- Topbar ---
        top = tk.Frame(main_col, bg=COLORS["panel"], height=52,
                       highlightbackground=COLORS.get("border", COLORS["dim"]),
                       highlightthickness=1)
        top.pack(side="top", fill="x")
        top.pack_propagate(False)
        self.title_lbl = tk.Label(top, text="SOC DASHBOARD", bg=COLORS["panel"],
                                  fg=COLORS["neon"], font=FONTS["title"])
        self.title_lbl.pack(side="left", padx=12, pady=12)
        self.tool_pill = tk.Label(top, text="", bg=COLORS.get("card", COLORS["panel"]),
                                  fg=COLORS["cyan"], font=FONTS["small"],
                                  relief="groove", borderwidth=1)
        self.tool_pill.pack(side="left", padx=8)
        self.root_pill = tk.Label(top, text="", bg=COLORS.get("card", COLORS["panel"]),
                                  font=FONTS["small"], relief="groove", borderwidth=1)
        self.root_pill.pack(side="left", padx=4)
        self.clock_lbl = tk.Label(top, text="", bg=COLORS["panel"],
                                  fg=COLORS["cyan"], font=FONTS["mono"])
        self.clock_lbl.pack(side="right", padx=12)

        # --- Content ---
        self.content = tk.Frame(main_col, bg=COLORS["bg"])
        self.content.pack(side="top", fill="both", expand=True)

        # --- Statusbar ---
        self.status = tk.Label(main_col, text="KRYUX bereit — alle Daten live.",
                               bg=COLORS["sidebar"], fg=COLORS["dim"],
                               font=FONTS["small"], anchor="w")
        self.status.pack(side="bottom", fill="x")

        self._build_sidebar()
        self._build_frames()
        self._refresh_tools()
        self._tick_clock()
        self.show(0)

    # -- Sidebar mit Live-Suche --
    def _build_sidebar(self):
        logo = tk.Label(self.sidebar, text="⬢ KRYUX", bg=COLORS["sidebar"],
                        fg=COLORS["neon"], font=FONTS["logo"])
        logo.pack(pady=(14, 0))
        sub = tk.Label(self.sidebar, text="// SECURITY SUITE  v2.0",
                       bg=COLORS["sidebar"], fg=COLORS.get("violet", COLORS["cyan"]),
                       font=FONTS["small"])
        sub.pack(pady=(0, 2))
        hint = tk.Label(self.sidebar, text="live • no fake data • scroll ↓",
                        bg=COLORS["sidebar"], fg=COLORS["dim"], font=FONTS["small"])
        hint.pack(pady=(0, 8))

        self.search = tk.Entry(self.sidebar, bg="#03110b", fg=COLORS["text"],
                               insertbackground=COLORS["neon"], font=FONTS["mono"],
                               relief="groove", highlightbackground=COLORS["dim"])
        self.search.pack(fill="x", padx=10, pady=(0, 8))
        self.search.insert(0, "⌕ Modul suchen …")
        self.search.bind("<FocusIn>", lambda e: self._clear_search_hint())
        self.search.bind("<KeyRelease>", lambda e: self._filter_nav())

        self.nav_box = tk.Frame(self.sidebar, bg=COLORS["sidebar"])
        self.nav_box.pack(fill="x")
        self.nav_btns: list[tuple[int, tk.Button]] = []
        for i, mod in enumerate(MODULES):
            title = getattr(mod, "TITLE", mod.__name__)
            b = tk.Button(self.nav_box, text=f"  ▸ {title}", anchor="w",
                          bg=COLORS["sidebar"], fg=COLORS["text"],
                          activebackground="#0e2a1e", activeforeground=COLORS["neon"],
                          relief="flat", font=FONTS["mono"], padx=10, pady=7,
                          command=lambda idx=i: self.show(idx))
            b.pack(fill="x", padx=8, pady=1)
            self.nav_btns.append((i, b))

        tk.Label(self.sidebar, text="Nur eigene Systeme testen!",
                 bg=COLORS["sidebar"], fg=COLORS["amber"],
                 font=FONTS["small"], wraplength=230).pack(pady=12)

    def _clear_search_hint(self):
        if self.search.get().startswith("⌕"):
            self.search.delete(0, "end")

    def _filter_nav(self):
        q = self.search.get().lower().replace("⌕", "").strip()
        for i, b in self.nav_btns:
            title = getattr(MODULES[i], "TITLE", "").lower()
            b.pack_forget() if q and q not in title else None
            if not q or q in title:
                b.pack(fill="x", padx=8, pady=1)
            else:
                try:
                    b.pack_forget()
                except Exception:
                    pass

    def _build_frames(self):
        for mod in MODULES:
            holder = tk.Frame(self.content, bg=COLORS["bg"])
            holder.place(relx=0, rely=0, relwidth=1, relheight=1)
            try:
                sf = ScrollableFrame(holder, bg=COLORS["bg"])
                sf.pack(fill="both", expand=True)
                inner = mod.build(sf.inner, self.ctx)
                if inner is not None and inner is not sf.inner:
                    try:
                        inner.pack(fill="both", expand=True)
                    except Exception:
                        pass
            except Exception as e:
                tk.Label(holder, text=f"Modul-Fehler {getattr(mod,'TITLE','?')}: {e}",
                         bg=COLORS["bg"], fg=COLORS["red"],
                         font=FONTS["mono"]).pack(pady=20)
            self.frames[mod] = holder

    def show(self, idx: int):
        mod = MODULES[idx]
        for m, f in self.frames.items():
            f.lower()
        self.frames[mod].lift()
        self.current = idx
        self.title_lbl.config(text=getattr(mod, "TITLE", "?").upper())
        for i, b in self.nav_btns:
            try:
                b.config(fg=COLORS["neon"] if i == idx else COLORS["text"],
                         bg="#0e2a1e" if i == idx else COLORS["sidebar"])
            except Exception:
                pass
        self.set_status(f"KRYUX › {getattr(mod,'TITLE','')} geladen.")

    def set_status(self, msg: str):
        def _set():
            try:
                self.status.config(text=f"[{datetime.now():%H:%M:%S}] {msg[:220]}")
            except Exception:
                pass
        try:
            self.root.after(0, _set)
        except Exception:
            pass

    def _refresh_tools(self):
        ok = sum(1 for t in TOOLS if which_tool(t) is not None)
        self.tool_pill.config(text=f" ◉ {ok}/{len(TOOLS)} Tools ")
        try:
            import os
            is_root = os.geteuid() == 0
        except Exception:
            is_root = False
        self.root_pill.config(
            text=" ⚠ ROOT " if is_root else " ○ user ",
            fg=COLORS["amber"] if is_root else COLORS["dim"])

    def _tick_clock(self):
        try:
            self.clock_lbl.config(text=datetime.now().strftime("%d.%m.%Y  %H:%M:%S"))
        except Exception:
            pass
        self.root.after(1000, self._tick_clock)


def main():
    print(BANNER)
    for m in MODULES:
        print(f"  [KRYUX] Modul OK: {getattr(m,'TITLE', m.__name__)}")
    missing = [t for t in ("nmap", "nikto", "sqlmap", "msfconsole")
               if which_tool(t) is None]
    if missing:
        print(f"  [KRYUX] Hinweis: nicht installiert → {', '.join(missing)}")
        print("           → Modul 'Setup & Install' zeigt Ubuntu-Alternativen (Git/Go/Gem/Docker).")
    root = tk.Tk()
    KryuxApp(root)
    root.mainloop()


if __name__ == "__main__":
    sys.exit(main())
