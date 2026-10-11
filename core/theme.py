"""KRYUX // SECURITY SUITE — core.theme.

Dark-Neon-Theme (tkinter/ttk): Farben, Fonts, Style-Helfer + ASCII-Banner.
Nur Standardlib (tkinter + ttk).
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

# ---------------------------------------------------------------------------
# KRYUX-Farbwelt (Dark + Neon-Grün/Cyan)
# ---------------------------------------------------------------------------
COLORS: dict[str, str] = {
    "bg": "#060b0d",       # Haupt-Hintergrund (tiefes Petrol-Schwarz)
    "panel": "#0c1416",    # Panel-Hintergrund
    "sidebar": "#04080a",  # Seitenleisten-Hintergrund
    "card": "#101a1d",     # Karten-Hintergrund (modern, leicht erhöht)
    "border": "#1f2f34",   # Karten-/Rahmen-Linien
    "neon": "#00ffa3",     # Primär-Akzent (Neon-Grün)
    "cyan": "#38e1ff",     # Sekundär-Akzent (Cyan)
    "violet": "#9d7bff",   # Tertiär-Akzent (Violett, sparsam)
    "amber": "#ffb300",    # Warnungen
    "red": "#ff4d6d",      # Fehler / kritisch
    "ok": "#00e676",       # Erfolg / installiert
    "text": "#d4f5e5",     # Haupt-Textfarbe (helles Mint)
    "dim": "#647f76",      # Gedimmte Texte / Rahmen
}

# ---------------------------------------------------------------------------
# KRYUX-Fonts (Consolas = Monospace-Look)
# ---------------------------------------------------------------------------
FONTS: dict[str, tuple] = {
    "logo": ("Consolas", 19, "bold"),
    "big": ("Consolas", 22, "bold"),
    "title": ("Consolas", 13, "bold"),
    "mono": ("Consolas", 10),
    "mono_bold": ("Consolas", 10, "bold"),
    "small": ("Consolas", 9),
}

# ---------------------------------------------------------------------------
# ASCII-Banner / Logo-String
# ---------------------------------------------------------------------------
BANNER: str = r"""
 ██╗  ██╗██████╗ ██╗   ██╗██╗   ██╗██╗  ██╗
 ██║ ██╔╝██╔══██╗╚██╗ ██╔╝██║   ██║╚██╗██╔╝
 █████╔╝ ██████╔╝ ╚████╔╝ ██║   ██║ ╚███╔╝
 ██╔═██╗ ██╔══██╗  ╚██╔╝  ██║   ██║ ██╔██╗
 ██║  ██╗██║  ██║   ██║   ╚██████╔╝██╔╝ ██╗
 ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
        KRYUX // SECURITY SUITE
     [ live system intel — no fake data ]
"""


def apply_dark(root: tk.Tk) -> ttk.Style:
    """Konfiguriert root + ttk-Styles auf KRYUX-Dark-Neon. Gibt Style zurück."""
    # --- Grundfarben des Fensters ---
    try:
        root.configure(bg=COLORS["bg"])
    except Exception:
        pass

    style = ttk.Style(root)
    try:
        # 'clam' lässt sich am besten dunkel einfärben
        style.theme_use("clam")
    except Exception:
        pass

    bg = COLORS["bg"]
    panel = COLORS["panel"]
    neon = COLORS["neon"]
    text = COLORS["text"]
    dim = COLORS["dim"]

    # --- Frames & Labels ---
    style.configure("TFrame", background=bg)
    style.configure("Panel.TFrame", background=panel)
    style.configure("TLabel", background=bg, foreground=text, font=FONTS["mono"])
    style.configure("Title.TLabel", background=bg, foreground=neon, font=FONTS["title"])
    style.configure("Logo.TLabel", background=bg, foreground=neon, font=FONTS["logo"])
    style.configure("Dim.TLabel", background=bg, foreground=dim, font=FONTS["small"])

    # --- Buttons (dunkel mit Neon-Rahmen) ---
    style.configure(
        "TButton",
        background=panel,
        foreground=neon,
        bordercolor=neon,
        darkcolor=panel,
        lightcolor=panel,
        font=FONTS["mono"],
        padding=(10, 5),
    )
    style.map(
        "TButton",
        background=[("active", "#0e2018"), ("pressed", "#0e2018")],
        foreground=[("active", "#ffffff"), ("disabled", dim)],
        bordercolor=[("active", neon)],
    )

    # --- Notebook (Tabs) ---
    style.configure("TNotebook", background=bg, borderwidth=0)
    style.configure(
        "TNotebook.Tab",
        background=panel,
        foreground=text,
        font=FONTS["mono"],
        padding=(12, 6),
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", "#0e2018")],
        foreground=[("selected", neon)],
    )

    # --- Eingabefelder ---
    style.configure(
        "TEntry",
        fieldbackground="#03110b",
        background="#03110b",
        foreground=text,
        insertcolor=neon,
        bordercolor=dim,
        font=FONTS["mono"],
    )
    style.configure(
        "TCombobox",
        fieldbackground="#03110b",
        background=panel,
        foreground=text,
        arrowcolor=neon,
        bordercolor=dim,
        font=FONTS["mono"],
    )
    # Dropdown-Liste der Combobox dunkel halten
    try:
        root.option_add("*TCombobox*Listbox.background", "#03110b")
        root.option_add("*TCombobox*Listbox.foreground", text)
        root.option_add("*TCombobox*Listbox.selectBackground", "#0e2018")
        root.option_add("*TCombobox*Listbox.selectForeground", neon)
    except Exception:
        pass

    # --- Treeview (Tabellen) ---
    style.configure(
        "Treeview",
        background="#03110b",
        fieldbackground="#03110b",
        foreground=text,
        rowheight=22,
        bordercolor=dim,
        font=FONTS["mono"],
    )
    style.configure(
        "Treeview.Heading",
        background=panel,
        foreground=neon,
        font=FONTS["title"],
    )
    style.map(
        "Treeview",
        background=[("selected", "#0e2018")],
        foreground=[("selected", neon)],
    )

    # --- Moderne Karten & Akzent-Button ---
    card = COLORS.get("card", panel)
    border = COLORS.get("border", dim)
    style.configure("Card.TFrame", background=card)
    style.configure("Card.TLabel", background=card, foreground=text,
                    font=FONTS["mono"])
    style.configure("CardTitle.TLabel", background=card, foreground=neon,
                    font=FONTS["title"])
    style.configure("Accent.TButton", background="#0e2a1e", foreground="#ffffff",
                    bordercolor=neon, font=FONTS.get("mono_bold", FONTS["mono"]),
                    padding=(12, 6))
    style.map("Accent.TButton",
              background=[("active", "#134a30"), ("pressed", "#134a30")])

    return style


def neon_button(btn: tk.Button | ttk.Button) -> None:
    """Verpasst einem Button den KRYUX-Neon-Look (für tk.Button & ttk ok)."""
    try:
        # tk.Button: direkte Farben setzen
        if isinstance(btn, tk.Button):
            btn.configure(
                bg=COLORS["panel"],
                fg=COLORS["neon"],
                activebackground="#0e2018",
                activeforeground="#ffffff",
                highlightbackground=COLORS["neon"],
                highlightcolor=COLORS["neon"],
                relief="groove",
                borderwidth=1,
                font=FONTS["mono"],
            )
        else:
            # ttk.Button: Style-Key setzen (apply_dark muss vorher gelaufen sein)
            try:
                btn.configure(style="TButton")
            except Exception:
                pass
    except Exception:
        pass


def make_scrolled_text(parent: tk.Widget, height: int = 12) -> tk.Text:
    """Erzeugt ein dunkles Text-Widget mit Scrollbar + grüner Schrift.

    - Gibt das tk.Text zurück (Scrollbar ist mit .yview gekoppelt).
    - Packt Frame (oben) + Scrollbar (rechts) + Text (expand/fill).
    """
    # Container-Rahmen im Panel-Look
    frame = tk.Frame(parent, bg=COLORS["panel"], highlightbackground=COLORS["dim"],
                     highlightthickness=1)
    frame.pack(fill="both", expand=True)

    # Scrollbar (dunkel)
    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side="right", fill="y")

    # Textfeld: dunkler Grund, grüne Monospace-Schrift
    txt = tk.Text(
        frame,
        height=height,
        bg="#03110b",
        fg=COLORS["neon"],
        insertbackground=COLORS["neon"],
        selectbackground="#0e2018",
        selectforeground=COLORS["neon"],
        font=FONTS["mono"],
        wrap="word",
        relief="flat",
        yscrollcommand=scrollbar.set,
    )
    txt.pack(side="left", fill="both", expand=True)
    scrollbar.config(command=txt.yview)

    return txt


# ---------------------------------------------------------------------------
# Kompat-Helfer für bestehende Module (Kurz-Aliase im KRYUX-Look)
# ---------------------------------------------------------------------------
def ensure_ttk_style(widget: tk.Widget) -> ttk.Style | None:
    """Wendet apply_dark() auf das Toplevel von widget an (robust, idempotent)."""
    try:
        top = widget.winfo_toplevel()  # type: ignore[attr-defined]
        return apply_dark(top)  # type: ignore[arg-type]
    except Exception:
        try:
            if isinstance(widget, tk.Tk):
                return apply_dark(widget)
        except Exception:
            pass
    return None


def section(parent: tk.Widget, title: str = "") -> tk.Frame:
    """Erzeugt einen Panel-Abschnitt mit Titelzeile; gibt den Body-Frame zurück.

    Der Abschnitt packt sich selbst (fill=x); Kinder in den Rückgabe-Frame packen.
    """
    outer = tk.Frame(parent, bg=COLORS["panel"], highlightbackground=COLORS["dim"],
                     highlightthickness=1)
    try:
        outer.pack(fill="x", padx=8, pady=6)
    except Exception:
        pass
    if title:
        try:
            tk.Label(outer, text=title, bg=COLORS["panel"], fg=COLORS["neon"],
                     font=FONTS["title"]).pack(anchor="w", padx=8, pady=(6, 2))
        except Exception:
            pass
    body = tk.Frame(outer, bg=COLORS["panel"])
    try:
        body.pack(fill="x", padx=8, pady=(0, 8))
    except Exception:
        pass
    return body


def mk_label(parent: tk.Widget, text: str = "", mono: bool = False,
             muted: bool = False, **kw) -> tk.Label:
    """KRYUX-Label (tk.Label). muted -> dimme Farbe, mono -> Monospace-Font."""
    fg = COLORS["dim"] if muted else COLORS["text"]
    font = FONTS["mono"] if mono else FONTS["small"]
    kw.setdefault("bg", COLORS["bg"])
    kw.setdefault("fg", fg)
    kw.setdefault("font", font)
    try:
        # Falls parent ein Panel-Abschnitt ist, Hintergrund anpassen
        if str(kw.get("bg")) == COLORS["bg"]:
            try:
                if parent.cget("bg") == COLORS["panel"]:
                    kw["bg"] = COLORS["panel"]
            except Exception:
                pass
    except Exception:
        pass
    return tk.Label(parent, text=text, **kw)


def mk_entry(parent: tk.Widget, width: int = 30, **kw) -> tk.Entry:
    """KRYUX-Eingabefeld (tk.Entry, dunkel mit grüner Schrift)."""
    kw.setdefault("width", width)
    kw.setdefault("bg", "#03110b")
    kw.setdefault("fg", COLORS["text"])
    kw.setdefault("insertbackground", COLORS["neon"])
    kw.setdefault("font", FONTS["mono"])
    kw.setdefault("relief", "groove")
    kw.setdefault("highlightbackground", COLORS["dim"])
    return tk.Entry(parent, **kw)


def mk_button(parent: tk.Widget, text: str = "", command=None,
              accent: bool = False, **kw) -> tk.Button:
    """KRYUX-Button (tk.Button). accent -> Neon-Vordergrund extra betont."""
    kw.setdefault("bg", COLORS["panel"] if not accent else "#0e2018")
    kw.setdefault("fg", COLORS["neon"])
    kw.setdefault("activebackground", "#0e2018")
    kw.setdefault("activeforeground", "#ffffff")
    kw.setdefault("font", FONTS["mono"])
    kw.setdefault("relief", "groove")
    btn = tk.Button(parent, text=text, command=command, **kw)
    return btn


def label(parent: tk.Widget, text: str = "", kind: str = "default", **kw) -> tk.Label:
    """Kurz-Alias: kind in {default, title, danger, warn, muted}."""
    kinds = {
        "default": (COLORS["text"], FONTS["mono"]),
        "title": (COLORS["neon"], FONTS["title"]),
        "danger": (COLORS["red"], FONTS["mono"]),
        "warn": (COLORS["amber"], FONTS["mono"]),
        "muted": (COLORS["dim"], FONTS["small"]),
    }
    fg, font = kinds.get(kind, kinds["default"])
    kw.setdefault("bg", COLORS["bg"])
    kw.setdefault("fg", fg)
    kw.setdefault("font", font)
    return tk.Label(parent, text=text, **kw)


def entry(parent: tk.Widget, width: int = 30, **kw) -> tk.Entry:
    """Kurz-Alias für mk_entry()."""
    return mk_entry(parent, width=width, **kw)


def button(parent: tk.Widget, text: str = "", command=None,
           kind: str = "default", **kw) -> tk.Button:
    """Kurz-Alias: kind in {default, danger, warn} steuert die Akzentfarbe."""
    fg = {"default": COLORS["neon"], "danger": COLORS["red"],
          "warn": COLORS["amber"]}.get(kind, COLORS["neon"])
    kw.setdefault("bg", COLORS["panel"])
    kw.setdefault("fg", fg)
    kw.setdefault("activebackground", "#0e2018")
    kw.setdefault("activeforeground", "#ffffff")
    kw.setdefault("font", FONTS["mono"])
    kw.setdefault("relief", "groove")
    return tk.Button(parent, text=text, command=command, **kw)


def output_text(parent: tk.Widget, height: int = 12) -> tk.Text:
    """Kurz-Alias für make_scrolled_text()."""
    return make_scrolled_text(parent, height=height)


def card(parent: tk.Widget, title: str = "", subtitle: str = "") -> tk.Frame:
    """Moderne Karte: dunkler Card-Hintergrund + Border + Titel.

    Gibt den Body-Frame zurück (Kinder dorthin packen).
    """
    outer = tk.Frame(parent, bg=COLORS.get("card", COLORS["panel"]),
                     highlightbackground=COLORS.get("border", COLORS["dim"]),
                     highlightthickness=1)
    try:
        outer.pack(fill="x", padx=8, pady=6)
    except Exception:
        pass
    if title:
        try:
            tk.Label(outer, text=title,
                     bg=COLORS.get("card", COLORS["panel"]),
                     fg=COLORS["neon"], font=FONTS["title"]).pack(
                         anchor="w", padx=10, pady=(8, 0))
        except Exception:
            pass
    if subtitle:
        try:
            tk.Label(outer, text=subtitle,
                     bg=COLORS.get("card", COLORS["panel"]),
                     fg=COLORS["dim"], font=FONTS["small"]).pack(
                         anchor="w", padx=10, pady=(0, 2))
        except Exception:
            pass
    body = tk.Frame(outer, bg=COLORS.get("card", COLORS["panel"]))
    try:
        body.pack(fill="x", padx=10, pady=(2, 10))
    except Exception:
        pass
    return body


def pill(parent: tk.Widget, text: str = "", kind: str = "ok") -> tk.Label:
    """Status-Pille: kind in {ok, warn, danger, info, muted}."""
    fg = {"ok": COLORS.get("ok", COLORS["neon"]), "warn": COLORS["amber"],
          "danger": COLORS["red"], "info": COLORS["cyan"],
          "muted": COLORS["dim"]}.get(kind, COLORS["text"])
    return tk.Label(parent, text=f" {text} ",
                    bg=COLORS.get("card", COLORS["panel"]), fg=fg,
                    font=FONTS["small"], relief="groove", borderwidth=1)


def draw_line_chart(canvas: tk.Canvas, series: list[float], max_val: float = 100.0,
                    line: str | None = None, fill: bool = True) -> None:
    """Zeichnet einen minimalen Live-Linienchart auf ein Canvas (SOC-Look).

    - series: Werte 0..max_val (älteste zuerst)
    - Grid + Linie + leichte Fläche, alles im KRYUX-Stil.
    """
    try:
        canvas.delete("all")
        w = canvas.winfo_width() or 300
        h = canvas.winfo_height() or 90
        line = line or COLORS["neon"]
        # Grid
        for i in range(1, 4):
            y = h * i / 4
            canvas.create_line(0, y, w, y, fill=COLORS.get("border", "#1f2f34"))
        if not series:
            return
        n = len(series)
        pts = []
        for i, v in enumerate(series):
            x = (i / max(n - 1, 1)) * (w - 4) + 2
            y = h - 4 - (min(max(v, 0), max_val) / max_val) * (h - 10)
            pts.extend([x, y])
        if fill and len(pts) >= 4:
            canvas.create_polygon(pts + [pts[-2], h, pts[0], h],
                                  fill="#0e2a1e", outline="")
        if len(pts) >= 4:
            canvas.create_line(*pts, fill=line, width=2, smooth=True)
        # letzter Wert als Punkt
        canvas.create_oval(pts[-2] - 3, pts[-1] - 3, pts[-2] + 3, pts[-1] + 3,
                           fill=line, outline="")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# ScrollableFrame: Canvas + Scrollbar + Mausrad (für Sidebar & Modul-Seiten)
# ---------------------------------------------------------------------------
class ScrollableFrame(tk.Frame):
    """Vertikal scrollbarer Frame (KRYUX-Dark-Style).

    Nutzung:
        sf = ScrollableFrame(parent, bg=COLORS["bg"])
        sf.pack(fill="both", expand=True)
        tk.Label(sf.inner, text="...").pack()  # in sf.inner packen/gridden
    - Mausrad: Linux (Button-4/5), Windows (MouseWheel), macOS (MouseWheel).
    - Bindet automatisch an sichtbare Größe (scrollregion folgt Inhalt).
    """

    def __init__(self, parent: tk.Widget, bg: str | None = None,
                 scrollbar_width: int = 12, **kw) -> None:
        super().__init__(parent, bg=bg or COLORS["bg"], **kw)
        self._bg = bg or COLORS["bg"]

        self.canvas = tk.Canvas(self, bg=self._bg, highlightthickness=0,
                                bd=0, relief="flat")
        self.vbar = tk.Scrollbar(self, orient="vertical",
                                 command=self.canvas.yview,
                                 width=scrollbar_width)
        try:
            self.vbar.configure(bg=COLORS["panel"], troughcolor=self._bg,
                                activebackground=COLORS["neon"])
        except Exception:
            pass
        self.canvas.configure(yscrollcommand=self.vbar.set)

        self.vbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.inner = tk.Frame(self.canvas, bg=self._bg)
        self._win = self.canvas.create_window((0, 0), window=self.inner,
                                              anchor="nw")

        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        # Mausrad nur wenn Maus über dem Widget (verhindert Doppel-Scroll)
        self.inner.bind("<Enter>", lambda e: self._bind_wheel())
        self.inner.bind("<Leave>", lambda e: self._unbind_wheel())

    def _on_inner_configure(self, event=None) -> None:
        try:
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        except Exception:
            pass

    def _on_canvas_configure(self, event=None) -> None:
        try:
            self.canvas.itemconfig(self._win, width=event.width)
        except Exception:
            pass

    def _on_wheel(self, event) -> str | None:
        try:
            num = getattr(event, "num", None)
            if num == 4:  # Linux hoch
                self.canvas.yview_scroll(-1, "units")
            elif num == 5:  # Linux runter
                self.canvas.yview_scroll(1, "units")
            else:  # Windows / macOS
                delta = getattr(event, "delta", 0)
                if delta:
                    self.canvas.yview_scroll(int(-delta / 120), "units")
            self._on_inner_configure()
        except Exception:
            pass
        return "break"

    def _bind_wheel(self) -> None:
        try:
            self.canvas.bind_all("<Button-4>", self._on_wheel, add="+")
            self.canvas.bind_all("<Button-5>", self._on_wheel, add="+")
            self.canvas.bind_all("<MouseWheel>", self._on_wheel, add="+")
        except Exception:
            pass

    def _unbind_wheel(self) -> None:
        try:
            self.canvas.unbind_all("<Button-4>")
            self.canvas.unbind_all("<Button-5>")
            self.canvas.unbind_all("<MouseWheel>")
        except Exception:
            pass
