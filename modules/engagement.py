"""KRYUX — Einsatz & Report: Pentest-Auftrag in einem Tool.

Ziel/W scope, Findings mit Schweregrad, Arbeits-Checkliste und
HTML-Report-Export mit KRYUX-Branding. Alles lokal, keine Cloud.
"""
from __future__ import annotations
import html
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

from core.theme import COLORS, FONTS, card
from core.utils import which_tool

TITLE = "Einsatz & Report"

SEV_COLORS = {"Kritisch": "#ff4d6d", "Hoch": "#ff8a3d", "Mittel": "#ffb300",
              "Niedrig": "#38e1ff", "Info": "#647f76"}
SEV_ORDER = {"Kritisch": 0, "Hoch": 1, "Mittel": 2, "Niedrig": 3, "Info": 4}

CHECKLIST = ["Scoping & Freigabe dokumentiert", "Recon (DNS, OSINT, Harvester)",
             "Netz-Scan (Nmap, Vuln-Scanner)", "Web-Tests (Nikto, Header, SSL)",
             "Schwachstellen verifiziert (nur Scope!)", "Firewall-Regeln geprüft",
             "Forensik-Artefakte gesichert", "Findings bewertet (CVSS-Gedanke)",
             "Report geschrieben & übergeben", "Re-Test angeboten"]


def build(parent: tk.Widget, ctx) -> tk.Frame:
    root = tk.Frame(parent, bg=COLORS["bg"])
    findings: list[dict] = []
    checks: dict[str, tk.BooleanVar] = {}

    # --- Auftrag ---
    au = card(root, "📋 Auftrag & Ziel",
              "Ein Auftrag = ein Report. Nur freigegebene Ziele testen!")
    form = tk.Frame(au, bg=COLORS.get("card", COLORS["panel"]))
    form.pack(fill="x")
    ent_client = tk.Entry(form, bg="#03110b", fg=COLORS["text"], font=FONTS["mono"], width=28)
    ent_target = tk.Entry(form, bg="#03110b", fg=COLORS["text"], font=FONTS["mono"], width=40)
    ent_client.grid(row=0, column=1, padx=6, pady=2, sticky="w")
    ent_target.grid(row=1, column=1, padx=6, pady=2, sticky="w")
    tk.Label(form, text="Kunde/Firma:", bg=COLORS.get("card", COLORS["panel"]),
             fg=COLORS["text"], font=FONTS["mono"]).grid(row=0, column=0, sticky="w")
    tk.Label(form, text="Ziel/Scope:", bg=COLORS.get("card", COLORS["panel"]),
             fg=COLORS["text"], font=FONTS["mono"]).grid(row=1, column=0, sticky="w")

    # --- Findings ---
    fi = card(root, "🐞 Findings", "Befund hinzufügen → erscheint im Report.")
    tree = ttk.Treeview(fi, columns=("sev", "host", "title"), show="headings", height=7)
    tree.heading("sev", text="Schwere")
    tree.heading("host", text="Host")
    tree.heading("title", text="Titel")
    tree.column("sev", width=90)
    tree.column("host", width=180)
    tree.column("title", width=380)
    tree.pack(fill="x")

    add = tk.Frame(fi, bg=COLORS.get("card", COLORS["panel"]))
    add.pack(fill="x", pady=(6, 0))
    ent_title = tk.Entry(add, bg="#03110b", fg=COLORS["text"], font=FONTS["mono"], width=30)
    ent_host = tk.Entry(add, bg="#03110b", fg=COLORS["text"], font=FONTS["mono"], width=22)
    cmb_sev = ttk.Combobox(add, values=list(SEV_ORDER), state="readonly", width=10)
    cmb_sev.set("Mittel")
    txt_desc = tk.Text(add, bg="#03110b", fg=COLORS["text"], font=FONTS["mono"],
                       height=3, wrap="word")
    for w, c in ((ent_title, 0), (ent_host, 1)):
        w.grid(row=0, column=c, padx=4, sticky="we")
    cmb_sev.grid(row=0, column=2, padx=4)
    txt_desc.grid(row=1, column=0, columnspan=3, sticky="we", pady=4)
    add.columnconfigure(0, weight=1)

    def redraw():
        try:
            tree.delete(*tree.get_children())
            for f in sorted(findings, key=lambda x: SEV_ORDER.get(x["sev"], 9)):
                tree.insert("", "end", values=(f["sev"], f["host"], f["title"]))
        except Exception:
            pass

    def add_finding():
        t = ent_title.get().strip()
        if not t:
            messagebox.showwarning("KRYUX", "Bitte mindestens einen Titel angeben.")
            return
        findings.append({"title": t, "host": ent_host.get().strip() or "-",
                         "sev": cmb_sev.get(),
                         "desc": txt_desc.get("1.0", "end").strip()})
        ent_title.delete(0, "end")
        txt_desc.delete("1.0", "end")
        redraw()
        ctx.log(f"Finding erfasst ({len(findings)}): {t}")

    def del_finding():
        sel = tree.selection()
        if not sel:
            return
        vals = tree.item(sel[0], "values")
        for f in list(findings):
            if (f["sev"], f["host"], f["title"]) == tuple(vals):
                findings.remove(f)
                break
        redraw()

    brow = tk.Frame(fi, bg=COLORS.get("card", COLORS["panel"]))
    brow.pack(fill="x", pady=(4, 0))
    for txt, cmd in (("＋ Befund", add_finding), ("− Löschen", del_finding)):
        tk.Button(brow, text=txt, command=cmd, bg=COLORS["panel"],
                  fg=COLORS["neon"], font=FONTS["mono"], relief="groove").pack(side="left", padx=3)

    # --- Checkliste ---
    cl = card(root, "✅ Arbeits-Checkliste", "Damit im Einsatz nichts vergessen wird.")
    for item in CHECKLIST:
        var = tk.BooleanVar(value=False)
        checks[item] = var
        tk.Checkbutton(cl, text=item, variable=var,
                       bg=COLORS.get("card", COLORS["panel"]),
                       fg=COLORS["text"], selectcolor="#0e2a1e",
                       activebackground=COLORS.get("card", COLORS["panel"]),
                       font=FONTS["mono"], anchor="w").pack(fill="x")

    # --- Export ---
    ex = card(root, "📤 Report-Export", "HTML-Report mit Branding + Findings + Toolständen.")

    def export_html():
        client = ent_client.get().strip() or "Unbenannt"
        target = ent_target.get().strip() or "-"
        tools = {t: ("installiert" if which_tool(t) else "fehlt")
                 for t in ("nmap", "nikto", "sqlmap", "msfconsole", "gobuster",
                           "ffuf", "hydra", "john", "tshark", "yara")}
        rows = "".join(
            f"<tr><td style='color:{SEV_COLORS.get(f['sev'], '#fff')}'>{html.escape(f['sev'])}</td>"
            f"<td>{html.escape(f['host'])}</td><td>{html.escape(f['title'])}</td>"
            f"<td>{html.escape(f['desc'])}</td></tr>"
            for f in sorted(findings, key=lambda x: SEV_ORDER.get(x["sev"], 9)))
        checks_html = "".join(
            f"<li>{'☑' if v.get() else '☐'} {html.escape(k)}</li>" for k, v in checks.items())
        tools_html = "".join(f"<li>{t}: {s}</li>" for t, s in tools.items())
        doc = f"""<!DOCTYPE html><html lang="de"><head><meta charset="utf-8">
<title>KRYUX Report — {html.escape(client)}</title>
<style>body{{background:#060b0d;color:#d4f5e5;font-family:monospace;max-width:900px;margin:auto;padding:24px}}
h1{{color:#00ffa3}}h2{{color:#38e1ff}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #1f2f34;padding:6px;text-align:left;font-size:13px}}</style></head>
<body><h1>⬢ KRYUX // SECURITY REPORT</h1>
<p>Kunde: <b>{html.escape(client)}</b> · Ziel/Scope: <b>{html.escape(target)}</b> · Datum: {datetime.now():%d.%m.%Y %H:%M}</p>
<p><i>Nur freigegebene Systeme getestet. Vertraulich.</i></p>
<h2>Findings ({len(findings)})</h2>
<table><tr><th>Schwere</th><th>Host</th><th>Titel</th><th>Beschreibung</th></tr>{rows or '<tr><td colspan=4>Keine Findings.</td></tr>'}</table>
<h2>Checkliste</h2><ul>{checks_html}</ul>
<h2>Werkzeugstände</h2><ul>{tools_html}</ul>
<p style="color:#647f76">Erstellt mit KRYUX // SECURITY SUITE — live, keine Fake-Daten.</p></body></html>"""
        path = filedialog.asksaveasfilename(defaultextension=".html",
                                            filetypes=[("HTML", "*.html")],
                                            initialfile=f"KRYUX_Report_{client[:20]}.html")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(doc)
            ctx.log(f"Report gespeichert: {path}")
            messagebox.showinfo("KRYUX", f"Report gespeichert:\n{path}")
        except Exception as e:
            messagebox.showerror("KRYUX", f"Speichern fehlgeschlagen:\n{e}")

    def save_json():
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"client": ent_client.get(), "target": ent_target.get(),
                           "findings": findings,
                           "checks": {k: v.get() for k, v in checks.items()}}, f,
                          ensure_ascii=False, indent=2)
            ctx.log(f"Einsatz gespeichert: {path}")
        except Exception as e:
            messagebox.showerror("KRYUX", str(e))

    def load_json():
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            ent_client.delete(0, "end")
            ent_client.insert(0, data.get("client", ""))
            ent_target.delete(0, "end")
            ent_target.insert(0, data.get("target", ""))
            findings.clear()
            findings.extend(data.get("findings", []))
            for k, v in data.get("checks", {}).items():
                if k in checks:
                    checks[k].set(bool(v))
            redraw()
            ctx.log(f"Einsatz geladen: {path}")
        except Exception as e:
            messagebox.showerror("KRYUX", str(e))

    for txt, cmd in (("📤 HTML-Report", export_html), ("💾 Speichern", save_json),
                     ("📂 Laden", load_json)):
        tk.Button(ex, text=txt, command=cmd, bg="#0e2a1e", fg="#ffffff",
                  font=FONTS["mono_bold"], relief="groove").pack(side="left", padx=4)
    return root
