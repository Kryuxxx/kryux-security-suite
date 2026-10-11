"""Passwort & Krypto — Stärke-Check, Hashes, Cracker-Lab, AES-Demo, Phishing-Check.

Vertrag: TITLE + build(parent, ctx) -> tk.Frame. Alles lokal, dunkles Theme.
"""

import base64
import hashlib
import ipaddress
import math
import os
import re
import threading
import tkinter as tk
from tkinter import filedialog, ttk
from urllib.parse import urlparse

TITLE = "Passwort & Krypto"

try:
    from core.theme import COLORS, FONTS  # type: ignore
except Exception:
    COLORS = {}
    FONTS = {}

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
F_BOLD = FONTS.get("bold", FONTS.get("NORMAL", ("Consolas", 10, "bold")))
F_DEF = FONTS.get("mono", FONTS.get("NORMAL", ("Consolas", 10)))
F_SMALL = FONTS.get("small", FONTS.get("SMALL", ("Consolas", 9)))

try:
    from cryptography.fernet import Fernet, InvalidToken
    _HAS_FERNET = True
except Exception:
    Fernet = None
    InvalidToken = Exception
    _HAS_FERNET = False

HASH_ALGOS = ["md5", "sha1", "sha256", "sha512", "sha3-256", "pbkdf2-sha256"]
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz",
                   "zip", "mov", "country", "stream", "party"}
PHISH_KEYWORDS = ("login", "verify", "verifizieren", "konto", "account",
                  "bank", "paypal", "sicherheit", "update", "bonus",
                  "gewinn", "suspend", "unlock", "signin")


# ---------------------------------------------------------- kleine Helfer ---
def _section(parent, title):
    lf = tk.LabelFrame(parent, text=f"  {title}  ", bg=PANEL, fg=FG,
                       font=F_BOLD, bd=1, relief="solid", labelanchor="nw")
    return lf


def _label(parent, text, fg=None, font=None):
    return tk.Label(parent, text=text, bg=parent.cget("bg") if _has_bg(parent) else PANEL,
                    fg=fg or FG, font=font or F_DEF, anchor="w", justify="left")


def _button(parent, text, command=None, accent=False):
    return tk.Button(parent, text=text, command=command, font=F_DEF, relief="groove",
                     bd=1, cursor="hand2",
                     bg="#0e2018" if accent else PANEL,
                     fg=ACCENT if accent else FG,
                     activebackground="#0e2018", activeforeground="#ffffff",
                     highlightbackground=ACCENT if accent else MUTED,
                     padx=10, pady=3)


def _entry(parent, **kw):
    base = {"bg": ENTRY_BG, "fg": FG, "insertbackground": ACCENT,
            "font": F_DEF, "relief": "solid", "bd": 1}
    base.update(kw)
    return tk.Entry(parent, **base)


def _has_bg(widget):
    try:
        widget.cget("bg")
        return True
    except Exception:
        return False


def _style_ttk(root):
    try:
        s = ttk.Style(root)
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure("KRYUX.TCombobox", fieldbackground=ENTRY_BG, background=PANEL,
                    foreground=FG, arrowcolor=ACCENT)
        s.configure("KRYUX.Horizontal.TProgressbar", background=ACCENT,
                    troughcolor=ENTRY_BG)
    except Exception:
        pass


# ---------------------------------------------------------------- Stärke ---
def _check_strength(pw: str):
    n = len(pw)
    classes = {
        "Kleinbuchstaben": bool(re.search(r"[a-zäöüß]", pw)),
        "Großbuchstaben": bool(re.search(r"[A-ZÄÖÜ]", pw)),
        "Ziffern": bool(re.search(r"[0-9]", pw)),
        "Sonderzeichen": bool(re.search(r"[^A-Za-z0-9ÄÖÜäöüß]", pw)),
    }
    active = sum(1 for v in classes.values() if v)
    pool = (26 if classes["Kleinbuchstaben"] else 0) + \
           (26 if classes["Großbuchstaben"] else 0) + \
           (10 if classes["Ziffern"] else 0) + \
           (32 if classes["Sonderzeichen"] else 0)
    entropy = round(n * math.log2(pool), 1) if n and pool else 0.0
    score = max(0, min(100, min(30, n * 2) + active * 12 + min(22, int(entropy / 6))))
    if score < 30:
        label = "Sehr schwach"
    elif score < 50:
        label = "Schwach"
    elif score < 70:
        label = "Mittel"
    elif score < 90:
        label = "Stark"
    else:
        label = "Sehr stark"
    tipps = []
    if n < 12:
        tipps.append("• Mindestens 12 Zeichen verwenden (besser 16+).")
    if not classes["Großbuchstaben"]:
        tipps.append("• Großbuchstaben ergänzen.")
    if not classes["Kleinbuchstaben"]:
        tipps.append("• Kleinbuchstaben ergänzen.")
    if not classes["Ziffern"]:
        tipps.append("• Ziffern ergänzen.")
    if not classes["Sonderzeichen"]:
        tipps.append("• Sonderzeichen ergänzen (!?#+-…).")
    if re.search(r"(123|abc|qwert|passwort|111|000)", pw.lower()):
        tipps.append("• Einfache Muster/Zahlenfolgen vermeiden.")
    if not tipps:
        tipps.append("• Gute Basis — trotzdem Passwort-Manager + 2FA nutzen.")
    tipps.append("• Hinweis: Prüfung erfolgt lokal, nichts wird übertragen.")
    return {"len": n, "classes": classes, "active": active,
            "entropy": entropy, "score": score, "label": label, "tipps": tipps}


# ---------------------------------------------------------------- Hash -----
def _hash_text(text: str, algo: str) -> str:
    data = text.encode("utf-8")
    if algo == "md5":
        return hashlib.md5(data).hexdigest()
    if algo == "sha1":
        return hashlib.sha1(data).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(data).hexdigest()
    if algo == "sha512":
        return hashlib.sha512(data).hexdigest()
    if algo == "sha3-256":
        return hashlib.sha3_256(data).hexdigest()
    if algo == "pbkdf2-sha256":
        salt = b"kryux-demo-salt"
        dk = hashlib.pbkdf2_hmac("sha256", data, salt, 100_000)
        return "pbkdf2_sha256$100000$kryux-demo-salt$" + dk.hex()
    raise ValueError(algo)


def _guess_algo(h: str):
    h = h.strip().lower()
    if h.startswith("pbkdf2_sha256$"):
        return "pbkdf2-sha256"
    if re.fullmatch(r"[0-9a-f]+", h):
        return {32: "md5", 40: "sha1", 64: ["sha256", "sha3-256"], 128: "sha512"}.get(len(h))
    return None


def _xor_crypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("Leerer Schlüssel")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# ---------------------------------------------------------------- Phishing --
def _phishing_check(url: str):
    u = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "http://" + u
    findings = []
    score = 0
    try:
        p = urlparse(u)
    except Exception:
        return [("Ungültige URL", 20)], 20, "auffällig"
    host = (p.hostname or "").lower().rstrip(".")
    full = u.lower()
    try:
        ipaddress.ip_address(host)
        findings.append(("IP-Adresse statt Domain", 25))
        score += 25
    except Exception:
        pass
    if "xn--" in host or "xn--" in full:
        findings.append(("Punycode (xn--) — mögliche IDN-Täuschung", 25))
        score += 25
    if "@" in u.split("://", 1)[-1]:
        findings.append(("@ in URL — Umleitungstrick", 20))
        score += 20
    if p.scheme == "http":
        findings.append(("Nur http (kein https)", 15))
        score += 15
    parts = host.split(".") if host else []
    if len(parts) >= 4:
        findings.append((f"Viele Subdomains ({len(parts)} Ebenen)", 10))
        score += 10
    if host.count("-") >= 2:
        findings.append(("Viele Bindestriche in Domain", 10))
        score += 10
    if len(u) > 120:
        findings.append((f"Sehr lange URL ({len(u)} Zeichen)", 10))
        score += 10
    if parts and parts[-1] in SUSPICIOUS_TLDS:
        findings.append((f"Auffällige TLD (.{parts[-1]})", 15))
        score += 15
    hit = [k for k in PHISH_KEYWORDS if k in full]
    if hit:
        findings.append((f"Lockwort(e): {', '.join(hit[:4])}", 15))
        score += 15
    try:
        port = p.port
    except Exception:
        port = None
    if port and port not in (80, 443):
        findings.append((f"Ungewöhnlicher Port :{port}", 10))
        score += 10
    score = max(0, min(100, score))
    if not findings:
        findings.append(("Keine typischen Phishing-Merkmale gefunden", 0))
    label = "unauffällig" if score < 25 else ("verdächtig" if score < 55 else "auffällig/gefährlich")
    return findings, score, label


# ---------------------------------------------------------------- Build -----
def build(parent, ctx) -> tk.Frame:
    _style_ttk(parent)
    root = tk.Frame(parent, bg=BG)
    root.pack(fill="both", expand=True)
    root._alive = True
    root.bind("<Destroy>", lambda _e: setattr(root, "_alive", False))

    def alive():
        return getattr(root, "_alive", True)

    tk.Label(root, text="🔐 Passwort & Krypto (100 % lokal)",
             bg=BG, fg=FG, font=F_TITLE, anchor="w").pack(fill="x", padx=10, pady=(8, 4))

    # ---- 1. Passwort-Stärke -------------------------------------------
    s1 = _section(root, "1 · Passwort-Stärke (lokal, keine Netz-Abfrage)")
    s1.pack(fill="x", padx=10, pady=5)
    row = tk.Frame(s1, bg=PANEL)
    row.pack(fill="x", padx=8, pady=6)
    _label(row, "Passwort:").pack(side="left")
    pw_entry = _entry(row, show="*", width=32)
    pw_entry.pack(side="left", padx=6)
    show_var = tk.BooleanVar(value=False)

    def _toggle_show():
        pw_entry.configure(show="" if show_var.get() else "*")

    tk.Checkbutton(row, text="anzeigen", variable=show_var, command=_toggle_show,
                   bg=PANEL, fg=MUTED, selectcolor=PANEL,
                   activebackground=PANEL, font=F_SMALL).pack(side="left")
    _button(row, "Prüfen", command=lambda: _do_strength(), accent=True).pack(side="left", padx=6)
    pw_out = _label(s1, "—", font=F_DEF)
    pw_out.pack(fill="x", padx=8)
    pw_tips = tk.Text(s1, height=4, bg=ENTRY_BG, fg=MUTED, font=F_SMALL,
                      relief="solid", bd=1, wrap="word")
    pw_tips.pack(fill="x", padx=8, pady=(2, 8))
    pw_tips.configure(state="disabled")

    def _do_strength():
        r = _check_strength(pw_entry.get())
        kl = ", ".join(k for k, v in r["classes"].items() if v) or "keine"
        pw_out.configure(
            text=f"Länge: {r['len']}  ·  Klassen: {r['active']}/4 ({kl})  ·  "
                 f"Entropie: ~{r['entropy']} Bit  ·  Score: {r['score']}/100 ({r['label']})",
            fg=OK if r["score"] >= 70 else (WARN if r["score"] >= 40 else DANGER))
        pw_tips.configure(state="normal")
        pw_tips.delete("1.0", "end")
        pw_tips.insert("end", "\n".join(r["tipps"]))
        pw_tips.configure(state="disabled")

    pw_entry.bind("<Return>", lambda e: _do_strength())

    # ---- 2. Hash-Generator --------------------------------------------
    s2 = _section(root, "2 · Hash-Generator (hashlib)")
    s2.pack(fill="x", padx=10, pady=5)
    r2 = tk.Frame(s2, bg=PANEL)
    r2.pack(fill="x", padx=8, pady=6)
    _label(r2, "Text:").pack(side="left")
    hash_in = _entry(r2, width=30)
    hash_in.pack(side="left", padx=6, fill="x", expand=True)
    algo_cb = ttk.Combobox(r2, values=HASH_ALGOS, state="readonly", width=15,
                           style="KRYUX.TCombobox")
    algo_cb.set("sha256")
    algo_cb.pack(side="left", padx=4)
    _button(r2, "Hash berechnen", command=lambda: _do_hash(), accent=True).pack(side="left", padx=4)
    hash_out = tk.Text(s2, height=3, bg=ENTRY_BG, fg=OK, font=F_SMALL,
                       relief="solid", bd=1, wrap="word")
    hash_out.pack(fill="x", padx=8, pady=(0, 8))

    def _do_hash():
        try:
            digest = _hash_text(hash_in.get(), algo_cb.get())
        except Exception as e:
            digest = f"Fehler: {e}"
        hash_out.delete("1.0", "end")
        hash_out.insert("end", digest)

    hash_in.bind("<Return>", lambda e: _do_hash())

    # ---- 3. Hash-Cracker (Lab) -----------------------------------------
    s3 = _section(root, "3 · Hash-Cracker — nur eigene Hashes (Dictionary-Lab)")
    s3.pack(fill="x", padx=10, pady=5)
    _label(s3, "⚠ Consent: Nur eigene Passwörter/Hashes oder Lab-Wortlisten verwenden!",
           fg=WARN, font=F_SMALL).pack(fill="x", padx=8, pady=(6, 0))
    r3 = tk.Frame(s3, bg=PANEL)
    r3.pack(fill="x", padx=8, pady=6)
    _label(r3, "Hash:").pack(side="left")
    crack_hash = _entry(r3, width=34)
    crack_hash.pack(side="left", padx=6, fill="x", expand=True)
    crack_algo = ttk.Combobox(r3, values=["auto"] + HASH_ALGOS, state="readonly",
                              width=13, style="KRYUX.TCombobox")
    crack_algo.set("auto")
    crack_algo.pack(side="left", padx=4)
    wordlist_var = tk.StringVar(value="keine Wortliste gewählt")
    _label(s3, "Wortliste:", fg=MUTED, font=F_SMALL).pack(anchor="w", padx=8)
    wl_row = tk.Frame(s3, bg=PANEL)
    wl_row.pack(fill="x", padx=8, pady=(0, 4))
    wl_lbl = _label(wl_row, "", font=F_SMALL)
    wl_lbl.pack(side="left", fill="x", expand=True)

    def _refresh_wl(*_a):
        try:
            wl_lbl.configure(text=wordlist_var.get())
        except Exception:
            pass
    try:
        wordlist_var.trace_add("write", _refresh_wl)
    except Exception:
        pass
    _refresh_wl()

    def _choose_wl():
        p = filedialog.askopenfilename(title="Wortliste wählen (txt, ein Kandidat pro Zeile)",
                                       filetypes=[("Text", "*.txt"), ("Alle", "*.*")])
        if p:
            wordlist_var.set(p)

    _button(wl_row, "Wortliste wählen…", command=_choose_wl).pack(side="right")
    prog = ttk.Progressbar(s3, mode="determinate", style="KRYUX.Horizontal.TProgressbar")
    prog.pack(fill="x", padx=8, pady=4)
    crack_status = _label(s3, "Bereit.", font=F_SMALL, fg=MUTED)
    crack_status.pack(fill="x", padx=8, pady=(0, 4))
    crack_state = {"stop": False, "running": False}

    def _set_status(txt, color=None):
        if not alive():
            return
        crack_status.configure(text=txt, fg=color or FG)

    def _crack_worker(target, algos, path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                total = sum(1 for _ in f)
            total = max(1, total)
            found = None
            done = 0
            t_low = target.strip().lower().split("$")[-1]
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if crack_state["stop"]:
                        break
                    cand = line.rstrip("\r\n")
                    done += 1
                    if cand:
                        for a in algos:
                            try:
                                d = _hash_text(cand, a)
                                if d.lower() == target.strip().lower() or \
                                   d.split("$")[-1].lower() == t_low:
                                    found = (cand, a)
                                    break
                            except Exception:
                                continue
                    if found or done % 50 == 0 or done >= total:
                        pct = done * 100.0 / total
                        d0, t0, p0 = done, total, pct
                        root.after(0, lambda d=d0, t=t0, p=p0: (
                            prog.configure(value=p),
                            crack_status.configure(text=f"{d}/{t} geprüft ({p:.1f} %) …")))

                    if found:
                        break

            def _fin():
                crack_state["running"] = False
                crack_state["stop"] = False
                if found:
                    prog.configure(value=100)
                    _set_status(f"✔ Treffer: '{found[0]}'  (Algo: {found[1]}) — nur für eigene Lab-Zwecke!", OK)
                elif crack_state.get("aborted"):
                    _set_status("Abgebrochen.", WARN)
                else:
                    # stop-Flag wurde oben schon zurückgesetzt; anhand found entscheiden
                    _set_status("Kein Treffer in dieser Wortliste." if not found else "Fertig.", MUTED)
                crack_state.pop("aborted", None)
            root.after(0, _fin)
        except Exception as e:
            root.after(0, lambda: (_set_status(f"Fehler: {e}", DANGER),
                                   crack_state.update(running=False)))

    def _start_crack():
        if crack_state["running"]:
            return
        target = crack_hash.get().strip()
        path = wordlist_var.get()
        if not target:
            _set_status("Bitte zuerst einen Hash eintragen.", WARN)
            return
        if not os.path.isfile(path):
            _set_status("Bitte eine Wortliste-Datei wählen.", WARN)
            return
        sel = crack_algo.get()
        if sel == "auto":
            g = _guess_algo(target)
            if g is None:
                _set_status("Algo nicht erkennbar — bitte manuell wählen.", WARN)
                return
            algos = g if isinstance(g, list) else [g]
        else:
            algos = [sel]
        crack_state.update(stop=False, running=True)
        crack_state.pop("aborted", None)
        try:
            prog.configure(value=0)
        except Exception:
            pass
        _set_status(f"Starte Dictionary-Vergleich ({', '.join(algos)}) …")
        threading.Thread(target=_crack_worker, args=(target, algos, path), daemon=True).start()

    def _stop_crack():
        crack_state["stop"] = True
        crack_state["aborted"] = True

    btn_row = tk.Frame(s3, bg=PANEL)
    btn_row.pack(fill="x", padx=8, pady=(0, 8))
    _button(btn_row, "Crack starten", command=_start_crack, accent=True).pack(side="left")
    _button(btn_row, "Stop", command=_stop_crack).pack(side="left", padx=6)

    # ---- 4. AES-Demo ----------------------------------------------------
    s4 = _section(root, "4 · AES-Demo (Verschlüsselung)")
    s4.pack(fill="x", padx=10, pady=5)
    if _HAS_FERNET:
        _label(s4, "Backend: cryptography.fernet (AES-128-CBC + HMAC) ✔",
               fg=MUTED, font=F_SMALL).pack(fill="x", padx=8, pady=(6, 0))
    else:
        _label(s4, "Backend: Demo-XOR (NICHT sicher!) — nur zur Anschauung, "
                   "für Echtgebrauch 'pip install cryptography'.",
               fg=DANGER, font=F_SMALL).pack(fill="x", padx=8, pady=(6, 0))
    r4 = tk.Frame(s4, bg=PANEL)
    r4.pack(fill="x", padx=8, pady=6)
    _label(r4, "Schlüssel:").pack(side="left")
    aes_key = _entry(r4, width=32)
    aes_key.pack(side="left", padx=6, fill="x", expand=True)

    def _gen_key():
        aes_key.delete(0, "end")
        if _HAS_FERNET:
            aes_key.insert(0, Fernet.generate_key().decode())
        else:
            aes_key.insert(0, "demo-schluessel-123")

    _button(r4, "Key erzeugen", command=_gen_key).pack(side="left")
    _label(s4, "Klartext / Chiffre (Base64):", fg=MUTED, font=F_SMALL).pack(anchor="w", padx=8)
    aes_in = tk.Text(s4, height=3, bg=ENTRY_BG, fg=FG, font=F_SMALL,
                     relief="solid", bd=1, wrap="word")
    aes_in.pack(fill="x", padx=8, pady=4)
    aes_out = tk.Text(s4, height=3, bg=ENTRY_BG, fg=ACCENT2, font=F_SMALL,
                      relief="solid", bd=1, wrap="word")
    aes_out.pack(fill="x", padx=8, pady=(0, 4))
    aes_status = _label(s4, "", font=F_SMALL, fg=MUTED)
    aes_status.pack(fill="x", padx=8, pady=(0, 4))

    def _aes_enc():
        try:
            msg = aes_in.get("1.0", "end-1c").encode("utf-8")
            if _HAS_FERNET:
                f = Fernet(aes_key.get().strip().encode())
                ct = f.encrypt(msg).decode()
            else:
                ct = base64.b64encode(_xor_crypt(msg, aes_key.get().encode())).decode()
            aes_out.delete("1.0", "end")
            aes_out.insert("end", ct)
            aes_status.configure(text="Verschlüsselt.", fg=OK)
        except Exception as e:
            aes_status.configure(text=f"Fehler: {e}", fg=DANGER)

    def _aes_dec():
        try:
            raw = aes_in.get("1.0", "end-1c").strip()
            if _HAS_FERNET:
                f = Fernet(aes_key.get().strip().encode())
                pt = f.decrypt(raw.encode()).decode("utf-8", errors="replace")
            else:
                pt = _xor_crypt(base64.b64decode(raw), aes_key.get().encode()).decode("utf-8", errors="replace")
            aes_out.delete("1.0", "end")
            aes_out.insert("end", pt)
            aes_status.configure(text="Entschlüsselt.", fg=OK)
        except Exception as e:
            aes_status.configure(text=f"Fehler: {e} (falscher Schlüssel/Format?)", fg=DANGER)

    br = tk.Frame(s4, bg=PANEL)
    br.pack(fill="x", padx=8, pady=(0, 8))
    _button(br, "Verschlüsseln", command=_aes_enc, accent=True).pack(side="left")
    _button(br, "Entschlüsseln", command=_aes_dec).pack(side="left", padx=6)

    # ---- 5. Phishing-URL -------------------------------------------------
    s5 = _section(root, "5 · Phishing-URL-Check (Heuristik, lokal)")
    s5.pack(fill="x", padx=10, pady=(5, 10))
    r5 = tk.Frame(s5, bg=PANEL)
    r5.pack(fill="x", padx=8, pady=6)
    _label(r5, "URL:").pack(side="left")
    url_entry = _entry(r5, width=40)
    url_entry.pack(side="left", padx=6, fill="x", expand=True)
    url_entry.insert(0, "https://beispiel.de/login")
    _button(r5, "Prüfen", command=lambda: _do_phish(), accent=True).pack(side="left", padx=4)
    ph_out = _label(s5, "—")
    ph_out.pack(fill="x", padx=8)
    ph_list = tk.Text(s5, height=5, bg=ENTRY_BG, fg=FG, font=F_SMALL,
                      relief="solid", bd=1, wrap="word")
    ph_list.pack(fill="x", padx=8, pady=(2, 8))
    ph_list.configure(state="disabled")

    def _do_phish():
        findings, score, label = _phishing_check(url_entry.get())
        color = OK if score < 25 else (WARN if score < 55 else DANGER)
        ph_out.configure(text=f"Risiko-Score: {score}/100 → {label}", fg=color)
        ph_list.configure(state="normal")
        ph_list.delete("1.0", "end")
        for txt, pts in findings:
            ph_list.insert("end", f"[+{pts}] {txt}\n")
        ph_list.configure(state="disabled")

    url_entry.bind("<Return>", lambda e: _do_phish())
    return root
