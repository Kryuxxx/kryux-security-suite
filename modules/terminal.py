"""Terminal & Logs — eingebautes Live-Terminal mit Whitelist + Schutz.

Vertrag: TITLE + build(parent, ctx) -> tk.Frame.
"""

import queue
import shlex
import subprocess
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

TITLE = "Terminal & Logs"

try:
    from core.theme import COLORS, FONTS  # type: ignore
except Exception:
    COLORS = {}
    FONTS = {}

try:
    from core.utils import run_cmd as _core_run_cmd  # type: ignore
except Exception:
    _core_run_cmd = None

BG = COLORS.get("bg", "#050a08")
PANEL = COLORS.get("panel", "#0a1410")
ENTRY_BG = COLORS.get("entry_bg", "#03110b")
FG = COLORS.get("text", COLORS.get("fg", "#c9ffe2"))
MUTED = COLORS.get("dim", COLORS.get("muted", "#5f7a6e"))
ACCENT = COLORS.get("neon", COLORS.get("accent", "#00ff9c"))
ACCENT2 = COLORS.get("cyan", COLORS.get("accent2", "#00e5ff"))
DANGER = COLORS.get("red", COLORS.get("danger", "#ff3355"))
WARN = COLORS.get("amber", COLORS.get("warn", "#ffb300"))

F_TITLE = FONTS.get("title", FONTS.get("TITLE", ("Consolas", 13, "bold")))
F_DEF = FONTS.get("mono", FONTS.get("NORMAL", ("Consolas", 10)))
F_SMALL = FONTS.get("small", FONTS.get("SMALL", ("Consolas", 9)))

PROMPT = "kryux@suite:~$ "

# Sichere, lesende / informative lokale Befehle (Präfix-Wörter bzw. Phrasen)
WHITELIST_WORDS = {
    "ls", "cat", "ps", "ss", "ip", "ping", "whoami", "id", "uname",
    "df", "free", "uptime", "echo", "pwd", "date", "head", "tail",
    "grep", "wc", "less", "more", "lsb_release", "nmcli", "lsusb",
    "lspci", "hostnamectl", "timedatectl", "netstat", "dig",
    "nslookup", "host", "traceroute", "journalctl", "dmesg", "env",
}
WHITELIST_PHRASES = ("nmap --help", "nmap -h", "nmap -V", "nmap --version")

# Harte Blocks: destruktiv / gefährlich — werden nie ausgeführt
BLOCK_PATTERNS = (
    "rm -rf /", "rm -rf /*", "rm -fr /", ":(){", "mkfs",
    "dd if=", "dd of=/dev", "> /dev/sd", "chmod -r 777 /",
    "chmod -r 777 /*", ": |:", "shutdown", "reboot", "poweroff", "halt",
)


def _is_blocked(cmd: str):
    low = cmd.strip().lower()
    for pat in BLOCK_PATTERNS:
        if pat.lower() in low:
            return pat
    if ":(" in low and "&" in low and "}" in low:
        return ":()-Forkbombe"
    return None


def _is_whitelisted(cmd: str):
    c = cmd.strip()
    if not c:
        return False
    for phrase in WHITELIST_PHRASES:
        if c == phrase or c.startswith(phrase + " "):
            return True
    # nmap: nur help/version erlauben
    if c.split()[0] == "nmap":
        return False
    try:
        parts = shlex.split(c)
    except Exception:
        parts = c.split()
    if not parts:
        return False
    # Pipes: alle Stufen müssen whitelisted sein
    segments = [s.strip() for s in c.split("|")]
    for seg in segments:
        try:
            w0 = (shlex.split(seg) or [""])[0]
        except Exception:
            w0 = seg.split()[0] if seg.split() else ""
        if w0 not in WHITELIST_WORDS:
            return False
    return True


def _run_cmd(argv, timeout=20):
    if _core_run_cmd is not None:
        try:
            return _core_run_cmd(argv, timeout=timeout)
        except TypeError:
            return _core_run_cmd(argv)
        except Exception as e:
            return 1, "", f"Fehler: {e}"
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout nach {timeout}s"
    except FileNotFoundError:
        return 127, "", f"Befehl nicht gefunden: {argv[0]}"
    except Exception as e:
        return 1, "", f"Fehler: {e}"


def build(parent, ctx) -> tk.Frame:
    def _ctx_log(msg):
        try:
            if ctx is not None and hasattr(ctx, "log"):
                ctx.log(msg)
        except Exception:
            pass

    root = tk.Frame(parent, bg=BG)
    root.pack(fill="both", expand=True)

    tk.Label(root, text="💻 Live-Terminal (gefiltert) & System-Logs",
             bg=BG, fg=FG, font=F_TITLE, anchor="w").pack(fill="x", padx=10, pady=(8, 2))
    tk.Label(root, text="Nur sichere lokale Befehle laufen direkt. Gefährliche Muster "
                        "(rm -rf /, Forkbombe, mkfs, dd …) werden blockiert. Sonstige Befehle "
                        "nur mit Haken „Erweitert“.",
             bg=BG, fg=MUTED, font=F_SMALL, anchor="w", justify="left",
             wraplength=900).pack(fill="x", padx=10)

    sec = tk.LabelFrame(root, text="  Terminal  ", bg=PANEL, fg=FG,
                        font=F_DEF, bd=1, relief="solid", labelanchor="nw")
    sec.pack(fill="both", expand=True, padx=10, pady=6)

    log = ScrolledText(sec, bg="#03110b", fg=FG, font=F_DEF,
                       insertbackground=FG, relief="solid", bd=1,
                       wrap="word", state="disabled", height=18)
    log.pack(fill="both", expand=True, padx=8, pady=(8, 4))
    log.tag_config("prompt", foreground=ACCENT)
    log.tag_config("err", foreground=DANGER)
    log.tag_config("info", foreground=MUTED)
    log.tag_config("cmd", foreground=ACCENT2)

    q: queue.Queue = queue.Queue()

    def _append(text, tag=None):
        try:
            log.configure(state="normal")
            log.insert("end", text, tag if tag else "")
            log.see("end")
            log.configure(state="disabled")
        except Exception:
            pass

    def _pump():
        try:
            while True:
                item = q.get_nowait()
                _append(*item)
        except queue.Empty:
            pass
        try:
            root.after(80, _pump)
        except Exception:
            pass

    def _exec(argv):
        rc, out, err = _run_cmd(argv, timeout=20)
        q.put((f"{out}", None))
        if err:
            q.put((f"{err}", "err"))
        q.put((f"[exit {rc}]\n", "info"))

    def _run_command(raw: str):
        raw = raw.strip()
        if not raw:
            return
        _append(PROMPT, "prompt")
        _append(raw + "\n", "cmd")
        _ctx_log(f"terminal: {raw}")
        blocked = _is_blocked(raw)
        if blocked:
            _append(f"⛔ Blockiert (gefährliches Muster: {blocked}). Nicht ausgeführt.\n", "err")
            return
        if raw.startswith("sudo") or raw.split()[0] == "sudo":
            _append("⛔ 'sudo' ist in diesem Terminal deaktiviert.\n", "err")
            return
        if _is_whitelisted(raw):
            try:
                argv = shlex.split(raw)
            except Exception as e:
                _append(f"Parse-Fehler: {e}\n", "err")
                return
            threading.Thread(target=_exec, args=(argv,), daemon=True).start()
            return
        if allow_ext.get():
            _append("⚠ Hinweis: Befehl steht NICHT auf der Whitelist — Ausführung trotzdem (mit Haken erlaubt).\n", "info")
            try:
                argv = shlex.split(raw)
            except Exception as e:
                _append(f"Parse-Fehler: {e}\n", "err")
                return
            threading.Thread(target=_exec, args=(argv,), daemon=True).start()
        else:
            _append("⚠ Nicht auf der Whitelist. Erlaubt z. B.: ls, cat, ps, ss, ip, ping, whoami, id, uname, "
                    "df, free, uptime, nmap --help … — oder Haken „Erweiterte Befehle“ setzen.\n", "info")

    row = tk.Frame(sec, bg=PANEL)
    row.pack(fill="x", padx=8, pady=(0, 4))
    tk.Label(row, text=PROMPT, bg=PANEL, fg=ACCENT, font=F_DEF).pack(side="left")
    entry = tk.Entry(row, bg=ENTRY_BG, fg=FG, insertbackground=FG, font=F_DEF,
                     relief="solid", bd=1)
    entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
    entry.bind("<Return>", lambda e: (_run_command(entry.get()), entry.delete(0, "end")))

    allow_ext = tk.BooleanVar(value=False)
    tk.Checkbutton(row, text="Erweiterte Befehle", variable=allow_ext,
                   bg=PANEL, fg=MUTED, selectcolor=PANEL,
                   activebackground=PANEL, font=F_SMALL).pack(side="left", padx=4)

    brow = tk.Frame(sec, bg=PANEL)
    brow.pack(fill="x", padx=8, pady=(0, 8))

    def _mkbtn(txt, cmd, accent=False):
        return tk.Button(brow, text=txt, command=cmd, font=F_DEF, relief="groove", bd=1,
                         cursor="hand2", bg="#0e2018" if accent else PANEL,
                         fg=ACCENT if accent else FG,
                         activebackground="#0e2018", activeforeground="#ffffff",
                         padx=10, pady=3)

    def _syslogs():
        q.put((PROMPT + "System-Logs (tail)\n", "prompt"))
        for cmd in (["journalctl", "--no-pager", "-n", "60"],
                    ["tail", "-n", "60", "/var/log/syslog"],
                    ["tail", "-n", "60", "/var/log/messages"],
                    ["dmesg", "--ctime", "--level=err,warn"]):
            rc, out, err = _run_cmd(cmd, timeout=10)
            if rc == 0 and out.strip():
                q.put((f"── {' '.join(cmd)} ──\n", "info"))
                q.put((out[-6000:] + "\n", None))
                return
        q.put(("Keine System-Logs lesbar (keine Rechte / kein journald/syslog).\n", "err"))

    def _clear():
        try:
            log.configure(state="normal")
            log.delete("1.0", "end")
            log.configure(state="disabled")
        except Exception:
            pass
        _append("KRYUX Live-Terminal — bereit. Tippe 'whoami' oder 'uptime'.\n", "info")

    _mkbtn("Ausführen", lambda: (_run_command(entry.get()), entry.delete(0, "end")), accent=True).pack(side="left")
    _mkbtn("System-Logs", lambda: threading.Thread(target=_syslogs, daemon=True).start()).pack(side="left", padx=6)
    _mkbtn("Clear", _clear).pack(side="left")

    _append("KRYUX Live-Terminal — bereit. Tippe 'whoami' oder 'uptime'.\n", "info")
    try:
        root.after(80, _pump)
        root.after(150, lambda: entry.focus_set())
    except Exception:
        pass
    return root
