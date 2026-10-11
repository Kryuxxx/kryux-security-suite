"""KRYUX // SECURITY SUITE — core.utils.

Zentrale System-Helfer: alles LIVE via subprocess / os / /proc.
Nur Standardlib. Keine Fake-Daten — bei Fehlern leere Werte + Fehlermeldung.
Deutsche Kommentare nach KRYUX-Standard.
"""

from __future__ import annotations

import getpass
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from typing import Callable


# ---------------------------------------------------------------------------
# Installations-Hinweise für externe Security-Tools (Debian/Ubuntu)
# ---------------------------------------------------------------------------
# KRYUX-Branding: einheitliche Hints, wenn ein Tool fehlt.
INSTALL_HINTS: dict[str, str] = {
    "nmap": "sudo apt install nmap",
    "nikto": "sudo apt install nikto",
    "sqlmap": "sudo apt install sqlmap",
    "msfconsole": "sudo apt install metasploit-framework",
    "ufw": "sudo apt install ufw",
}

# Standard-Logdateien, die tail_log() der Reihe nach prüft
DEFAULT_LOG_PATHS: list[str] = [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/kern.log",
]

# Hinweis-Text, wenn Root-Rechte fehlen
NEEDS_SUDO_HINT: str = (
    "Hinweis [KRYUX]: Für diese Aktion sind Root-Rechte nötig. "
    "Bitte mit 'sudo python3 main.py' starten oder Befehl mit sudo ausführen."
)


# ---------------------------------------------------------------------------
# Tool-Suche
# ---------------------------------------------------------------------------
def which_tool(name: str) -> str | None:
    """Prüft, ob ein externes Tool im PATH vorhanden ist (shutil.which)."""
    try:
        return shutil.which(name)
    except Exception:
        return None


def install_hint(name: str) -> str:
    """Gibt den Installations-Hinweis für ein Tool zurück (Fallback generisch)."""
    try:
        return INSTALL_HINTS.get(name, f"sudo apt install {name}")
    except Exception:
        return f"sudo apt install {name}"


# ---------------------------------------------------------------------------
# Kommando-Ausführung (blockierend)
# ---------------------------------------------------------------------------
def run_cmd(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Führt ein Kommando OHNE shell=True aus, gibt (rc, stdout, stderr) zurück.

    - cmd: Liste, z. B. ["ss", "-tulpn"]
    - timeout: Sekunden bis zum Abbruch
    - Liefert bei Fehlern rc=-1 und Fehlermeldung in err (nie Exception).
    """
    try:
        # Absichtlich ohne shell=True (Schutz vor Shell-Injection)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError as exc:
        # Tool nicht installiert -> Installations-Hinweis anhängen
        hint = INSTALL_HINTS.get(cmd[0] if cmd else "", "")
        msg = f"[KRYUX] Befehl nicht gefunden: {exc}"
        if hint:
            msg += f" — Installation: {hint}"
        return 127, "", msg
    except subprocess.TimeoutExpired:
        return 124, "", f"[KRYUX] Zeitüberschreitung nach {timeout}s: {' '.join(cmd)}"
    except Exception as exc:  # robust: niemals abstürzen
        return -1, "", f"[KRYUX] Fehler bei {' '.join(cmd)}: {exc}"


# ---------------------------------------------------------------------------
# Kommando-Ausführung (streaming, mit Stop-Support)
# ---------------------------------------------------------------------------
class StreamHandle:
    """Steuer-Objekt für run_stream(): erlaubt .stop() zum Abbrechen."""

    def __init__(self) -> None:
        # Stop-Flag für den Lese-Thread
        self._stop_event = threading.Event()
        # Laufender Prozess (wird beim Start gesetzt)
        self.process: subprocess.Popen | None = None
        # Lese-Thread (wird im Thread-Modus gesetzt)
        self.thread: threading.Thread | None = None
        # Returncode nach Abschluss (None solange läuft)
        self.rc: int | None = None

    def stop(self) -> None:
        """Bricht den Stream ab: Flag setzen + Prozess beenden."""
        self._stop_event.set()
        try:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except Exception:
                    try:
                        self.process.kill()
                    except Exception:
                        pass
        except Exception:
            pass

    @property
    def stopped(self) -> bool:
        """True, wenn .stop() aufgerufen wurde."""
        return self._stop_event.is_set()

    def wait(self, timeout: float | None = None) -> int | None:
        """Wartet auf den Thread-Modus und gibt den Returncode zurück."""
        try:
            if self.thread is not None:
                self.thread.join(timeout=timeout)
        except Exception:
            pass
        return self.rc


def _pump_stream(
    handle: StreamHandle,
    cmd: list[str],
    on_line: Callable[[str], None],
    stop_check: Callable[[], bool],
) -> int:
    """Liest einen Popen-Prozess zeilenweise (stdout+stderr gemergt).

    Gibt den Returncode zurück (127 = Tool fehlt, -9 = gestoppt).
    """
    try:
        # Zeilen-gepuffert: bufsize=1 + text=True, ohne shell=True
        handle.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        hint = INSTALL_HINTS.get(cmd[0] if cmd else "", "")
        msg = f"[KRYUX] Befehl nicht gefunden: {' '.join(cmd)}"
        if hint:
            msg += f" — Installation: {hint}"
        try:
            on_line(msg)
        except Exception:
            pass
        return 127
    except Exception as exc:
        try:
            on_line(f"[KRYUX] Stream-Fehler: {exc}")
        except Exception:
            pass
        return -1

    rc = -1
    try:
        assert handle.process.stdout is not None
        for raw in handle.process.stdout:
            # Bei Stop sofort abbrechen
            if stop_check():
                break
            try:
                on_line(raw.rstrip("\n"))
            except Exception:
                # Callback-Fehler dürfen den Stream nicht killen
                pass
        if stop_check():
            try:
                handle.process.terminate()
            except Exception:
                pass
        try:
            rc = handle.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                handle.process.kill()
            except Exception:
                pass
            rc = handle.process.wait()
        # Falls per .stop()/Event abgebrochen, -9 melden
        if stop_check() and rc == 0:
            rc = -9
    except Exception:
        rc = -9 if stop_check() else -1
    finally:
        try:
            if handle.process.stdout:
                handle.process.stdout.close()
        except Exception:
            pass
    return rc


def run_stream(
    cmd: list[str],
    on_line: Callable[[str], None],
    on_done: Callable[[int], None] | None = None,
    stop_event: threading.Event | None = None,
) -> StreamHandle | int:
    """Startet ein Kommando mit zeilenweisen Callbacks (line-buffered).

    Spec-Modus (Thread + Handle):
        run_stream(cmd, on_line, on_done) -> StreamHandle mit .stop()
        - on_line(zeile) für jede Ausgabezeile (ohne Zeilenumbruch).
        - on_done(returncode) am Ende (-1 Fehler, -9 Stop, 127 Tool fehlt).

    Legacy-Modus (blockierend, für bestehende Module):
        run_stream(cmd, on_line, stop_event=ev) -> int (Returncode)
        - Läuft im aufrufenden Thread, stop_event bricht ab (rc=-9).
    """
    handle = StreamHandle()

    def _stop_check() -> bool:
        if handle._stop_event.is_set():
            return True
        try:
            if stop_event is not None and stop_event.is_set():
                return True
        except Exception:
            pass
        return False

    # --- Legacy: blockierend im Aufrufer-Thread, int zurück ---
    if on_done is None and stop_event is not None:
        rc = _pump_stream(handle, cmd, on_line, _stop_check)
        handle.rc = rc
        return rc

    # --- Spec: Hintergrund-Thread, Handle zurück ---
    def _target() -> None:
        rc = _pump_stream(handle, cmd, on_line, _stop_check)
        handle.rc = rc
        if on_done is not None:
            try:
                on_done(rc)
            except Exception:
                pass

    t = threading.Thread(
        target=_target, daemon=True, name=f"kryux-stream-{(cmd[0] if cmd else '?')}"
    )
    handle.thread = t
    t.start()
    return handle


# ---------------------------------------------------------------------------
# System-Statistiken (live aus /proc + shutil + os)
# ---------------------------------------------------------------------------
def _read_proc_stat_cpu() -> tuple[int, int] | None:
    """Liest erste 'cpu '-Zeile aus /proc/stat -> (total, idle)."""
    try:
        with open("/proc/stat", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("cpu "):
                    parts = line.split()
                    nums = [int(x) for x in parts[1:]]
                    if not nums:
                        return None
                    total = sum(nums)
                    # idle = idle + iowait (Feld 4 + 5, falls vorhanden)
                    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
                    return total, idle
    except Exception:
        pass
    return None


def sys_stats() -> dict:
    """Sammelt echte Systemdaten: CPU-%, RAM, Disk, Uptime, Loadavg.

    Gibt immer ein Dict zurück, bei Fehlern stehen 0/''/None drin — nie Fake.
    Enthält Spec-Keys (cpu_percent, ...) plus Kompat-Keys (cpu, ram, ...),
    damit bestehende Dashboard-Ansichten direkt weiterlaufen.
    """
    daten: dict = {
        # --- Spec-Keys ---
        "cpu_percent": 0.0,
        "ram_total_mb": 0,
        "ram_used_mb": 0,
        "ram_percent": 0.0,
        "disk_total_gb": 0.0,
        "disk_used_gb": 0.0,
        "disk_percent": 0.0,
        "uptime_sec": 0.0,
        "uptime_str": "",
        "loadavg": (0.0, 0.0, 0.0),
        # --- Kompat-Keys (Dashboard-Fallback-Format) ---
        "hostname": "",
        "user": "",
        "uptime": "?",
        "load": "?",
        "cpu": 0.0,
        "ram": 0.0,
        "disk": 0.0,
    }

    # --- Hostname + User (für Kompat-Ansicht) ---
    try:
        daten["hostname"] = socket.gethostname()
    except Exception:
        pass
    try:
        daten["user"] = getpass.getuser()
    except Exception:
        daten["user"] = "?"

    # --- CPU-% über zwei Samples aus /proc/stat (ca. 0.15 s Abstand) ---
    try:
        a = _read_proc_stat_cpu()
        time.sleep(0.15)
        b = _read_proc_stat_cpu()
        if a and b:
            total_diff = b[0] - a[0]
            idle_diff = b[1] - a[1]
            if total_diff > 0:
                daten["cpu_percent"] = round((1.0 - idle_diff / total_diff) * 100.0, 1)
                daten["cpu"] = daten["cpu_percent"]
    except Exception:
        pass

    # --- RAM aus /proc/meminfo (kB -> MB) ---
    try:
        meminfo: dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if ":" in line:
                    k, v = line.split(":", 1)
                    m = re.search(r"(\d+)", v)
                    if m:
                        meminfo[k.strip()] = int(m.group(1))
        total_kb = meminfo.get("MemTotal", 0)
        avail_kb = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        if total_kb > 0:
            used_kb = max(0, total_kb - avail_kb)
            daten["ram_total_mb"] = round(total_kb / 1024)
            daten["ram_used_mb"] = round(used_kb / 1024)
            daten["ram_percent"] = round(used_kb / total_kb * 100.0, 1)
            daten["ram"] = daten["ram_percent"]
    except Exception:
        pass

    # --- Disk via shutil.disk_usage("/") ---
    try:
        du = shutil.disk_usage("/")
        daten["disk_total_gb"] = round(du.total / (1024 ** 3), 1)
        daten["disk_used_gb"] = round(du.used / (1024 ** 3), 1)
        if du.total > 0:
            daten["disk_percent"] = round(du.used / du.total * 100.0, 1)
            daten["disk"] = daten["disk_percent"]
    except Exception:
        pass

    # --- Uptime aus /proc/uptime ---
    try:
        with open("/proc/uptime", "r", encoding="utf-8", errors="replace") as fh:
            secs = float(fh.read().strip().split()[0])
            daten["uptime_sec"] = round(secs, 1)
            # Lesbare Form: Xd Xh Xm
            m, s = divmod(int(secs), 60)
            h, m = divmod(m, 60)
            d, h = divmod(h, 24)
            if d > 0:
                daten["uptime_str"] = f"{d}d {h}h {m}m"
            elif h > 0:
                daten["uptime_str"] = f"{h}h {m}m"
            else:
                daten["uptime_str"] = f"{m}m {s}s"
            daten["uptime"] = daten["uptime_str"]
    except Exception:
        pass

    # --- Load Average ---
    try:
        daten["loadavg"] = os.getloadavg()
        try:
            daten["load"] = " ".join(f"{v:.2f}" for v in daten["loadavg"])
        except Exception:
            pass
    except Exception:
        pass

    return daten


# ---------------------------------------------------------------------------
# Netzwerk: Interfaces
# ---------------------------------------------------------------------------
def get_interfaces() -> list[dict]:
    """Liefert echte Interfaces als [{name, ip, mac, state}].

    Primär via 'ip -j addr' (JSON), Fallback 'ip addr' mit Regex-Parsing.
    Enthält zusätzlich die Alias-Keys 'iface'/'addr' für ältere Ansichten.
    Bei Fehler/fehlendem Tool: leere Liste (nie Fake).
    """
    # --- Versuch 1: JSON-Ausgabe (sauber & stabil) ---
    try:
        rc, out, _ = run_cmd(["ip", "-j", "addr"], timeout=10)
        if rc == 0 and out.strip():
            data = json.loads(out)
            result: list[dict] = []
            for iface in data:
                name = str(iface.get("ifname", "?"))
                state = str(iface.get("operstate", "?"))
                mac = str(iface.get("address", "?"))
                # Erste IPv4-Adresse aus addr_info nehmen
                ip = ""
                try:
                    for ai in iface.get("addr_info", []):
                        if ai.get("family") == "inet":
                            ip = str(ai.get("local", ""))
                            break
                    if not ip and iface.get("addr_info"):
                        ip = str(iface["addr_info"][0].get("local", ""))
                except Exception:
                    pass
                result.append(
                    {
                        "name": name,
                        "ip": ip,
                        "mac": mac,
                        "state": state,
                        "iface": name,  # Alias für ältere Ansichten
                        "addr": ip,  # Alias für ältere Ansichten
                    }
                )
            if result:
                return result
    except Exception:
        pass

    # --- Versuch 2 (Fallback): klassisches 'ip addr' parsen ---
    try:
        rc, out, _ = run_cmd(["ip", "addr"], timeout=10)
        if rc != 0 or not out.strip():
            return []
        result = []
        cur: dict | None = None
        for line in out.splitlines():
            # Neue Interface-Zeile: "2: eth0: <FLAGS> ... state UP ..."
            m = re.match(r"^\d+:\s+([^:]+):\s+<([^>]*)>.*state\s+(\S+)", line)
            if m:
                if cur is not None:
                    result.append(cur)
                _nm = m.group(1).strip()
                cur = {
                    "name": _nm,
                    "ip": "",
                    "mac": "",
                    "state": m.group(3).strip(),
                    "iface": _nm,
                    "addr": "",
                }
                continue
            if cur is None:
                continue
            # MAC-Zeile: "link/ether aa:bb:cc:dd:ee:ff ..."
            m_mac = re.search(r"link/\S+\s+([0-9a-fA-F:]{11,})", line)
            if m_mac and not cur["mac"]:
                cur["mac"] = m_mac.group(1)
            # IPv4-Zeile: "inet 192.168.1.10/24 ..."
            m_ip = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m_ip and not cur["ip"]:
                cur["ip"] = m_ip.group(1)
                cur["addr"] = m_ip.group(1)
        if cur is not None:
            result.append(cur)
        return result
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Netzwerk: offene Ports + Verbindungen (live via ss)
# ---------------------------------------------------------------------------
def get_open_ports() -> list[dict]:
    """Parst 'ss -tulpn' -> [{proto, local, process}]. Echte Live-Daten."""
    try:
        rc, out, _ = run_cmd(["ss", "-tulpn"], timeout=10)
        if rc != 0 or not out.strip():
            return []
        ports: list[dict] = []
        lines = out.splitlines()
        # Kopfzeile überspringen ("Netid State Recv-Q ...")
        for line in lines[1:]:
            if not line.strip():
                continue
            # Spalten per Whitespace trennen (ss-Tabelle ist stabil genug)
            cols = line.split()
            if len(cols) < 5:
                continue
            proto = cols[0]
            local = cols[4]
            # Prozessname aus users:(("...",pid=..,fd=..)) extrahieren
            proc = ""
            m = re.search(r'\(\("([^"]+)"', line)
            if m:
                proc = m.group(1)
            ports.append({"proto": proto, "local": local, "process": proc})
        return ports
    except Exception:
        return []


def get_connections(count: int = 50) -> list[dict]:
    """Parst 'ss -tunp' -> Liste mit max. count Einträgen (Live-Daten)."""
    try:
        rc, out, _ = run_cmd(["ss", "-tunp"], timeout=10)
        if rc != 0 or not out.strip():
            return []
        conns: list[dict] = []
        lines = out.splitlines()
        for line in lines[1:]:
            if len(conns) >= count:
                break
            if not line.strip():
                continue
            cols = line.split()
            if len(cols) < 5:
                continue
            proto = cols[0]
            state = cols[1] if len(cols) > 1 else ""
            local = cols[4] if len(cols) > 4 else ""
            peer = cols[5] if len(cols) > 5 else ""
            proc = ""
            m = re.search(r'\(\("([^"]+)"', line)
            if m:
                proc = m.group(1)
            conns.append(
                {"proto": proto, "state": state, "local": local, "peer": peer, "process": proc}
            )
        return conns
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Netzwerk-Durchsatz (Summe aus /proc/net/dev, ohne lo)
# ---------------------------------------------------------------------------
def net_io() -> dict:
    """Summiert RX/TX-Bytes aller Interfaces außer 'lo' aus /proc/net/dev."""
    daten = {"rx": 0, "tx": 0}
    try:
        with open("/proc/net/dev", "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        # Erste 2 Zeilen sind Kopfzeilen
        for line in lines[2:]:
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            name = name.strip()
            if name == "lo" or not name:
                continue
            cols = rest.split()
            # Spalte 0 = RX bytes, Spalte 8 = TX bytes
            if len(cols) >= 9:
                try:
                    daten["rx"] += int(cols[0])
                    daten["tx"] += int(cols[8])
                except ValueError:
                    continue
    except Exception:
        pass
    return daten


# ---------------------------------------------------------------------------
# Log-Datei lesen
# ---------------------------------------------------------------------------
def tail_log(path: str | int | None = None, n: int = 50) -> str:
    """Gibt die letzten n Zeilen einer Logdatei zurück (echte Dateiinhalte).

    - Wenn path (str) existiert, wird genau diese Datei gelesen.
    - Sonst wird in DEFAULT_LOG_PATHS die erste existierende Datei genommen.
    - Kompat: tail_log(25) — int als erstes Argument wird als n gewertet.
    - Bei fehlenden Rechten / fehlender Datei: erklärender KRYUX-Text (kein Fake).
    """
    # Kompat: positionsaufruf tail_log(n) mit int
    if isinstance(path, int):
        n = path
        path = None
    kandidat = ""
    try:
        # 1) Expliziter Pfad, falls vorhanden
        if isinstance(path, str) and path and os.path.isfile(path):
            kandidat = path
        else:
            # 2) Standard-Liste durchgehen, erste existierende nehmen
            for p in DEFAULT_LOG_PATHS:
                try:
                    if os.path.isfile(p):
                        kandidat = p
                        break
                except Exception:
                    continue
        if not kandidat:
            return "[KRYUX] Keine Logdatei gefunden (geprüft: {})".format(
                ", ".join(DEFAULT_LOG_PATHS)
            )
        # 3) Letzte n Zeilen lesen
        try:
            with open(kandidat, "r", encoding="utf-8", errors="replace") as fh:
                zeilen = fh.readlines()
        except PermissionError:
            return f"[KRYUX] Keine Leserechte für {kandidat}. {NEEDS_SUDO_HINT}"
        except Exception as exc:
            return f"[KRYUX] Log kann nicht gelesen werden ({kandidat}): {exc}"
        auswahl = zeilen[-n:] if n > 0 else zeilen
        kopf = f"[KRYUX] Quelle: {kandidat} (letzte {len(auswahl)} Zeilen)\n"
        return kopf + "".join(auswahl)
    except Exception as exc:
        return f"[KRYUX] tail_log-Fehler: {exc}"


# ---------------------------------------------------------------------------
# Root-Rechte
# ---------------------------------------------------------------------------
def is_root() -> bool:
    """True, wenn das Programm als Root läuft (geteuid()==0)."""
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        # Kein Unix (z. B. Windows): kein Root-Konzept
        return False
    except Exception:
        return False


def needs_sudo() -> str:
    """Gibt den KRYUX-Hinweis-String für fehlende Root-Rechte zurück."""
    if is_root():
        return "[KRYUX] Root-Rechte aktiv — alle Module verfügbar."
    return NEEDS_SUDO_HINT
