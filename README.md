# ⬢ KRYUX // SECURITY SUITE  v2.0

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)]

Das ultimative CyberSecurity-Programm mit moderner Hacker-GUI (Dark-Neon, Cards, Live-Charts) — **live, keine Fake-Alerts**.
Alle Daten kommen echt vom System (`ss`, `ip`, `ufw`, `nmap`, `nikto`, `sqlmap`, `msfconsole`, `/proc`, Logs).

> **Legal & ethisch:** Nur eigene Systeme / eigenes Labor mit Erlaubnis testen!

## Start

```bash
cd Kryux_Security_Suite
chmod +x run.sh
./run.sh
# oder:
python3 main.py
# Für Firewall & manche Scans mit Root:
sudo python3 main.py
```

Voraussetzung: Python 3.10+ (getestet 3.14) + tkinter (meist vorinstalliert).
Keine Pflicht-Abhängigkeiten. Optional: `scapy`, `cryptography`, `psutil`.

Fehlende Tools nachinstallieren (Debian/Ubuntu/Kali):
```bash
sudo apt install nmap nikto sqlmap ufw gobuster ffuf hydra john hashcat tshark yara binwalk theharvester amass wpscan whatweb dirb crunch macchanger netdiscover tcpdump hping3 steghide bulk-extractor lynis rkhunter
# Metasploit (groß):
sudo apt install metasploit-framework
```

> **Ubuntu-Problem (z.B. `nikto` nicht gefunden)?** Kein Problem: Das Modul
> **Setup & Install** erkennt dein OS und zeigt pro Tool alle Wege —
> Kali-apt, Ubuntu-apt, Snap, Go (`go install …`), Gem (`gem install wpscan`),
> Pipx, Git-Clone und Docker — mit Copy-Buttons. Auch jede Tool-Karte im
> **Kali Arsenal** hat einen ⚙-Install-Button mit denselben Alternativen.

## Bedienung / Scrollen

- **Alles scrollt:** Sidebar + jede Modul-Seite haben eine Neon-Scrollbar + Mausrad-Support (Linux Button-4/5, Windows/macOS Wheel). Maus über den Bereich bewegen und scrollen.
- Oben: Tool-Status (`●` installiert / `○` fehlt). Unten: Status-Log.

## Features (12 Module)

| # | Modul | Was es live kann |
|---|-------|------------------|
| 1 | **SOC Dashboard** | KPI-Karten + **Live-Charts** (CPU/RAM/Netz als Canvas-Graphen), Risiko-Kachel aus echten Ports, Interfaces/Ports/Verbindungen, Log-Vorschau mit Suche, externe IP |
| 2 | **Nmap Scanner** | Echter `nmap`-Aufruf mit Profilen (Quick/Standard/Full/Aggressiv/UDP), Timing T0–T5, `-Pn -sV -O -sC`, Live-Output + Risiko-Auswertung (telnet/445/RDP warnen). Fallback: eingebauter TCP-Connect-Scan wenn nmap fehlt |
| 3 | **Web & Nikto Scanner** | `nikto -h` live, Security-Header-Check, SSL-Ablauf-Check (openssl), robots.txt/sitemap-Analyse |
| 4 | **SQLMap** | Target + Level/Risk, `--batch --forms --crawl --dbs`, Consent-Pflicht, Live-Output + injectable-Auswertung |
| 5 | **Metasploit** | `search`, Payload-Builder (LHOST auto, msfvenom-Befehl zum Kopieren), `msfconsole -x` Live-Ausführung, Button für interaktives Terminal |
| 6 | **Vuln Scanner** | Offene-Ports-Risiko-Mapping, `apt upgradable`, UFW-Status, SSH-Perms, world-writable/SUID-Fundstellen, Score 0–100 + TXT-Report |
| 7 | **Firewall Manager** | Backend-Auto-Erkennung (ufw/firewalld/iptables), Regeln-Tabelle, allow/deny hinzufügen (Port/Proto/IP), Löschen per Nummer, enable/disable, Logging-Level — via pkexec/sudo, ehrliche Fehler statt Fake |
| 8 | **Forensik** | Prozesse (`ps -aux`, Miner/Keylog-Muster markiert), Datei-Hashes (MD5/SHA256 + Vergleich), Metadaten (JPEG/PDF), Log-Analyse (Brute-Force pro IP), Timeline (neueste 100 Dateien) |
| 9 | **Netzwerk Tools** | Ping-Sweep, Traceroute, DNS-Lookup, Banner-Grabber, Header-Check |
| 10 | **Passwort & Krypto** | Stärke-Check (Entropie), Hash-Generator (6 Algos), Dictionary-Cracker (eigener Hash + Wortliste), Fernet/XOR-Demo, Phishing-URL-Score |
| 11 | **Terminal & Logs** | Eingebautes Terminal mit Whitelist + Blockliste (`rm -rf /` etc. geblockt), System-Logs |
| 12 | **Extras & Härtung** | WiFi (`nmcli`), USB (`lsusb`), Backup-Vergleich (SHA256-Stichprobe), SSH-Audit + Härtungs-Tipps aus echten Werten |
| 13 | **Kali Arsenal** (39 kuratiert + **324 Katalog-Tools**) | 7 Tabs wie bisher + 8. Tab „Alle Tools 🔍“ (Suche + Kategorie-Filter über alle Kali-Tools, Live-Runner, ⚙-Install-Dialog) |
| 14 | **Setup & Install** (NEU) | OS-Erkennung, 24 Kern-Tools mit Status, Anleitungen mit Ubuntu-Alternativen, APT-Direktinstall |
| 15 | **Einsatz & Report** (NEU) | Auftrag/Scope, Findings mit Schweregrad, Checkliste, HTML-Report-Export mit Branding, Save/Load als JSON |

## Parameter-Beispiele

- **Nmap:** Target `127.0.0.1`, Ports `1-1024`, Profil `Standard -sV`, Timing `T4`, Zusatz `-Pn`
- **Nikto:** URL `http://localhost/DVWA/` (nur eigenes Labor!)
- **SQLMap:** URL `http://localhost:8080/index.php?id=1`, Level 1, Risk 1, Consent-Haken setzen
- **Firewall:** Action `allow`, Proto `tcp`, Port `22`, From `192.168.1.0/24`
- **Forensik-Timeline:** Ordner `/home/kryux` wählen (Tiefe ≤4, max 100 Einträge)

## Projektstruktur

```
Kryux_Security_Suite/
├── main.py            # Sidebar-GUI, KRYUX-Branding, Modul-Loader
├── run.sh             # Starter
├── requirements.txt   # nur optionale Pakete
├── core/
│   ├── utils.py       # run_cmd/run_stream/sys_stats/interfaces/ports/logs
│   └── theme.py       # COLORS/FONTS/BANNER/apply_dark/Widgets
└── modules/
    ├── dashboard.py, nmap_scanner.py, web_scanner.py, sqlmap_runner.py
    ├── metasploit.py, vuln_scanner.py, firewall_manager.py, forensics.py
    └── network_tools.py, password_crypto.py, terminal.py, extras.py
```

Jedes Modul: `TITLE="..."` + `def build(parent, ctx) -> tk.Frame`, langlaufende Scans in Threads mit Stop-Button.

## Screenshots / Bedienung

1. Links Modul wählen, rechts arbeitet das Panel.
2. Oben: Tool-Status (`●` installiert / `○` fehlt).
3. Unten: Status-Log mit Zeitstempel.
4. Alle Langläufer haben Stop + Export (txt).

Viel Erfolg beim defensiven Lernen — **KRYUX**.

## Lizenz & Security

- Lizenz: [MIT](LICENSE)
- [Security Policy](SECURITY.md) – nur autorisierte Nutzung, Schwachstellen bitte privat melden.
