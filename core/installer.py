"""KRYUX — Install-Manager: Installationswege für Security-Tools.

Problem: Auf Ubuntu fehlen viele Kali-Pakete (z.B. `nikto`).
Lösung: pro Tool mehrere Wege (Kali-apt, Ubuntu-apt, Snap, Go, Gem/Pip,
Git, Docker) + Dialog mit Copy-Buttons. Alles nur Anleitungen, live prüfbar.
"""
from __future__ import annotations
import os
import tkinter as tk

from core.theme import COLORS, FONTS

# ---------------------------------------------------------------------------
# Tool-Installationsdatenbank: tool -> Liste von (Label, Befehl)
# ---------------------------------------------------------------------------
INSTALL_DB: dict[str, list[tuple[str, str]]] = {
    "nikto": [
        ("Kali: apt", "sudo apt update && sudo apt install -y nikto"),
        ("Ubuntu: Git (empfohlen)",
         "sudo apt install -y perl libwhisker2-perl libwww-perl libnet-ssleay-perl git && "
         "git clone https://github.com/sullo/nikto ~/tools/nikto && "
         "cd ~/tools/nikto/program && perl nikto.pl -h https://ZIEL"),
        ("Ubuntu: Docker", "docker run --rm sullo/nikto -h https://ZIEL"),
    ],
    "sqlmap": [
        ("Kali/Ubuntu: apt", "sudo apt update && sudo apt install -y sqlmap"),
        ("Pipx (aktuell)", "sudo apt install -y pipx && pipx install sqlmap && sqlmap --version"),
        ("Git (immer aktuell)",
         "git clone --depth 1 https://github.com/sqlmapproject/sqlmap ~/tools/sqlmap && "
         "python3 ~/tools/sqlmap/sqlmap.py -h"),
    ],
    "wpscan": [
        ("Ruby-Gem (empfohlen)", "sudo apt install -y ruby ruby-dev build-essential && sudo gem install wpscan && wpscan --version"),
        ("Docker", "docker run --rm wpscanteam/wpscan --url https://ZIEL --enumerate vp"),
    ],
    "gobuster": [
        ("Go (empfohlen)", "go install github.com/OJ/gobuster/v3@latest && export PATH=$PATH:~/go/bin && gobuster version"),
        ("Kali: apt", "sudo apt install -y gobuster"),
        ("Ubuntu 24.04+: apt", "sudo apt update && sudo apt install -y gobuster"),
    ],
    "ffuf": [
        ("Go (empfohlen)", "go install github.com/ffuf/ffuf/v2@latest && export PATH=$PATH:~/go/bin"),
        ("Kali: apt", "sudo apt install -y ffuf"),
    ],
    "amass": [
        ("Go (empfohlen)", "go install -v github.com/owasp-amass/amass/v4/...@master && export PATH=$PATH:~/go/bin"),
        ("Kali: apt", "sudo apt install -y amass"),
    ],
    "subfinder": [
        ("Go (empfohlen)", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && export PATH=$PATH:~/go/bin"),
        ("Kali: apt", "sudo apt install -y subfinder"),
    ],
    "katana": [
        ("Go (empfohlen)", "go install github.com/projectdiscovery/katana/cmd/katana@latest && export PATH=$PATH:~/go/bin"),
    ],
    "httpx": [
        ("Go (empfohlen)", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && export PATH=$PATH:~/go/bin"),
    ],
    "nuclei": [
        ("Go (empfohlen)", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && export PATH=$PATH:~/go/bin && nuclei -update-templates"),
    ],
    "theHarvester": [
        ("Kali: apt", "sudo apt install -y theharvester"),
        ("Git (empfohlen)", "git clone https://github.com/laramies/theHarvester ~/tools/theHarvester && "
         "cd ~/tools/theHarvester && pip install -r requirements.txt && python3 theHarvester.py -h"),
    ],
    "sherlock": [
        ("Pipx (empfohlen)", "sudo apt install -y pipx && pipx install sherlock-project && sherlock --version"),
    ],
    "spiderfoot": [
        ("Git", "git clone https://github.com/smicallef/spiderfoot ~/tools/spiderfoot && "
         "cd ~/tools/spiderfoot && pip install -r requirements.txt && python3 ./sf.py -h"),
    ],
    "hydra": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y hydra hydra-gtk"),
    ],
    "john": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y john"),
        ("Jumbo (Git, mehr Formate)", "git clone https://github.com/openwall/john ~/tools/john && "
         "cd ~/tools/john/src && ./configure && make -s clean && make -sj4 && ../run/john --list=formats | head"),
    ],
    "hashcat": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y hashcat && hashcat --version"),
    ],
    "medusa": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y medusa"),
    ],
    "crunch": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y crunch"),
    ],
    "nmap": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y nmap && nmap --version"),
        ("Snap", "sudo snap install nmap"),
    ],
    "tshark": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y tshark && "
         "sudo usermod -aG wireshark $USER  # danach neu einloggen für Capture ohne Root"),
    ],
    "wireshark": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y wireshark"),
    ],
    "tcpdump": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y tcpdump"),
    ],
    "netdiscover": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y netdiscover"),
    ],
    "hping3": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y hping3"),
    ],
    "macchanger": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y macchanger"),
    ],
    "aircrack-ng": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y aircrack-ng"),
    ],
    "wifite": [
        ("Kali: apt", "sudo apt install -y wifite"),
        ("Ubuntu: Git", "git clone https://github.com/kimocoder/wifite2 ~/tools/wifite2 && "
         "cd ~/tools/wifite2 && sudo python3 Wifite.py --help"),
    ],
    "kismet": [
        ("Kismet-Repo (Ubuntu)", "wget -O - https://www.kismetwireless.net/repos/kismet-release.gpg.key | gpg --dearmor | "
         "sudo tee /usr/share/keyrings/kismet-archive-keyring.gpg >/dev/null && "
         "echo 'deb [signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] https://www.kismetwireless.net/repos/apt/release/$(lsb_release -sc) ./' | "
         "sudo tee /etc/apt/sources.list.d/kismet.list && sudo apt update && sudo apt install -y kismet"),
        ("Kali: apt", "sudo apt install -y kismet"),
    ],
    "yara": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y yara"),
    ],
    "binwalk": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y binwalk"),
    ],
    "steghide": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y steghide"),
    ],
    "bulk-extractor": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y bulk-extractor"),
    ],
    "exploitdb": [
        ("Kali: apt", "sudo apt install -y exploitdb && searchsploit -u"),
        ("Ubuntu: Git", "git clone https://github.com/offensive-security/exploitdb /opt/exploitdb && "
         "sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && searchsploit -u"),
    ],
    "metasploit-framework": [
        ("Kali: apt", "sudo apt install -y metasploit-framework && msfdb init"),
        ("Ubuntu: Installer",
         "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && "
         "chmod +x msfinstall && sudo ./msfinstall && msfdb init"),
    ],
    "burpsuite": [
        ("Kali: apt", "sudo apt install -y burpsuite"),
        ("Manuell (alle Systeme)", "Download von https://portswigger.net/burp/releases laden und installieren"),
    ],
    "responder": [
        ("Kali: apt", "sudo apt install -y responder"),
        ("Ubuntu: Git", "git clone https://github.com/lgandx/Responder ~/tools/Responder && "
         "cd ~/tools/Responder && sudo python3 Responder.py -h"),
    ],
    "impacket": [
        ("Pipx (empfohlen)", "sudo apt install -y pipx && pipx install impacket && impacket-smbserver -h"),
        ("Kali: apt", "sudo apt install -y impacket-scripts"),
    ],
    "bloodhound": [
        ("Kali: apt", "sudo apt install -y bloodhound"),
        ("Docker (alle Systeme)", "docker run -d --name neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/blutgeld neo4j:4.4 && "
         "echo 'BloodHound-Release von https://github.com/BloodHoundAD/BloodHound/releases laden'"),
    ],
    "bettercap": [
        ("Go (empfohlen)", "sudo apt install -y libpcap-dev libusb-1.0-0-dev && "
         "go install github.com/bettercap/bettercap@latest && export PATH=$PATH:~/go/bin"),
        ("Kali: apt", "sudo apt install -y bettercap"),
    ],
    "lynis": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y lynis"),
    ],
    "rkhunter": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y rkhunter && sudo rkhunter --update"),
    ],
    "whatweb": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y whatweb"),
        ("Git", "git clone https://github.com/urbanadventurer/whatweb ~/tools/whatweb && ~/tools/whatweb/whatweb --version"),
    ],
    "dirb": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y dirb"),
    ],
    "sublist3r": [
        ("Kali: apt", "sudo apt install -y sublist3r"),
        ("Git", "git clone https://github.com/aboul3la/Sublist3r ~/tools/Sublist3r && "
         "cd ~/tools/Sublist3r && pip install -r requirements.txt && python3 sublist3r.py -h"),
    ],
    "enum4linux": [
        ("Ubuntu/Kali: apt", "sudo apt update && sudo apt install -y enum4linux smbclient"),
    ],
    "openvas": [
        ("Kali: apt (GVM)", "sudo apt install -y gvm && sudo gvm-setup && sudo gvm-start"),
        ("Hinweis Ubuntu", "GVM auf Ubuntu nur via Docker/Quellen sinnvoll — siehe https://greenbone.github.io/docs/"),
    ],
}


def detect_os() -> str:
    """Erkennt Distribution (Ubuntu/Kali/Debian/…) aus /etc/os-release."""
    try:
        with open("/etc/os-release", encoding="utf-8", errors="replace") as f:
            data = f.read().lower()
        for key in ("kali", "ubuntu", "debian", "arch", "fedora", "parrot"):
            if key in data:
                return key
    except Exception:
        pass
    return "linux"


def get_install_options(tool: str) -> list[tuple[str, str]]:
    """Installationswege für ein Tool (Label, Befehl). Mit generischem Fallback."""
    opts = list(INSTALL_DB.get(tool, []))
    if not opts:
        opts = [
            ("Kali: apt", f"sudo apt update && sudo apt install -y {tool}"),
            ("Ubuntu: apt versuchen", f"sudo apt update && sudo apt install -y {tool}  # fehlt ggf. in Ubuntu-Repos → Git/Docker prüfen"),
        ]
    return opts


def show_install_dialog(parent: tk.Widget, tool: str) -> None:
    """Dialog mit allen Installationswegen + Copy-Buttons (KRYUX-Style)."""
    win = tk.Toplevel(parent)
    win.title(f"KRYUX — Install: {tool}")
    win.geometry("720x420")
    try:
        win.configure(bg=COLORS["bg"])
    except Exception:
        pass
    osinfo = detect_os()
    tk.Label(win, text=f"⬢ {tool} installieren  (Erkannt: {osinfo})",
             bg=COLORS["bg"], fg=COLORS["neon"], font=FONTS["title"]).pack(
                 anchor="w", padx=12, pady=(10, 2))
    tk.Label(win, text="Warum schlägt 'apt install' auf Ubuntu fehl? Ubuntu-Repos enthalten keine Kali-Pakete "
                       "(z.B. nikto, wpscan) — nutze die Alternativen unten.",
             bg=COLORS["bg"], fg=COLORS["dim"], font=FONTS["small"],
             wraplength=680, justify="left").pack(anchor="w", padx=12, pady=(0, 8))

    frame = tk.Frame(win, bg=COLORS["bg"])
    frame.pack(fill="both", expand=True, padx=12, pady=4)
    txt = tk.Text(frame, bg="#03110b", fg=COLORS["text"], font=FONTS["mono"],
                  wrap="word", height=14)
    txt.pack(side="left", fill="both", expand=True)
    sb = tk.Scrollbar(frame, command=txt.yview)
    sb.pack(side="right", fill="y")
    txt.configure(yscrollcommand=sb.set)

    cmds: list[str] = []
    for label, cmd in get_install_options(tool):
        txt.insert("end", f"▸ {label}\n", "lbl")
        txt.insert("end", f"  {cmd}\n\n")
        cmds.append(cmd)
    try:
        txt.tag_config("lbl", foreground=COLORS["cyan"])
    except Exception:
        pass
    txt.configure(state="disabled")

    btns = tk.Frame(win, bg=COLORS["bg"])
    btns.pack(fill="x", padx=12, pady=8)

    def copy_all():
        try:
            win.clipboard_clear()
            win.clipboard_append("\n".join(cmds))
        except Exception:
            pass

    tk.Button(btns, text="⧉ Alle Befehle kopieren", command=copy_all,
              bg=COLORS["panel"], fg=COLORS["neon"], font=FONTS["mono"],
              relief="groove").pack(side="left")
    tk.Button(btns, text="Schließen", command=win.destroy,
              bg=COLORS["panel"], fg=COLORS["text"], font=FONTS["mono"],
              relief="groove").pack(side="right")
