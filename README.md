# scamsleuth
Whether you’re in incident response, corporate IT, or just helping friends fight spam, ScamSleuth turns reconnaissance from minutes to milliseconds.

<img width="1024" height="1024" alt="noscam" src="https://github.com/user-attachments/assets/63609446-0c3e-4f29-a3db-f0cb4ac37c1a" />





## ✨ Features

| Category | What you get |
|----------|--------------|
| **Phone OSINT** | Region, carrier, line-type, local time-zones + crowdsourced spam counts |
| **E-mail Intel** | Syntax validation, live MX/SPF/DMARC/TXT checks, breach sightings |
| **IP / Domain** | Instant DNS resolve, GeoIP (ipinfo), bogon/private-net detection |
| **Risk Score** | 0-10 heuristic so you can triage lightning-fast |
| **Dark-Mode GUI** | Single-file Tkinter app — no Electron, no browser lag |
| **JSON Export** | Save a full investigation log in one click |

---

## 🚀 Quick start

### 1 · Clone

```bash
git clone https://github.com/yourname/ScamSleuth.git
cd ScamSleuth

2 · Install the deps

Choose one of the supported methods:
Method	Commands	When to pick it
Virtual env (recommended)	bash<br>python3 -m venv .venv<br>source .venv/bin/activate<br>pip install -U pip<br>pip install -r requirements.txt	Keeps everything isolated
Apt packages (Debian/Kali)	bash<br>sudo apt update && sudo apt install python3-{phonenumbers,email-validator,dnspython,tldextract,requests}	You prefer system packages
pipx	bash<br>sudo apt install pipx<br>pipx runpip scamsleuth -r requirements.txt	One-click sandbox install
3 · Run

python scamsleuth.py

🛠 Usage

    Pick Phone, Email, or IP/Domain tab.

    Enter the target & hit Lookup.

    Read the live log or hit 💾 Export JSON for a report file.

    Tip: Enable/disable remote look-ups in config.py (set ENABLE_REMOTE_LOOKUPS = False for 100 % offline).

📋 Sample output

{
  "international": "+1 202-555-0189",
  "region": "District of Columbia",
  "carrier": "Verizon Wireless",
  "timezones": ["America/New_York"],
  "type": "MOBILE",
  "spam_reports": 7,
  "spam_category": "Robocall"
}
🔥 Scam Score: 7/10
----------------------------------------------------------------

🔒 Privacy & ethics

ScamSleuth is designed for defensive investigations only.
Always respect privacy laws (TCPA, GDPR, etc.). Never use personal data without consent.
📅 Roadmap

Bulk CSV import/export

CLI-only mode (scamsleuth --phone +12025550189)

CVE-aware mail server analysis

    Plug-in SDK (write your own enrichment modules)

🤝 Contributing

    Fork → Feature → PR.

    Follow Conventional Commits (feat: …, fix: …).

    Run flake8 + black before pushing.

    Open an issue for large changes first.

📝 License

MIT © 2025 NeoDay — free as in freedom.
See LICENSE for details.
🙏 Acknowledgements

    phonenumbers for number parsing

    email-validator for e-mail sanity checks

    ipinfo.io for the free GeoIP tier

    Everyone fighting spam one lookup at a time 💚

