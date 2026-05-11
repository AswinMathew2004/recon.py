<div align="center">

# 🔎 recon.py

### The most powerful all-in-one OSINT lookup tool for Kali Linux

**Zero dependencies.** Pure Python stdlib. Just clone and run.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Stdlib only](https://img.shields.io/badge/Dependencies-ZERO-success)](https://docs.python.org/3/library/)
[![Platform](https://img.shields.io/badge/Platform-Kali_Linux-557C94?logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Made by Aswin Mathew](https://img.shields.io/badge/Made_by-Aswin_Mathew-purple)](https://aswinmathew.xyz)

[Features](#-features) • [Install](#-installation) • [Usage](#-usage) • [Demo](#-demo) • [How it works](#-how-it-works)

</div>

---

## ✨ Features — six full OSINT modules, A to Z

| Flag | Module | What it does |
|---|---|---|
| `-u` | **Username** | Concurrent scan across **80+ sites**: GitHub, GitLab, X/Twitter, Instagram, TikTok, Reddit, YouTube, Twitch, Medium, Stack Overflow, Steam, Roblox, SoundCloud, Spotify, Telegram, Keybase, Replit, NPM, PyPI, Dribbble, Behance, ArtStation, Patreon, Bluesky, Threads, Mastodon, HackerRank, LeetCode, TryHackMe, MyAnimeList, AniList, and many more |
| `-e` | **Email** | Format validation • **MX record check** (via Google DoH) • SPF + DMARC sniff • Gravatar avatar + profile JSON • **Disposable email detection** (50+ domains) • Free vs business classification • Auto-scans local-part as username • Breach lookup links (HIBP, DeHashed, IntelX, LeakCheck) |
| `-p` | **Phone** | **Embedded ITU E.164 database** for 200+ countries (zero deps!) • Country, region, ISO code, timezone, expected length • **Indian carrier hints by prefix series** • **US area code → state mapping** (350+ NPAs) • Truecaller / WhatsApp / Telegram / Sync.me / WhitePages lookup links |
| `-n` | **Name** | 18 pre-built Google / Bing / DuckDuckGo / Yandex dorks (LinkedIn, FB, X, GitHub, IG, Reddit, YouTube, PDFs, resumes, court records, images) • Auto-generates 10+ username permutations (`firstlast`, `first.last`, `flast`, `lf`, `f.last`, etc.) and runs the full username scan on each |
| `-d` | **Domain** 🆕 | **WHOIS** over raw socket (port 43, follows referrals) • Full DNS: A, AAAA, MX, NS, TXT, CNAME, SOA • **SSL certificate** info (issuer, validity, SANs) • HTTP headers + **tech stack fingerprint** (WordPress, React, Cloudflare, etc.) • robots.txt + sitemap.xml • **Subdomain enumeration via crt.sh** (Certificate Transparency) • Wayback Machine snapshot |
| `-i` | **IP** 🆕 | Reverse DNS • Full geolocation (country, region, city, ZIP, coordinates, timezone) • ISP / Organization / **ASN** • Mobile / proxy / VPN / hosting flags • IP WHOIS • **Quick port scan** of 12 common services |
| `-o` | **JSON export** | Save the entire structured report to JSON for piping into Maltego, Spiderfoot, or your own pipelines |

### Why it's "most powerful"

- 🧬 **Zero pip installs** — no `requests`, no `phonenumbers`, no `dnspython`. Built entirely on `urllib`, `socket`, `ssl`, `concurrent.futures` from the Python standard library. Runs on any fresh Linux/Kali install with just `python3`.
- ⚡ **Threaded** — 25 worker threads scan 80+ sites in seconds
- 🌍 **Embedded ITU phone DB** — country codes, timezones, ISO codes for the whole world, all in-code
- 🔍 **Two new modules** — `-d` and `-i` make this a full red-team recon kit, not just a username searcher
- 🎯 **No API keys ever required** — uses Google's free DoH for DNS, crt.sh for subdomains, ip-api.com for geo

---

## 📦 Installation

```bash
# 1. Clone
git clone https://github.com/AswinMathew2004/recon.py.git
cd recon

# 2. Make executable (optional)
chmod +x recon.py

# 3. Run — that's it. No pip, no venv, no dependencies.
python3 recon.py -u octocat
```

### Make it a global command (optional)

```bash
sudo ln -s "$(pwd)/recon.py" /usr/local/bin/recon
recon -u johndoe
```

---

## 🚀 Usage

```bash
# Single-target lookups
python3 recon.py -u johndoe                  # 80+ social/dev/gaming sites
python3 recon.py -e john@example.com         # email intelligence
python3 recon.py -p +14155552671             # US phone → state lookup
python3 recon.py -p +919876543210            # India phone → carrier hints
python3 recon.py -n "John Doe"               # name dorks + permutation scan
python3 recon.py -d example.com              # full domain intelligence
python3 recon.py -i 8.8.8.8                  # IP geolocation + WHOIS + ports

# Combine everything for full target profile
python3 recon.py -u johndoe -e john@x.com -p +91... -n "John Doe" -d x.com -o report.json
```

### All flags

```
-u, --username  Username (80+ sites)
-e, --email     Email investigation
-p, --phone     Phone with +country code
-n, --name      Full name
-d, --domain    Domain WHOIS/DNS/SSL/subdomains
-i, --ip        IP geo/ASN/ports
-o, --output    Save structured JSON report
-v, --version   Show version
-h, --help      Show help
```

---

## 📺 Demo

```
$ python3 recon.py -p +14155552671

  ____
 |  _ \ ___  ___ ___  _ __
 | |_) / _ \/ __/ _ \| '_ \
 |  _ <  __/ (_| (_) | | | |   v2.0.0
 |_| \_\___|\___\___/|_| |_|
   OSINT lookup • Pure stdlib • Kali Linux
      by Aswin Mathew  •  https://github.com/AswinMathew2004

╔══ PHONE → +14155552671 ════════════════════════════════════════╗
  [✓] E.164 form     →  +14155552671
  [✓] Country        →  United States/Canada (US/CA)  [+1]
  [✓] National no.   →  4155552671
  [✓] Timezone       →  America/New_York
  [✓] Length valid   →  10 digits (expected 10)
  [✓] US state       →  CA  (area code 415)

  [i] Manual lookups:
      Truecaller   → https://www.truecaller.com/search/us/ca/4155552671
      WhatsApp     → https://wa.me/14155552671
      ...
```

```
$ python3 recon.py -d github.com

╔══ DOMAIN → github.com ═════════════════════════════════════════╗
  [i] Querying WHOIS over port 43…
      Registrar          MarkMonitor Inc.
      Created            2007-10-09T18:20:50Z
      Expires            2026-10-09T07:00:00Z
      Name servers       DNS1.P08.NSONE.NET, DNS2.P08.NSONE.NET, ...
      DNSSEC             unsigned

  [i] DNS records (via Google DoH):
  [✓] A      (1)    140.82.114.4
  [✓] MX     (5)    1 aspmx.l.google.com.  ...
  [✓] TXT    (8)    v=spf1 ip4:192.30.252.0/22 ...

  [i] SSL certificate:
      Subject CN     github.com
      Issuer         Sectigo Limited / Sectigo ECC ...
      Valid until    Mar 14 23:59:59 2025 GMT
      SAN (2)        github.com, www.github.com

  [✓] Tech detected  →  Cloudflare, React, jQuery

  [i] Subdomain enumeration via crt.sh:
  [✓] Found 4823 unique subdomain(s)
      api.github.com
      assets.github.com
      ...
```

---

## 🧠 How it works

| Task | Library used | What's avoided |
|---|---|---|
| HTTP / HTTPS requests | `urllib.request` + `ssl` | `requests`, `httpx` |
| DNS queries (A, MX, TXT, NS) | `urllib` → Google DoH JSON API | `dnspython` |
| WHOIS lookups | raw TCP socket on port 43 | `python-whois` |
| SSL certificate parsing | `ssl.SSLContext.getpeercert()` | `cryptography` |
| Phone number parsing | embedded ITU dictionary | `phonenumbers` |
| Port scanning | `socket.create_connection` | `nmap`, `scapy` |
| Subdomain enumeration | crt.sh JSON endpoint | brute force, paid APIs |
| IP geolocation | ip-api.com (free, no key) | MaxMind GeoIP DB |
| Threading | `concurrent.futures.ThreadPoolExecutor` | — |

**Result:** the entire tool fits in one file, runs anywhere Python 3 runs, and never needs a `pip install`.

---

## 🧩 Extending

Adding a new platform takes one line. Edit the `SITES` dict in `recon.py`:

```python
SITES = {
    # ...
    "MyPlatform": ("https://myplatform.com/{}", "code", 200),
    # method "code" → HTTP status equals `expected` means exists
    # method "neg"  → 200 AND `expected` NOT in body
    # method "pos"  → 200 AND `expected` IS in body
}
```

Adding a new country phone code? Edit `COUNTRY_CODES`:
```python
COUNTRY_CODES = {
    ...
    999:("Atlantis","AT","Atlantic/Mid",10),
}
```

---

## 🛣 Roadmap

- [ ] HIBP API integration (with optional API key via env var)
- [ ] HTML report export with styled output
- [ ] Reverse image search on found profile pics
- [ ] Shodan integration for `-i` mode (with key)
- [ ] Docker image for one-shot execution
- [ ] Web UI

PRs welcome!

---

## 🧰 Pairs well with other Kali tools

[`sherlock`](https://github.com/sherlock-project/sherlock) • [`holehe`](https://github.com/megadose/holehe) • [`theHarvester`](https://github.com/laramies/theHarvester) • [`PhoneInfoga`](https://github.com/sundowndev/phoneinfoga) • [`Maigret`](https://github.com/soxoj/maigret) • [`Spiderfoot`](https://github.com/smicallef/spiderfoot) • [`Amass`](https://github.com/owasp-amass/amass)

---

## ⚠️ Legal & Ethical Use

This tool is built for:

- ✅ **Self-research** — see what's public about *you*
- ✅ **Authorized penetration testing** — with written permission from the target
- ✅ **Journalism / academic research** on public information
- ✅ **Cybersecurity learning** (CTFs, labs, red team exercises)

It must **NOT** be used for:

- ❌ Stalking, harassment, or doxxing private individuals
- ❌ Unauthorized investigation
- ❌ Anything that violates the laws of your jurisdiction

The port scan in `-i` mode is light and connection-only, but **port scanning systems you don't own may still be illegal where you live.** Know your local laws.

**You are responsible for how you use this tool.** The author assumes no liability for misuse.

---

## 📜 License

[MIT](LICENSE) © 2026 [Aswin Mathew](https://aswinmathew.xyz)

---

<div align="center">

### Made with ❤️ by Aswin Mathew

[🌐 aswinmathew.xyz](https://aswinmathew.xyz) • [💻 GitHub](https://github.com/AswinMathew2004)

⭐ **Star this repo if you found it useful!**

</div>
