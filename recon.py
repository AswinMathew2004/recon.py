#!/usr/bin/env python3
"""
recon.py v2.0 — Most powerful all-in-one OSINT lookup tool for Kali Linux
==========================================================================
PURE PYTHON STDLIB — zero pip installs. Works on any fresh Kali / Linux box.

Modules:
  -u  username  → 80+ social / dev / gaming / streaming sites
  -e  email     → format, MX records, gravatar, disposable check, breach links
  -p  phone     → country, region, carrier hints, line type (embedded ITU DB)
  -n  "name"    → search-engine dorks + auto-generated username permutations
  -d  domain    → WHOIS, DNS (A/AAAA/MX/NS/TXT), SSL cert, subdomains, headers
  -i  ip        → geolocation, reverse DNS, ASN, hosting provider

Author : Aswin Mathew
GitHub : https://github.com/AswinMathew2004
Web    : https://aswinmathew.xyz
License: MIT
"""

import argparse
import concurrent.futures
import hashlib
import json
import re
import socket
import ssl
import sys
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone as _tz

__version__ = "2.0.0"
__author__  = "Aswin Mathew"
__github__  = "https://github.com/AswinMathew2004"
__website__ = "https://aswinmathew.xyz"


# ════════════════════════════════════════════════════════════════════════════
#  TERMINAL COLORS + BANNER
# ════════════════════════════════════════════════════════════════════════════
class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
    M="\033[95m"; CY="\033[96m"; W="\033[97m"
    BOLD="\033[1m"; DIM="\033[2m"; END="\033[0m"

def banner():
    print(f"""{C.CY}
  ____                       
 |  _ \\ ___  ___ ___  _ __   
 | |_) / _ \\/ __/ _ \\| '_ \\  
 |  _ <  __/ (_| (_) | | | | 
 |_| \\_\\___|\\___\\___/|_| |_| {C.W} v{__version__}
{C.CY}   OSINT lookup • Pure stdlib • Kali Linux
{C.DIM}      by {__author__}  •  {__github__}{C.END}
""")

def section(label):
    print(f"\n{C.BOLD}{C.B}╔══ {label} {'═'*max(0,60-len(label))}╗{C.END}")

def ok(msg):    print(f"  {C.G}[✓]{C.END} {msg}")
def warn(msg):  print(f"  {C.Y}[!]{C.END} {msg}")
def info(msg):  print(f"  {C.CY}[i]{C.END} {msg}")
def fail(msg):  print(f"  {C.R}[✗]{C.END} {msg}")
def hit(name, url): print(f"  {C.G}[✓]{C.END} {name:<18} → {url}")


# ════════════════════════════════════════════════════════════════════════════
#  HTTP / DNS / WHOIS — all built on Python stdlib
# ════════════════════════════════════════════════════════════════════════════
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
TIMEOUT = 10

def http_get(url, timeout=TIMEOUT, headers=None, head_only=False):
    """GET (or HEAD) a URL using urllib. Returns (status, text, response_headers)."""
    h = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9"}
    if headers: h.update(headers)
    method = "HEAD" if head_only else "GET"
    req = urllib.request.Request(url, headers=h, method=method)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # OSINT: tolerate self-signed/expired
    try:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        with opener.open(req, timeout=timeout) as r:
            text = "" if head_only else r.read().decode("utf-8", errors="ignore")
            return r.status, text, dict(r.headers)
    except urllib.error.HTTPError as e:
        try: text = "" if head_only else e.read().decode("utf-8", errors="ignore")
        except Exception: text = ""
        return e.code, text, dict(e.headers) if e.headers else {}
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError, ssl.SSLError):
        return None, "", {}

def dns_query(name, qtype="A"):
    """Resolve DNS via Google DoH (no dependencies)."""
    url = f"https://dns.google/resolve?name={urllib.parse.quote(name)}&type={qtype}"
    status, body, _ = http_get(url, timeout=8)
    if status != 200: return []
    try:
        data = json.loads(body)
        return [a.get("data","") for a in data.get("Answer", [])]
    except Exception:
        return []

def whois_query(target):
    """Pure-socket WHOIS over port 43. Walks referrals."""
    # Pick a starting server
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
        server = "whois.arin.net"
    else:
        tld = target.rsplit(".", 1)[-1].lower()
        tld_servers = {
            "com":"whois.verisign-grs.com","net":"whois.verisign-grs.com",
            "org":"whois.pir.org","io":"whois.nic.io","co":"whois.nic.co",
            "info":"whois.nic.info","biz":"whois.nic.biz","me":"whois.nic.me",
            "xyz":"whois.nic.xyz","dev":"whois.nic.google","app":"whois.nic.google",
            "ai":"whois.nic.ai","tech":"whois.nic.tech","online":"whois.nic.online",
            "in":"whois.registry.in","uk":"whois.nic.uk","de":"whois.denic.de",
        }
        server = tld_servers.get(tld, "whois.iana.org")

    def _query(s, q):
        try:
            sock = socket.create_connection((s, 43), timeout=10)
            sock.sendall((q + "\r\n").encode())
            buf = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                buf += chunk
            sock.close()
            return buf.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    body = _query(server, target)
    # Follow one referral if present
    m = re.search(r"(?i)(?:whois|refer):\s*([\w\.\-]+)", body)
    if m and m.group(1).lower() != server.lower():
        body2 = _query(m.group(1), target)
        if body2: body = body2
    return body

def get_ssl_cert(hostname, port=443):
    """Pull TLS certificate via stdlib ssl module."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except Exception:
        return None


# ════════════════════════════════════════════════════════════════════════════
#  USERNAME LOOKUP — 80+ sites
# ════════════════════════════════════════════════════════════════════════════
# Format: site_name → (url_template, method, expected)
#   method "code"  → user exists if HTTP status == expected
#   method "neg"   → user exists if HTTP 200 AND expected string NOT in body
#   method "pos"   → user exists if expected string IN body
SITES = {
    # ── Code / Dev ──
    "GitHub":         ("https://github.com/{}",                          "code", 200),
    "GitLab":         ("https://gitlab.com/{}",                          "code", 200),
    "Bitbucket":      ("https://bitbucket.org/{}/",                      "code", 200),
    "DockerHub":      ("https://hub.docker.com/u/{}",                    "code", 200),
    "NPM":            ("https://www.npmjs.com/~{}",                      "code", 200),
    "PyPI":           ("https://pypi.org/user/{}/",                      "code", 200),
    "Replit":         ("https://replit.com/@{}",                         "code", 200),
    "CodePen":        ("https://codepen.io/{}",                          "code", 200),
    "JSFiddle":       ("https://jsfiddle.net/user/{}/",                  "code", 200),
    "Kaggle":         ("https://www.kaggle.com/{}",                      "code", 200),
    "HackerRank":     ("https://www.hackerrank.com/profile/{}",          "code", 200),
    "LeetCode":       ("https://leetcode.com/{}/",                       "code", 200),
    "Codeforces":     ("https://codeforces.com/profile/{}",              "neg",  "/profile/?"),
    "TryHackMe":      ("https://tryhackme.com/p/{}",                     "code", 200),
    "Dev.to":         ("https://dev.to/{}",                              "code", 200),
    "Hashnode":       ("https://hashnode.com/@{}",                       "code", 200),
    "StackOverflow":  ("https://stackoverflow.com/users/{}",             "code", 200),
    "HackerNews":     ("https://news.ycombinator.com/user?id={}",        "neg",  "No such user."),

    # ── Social / Mainstream ──
    "Twitter/X":      ("https://x.com/{}",                               "code", 200),
    "Instagram":      ("https://www.instagram.com/{}/",                  "code", 200),
    "Threads":        ("https://www.threads.net/@{}",                    "code", 200),
    "Bluesky":        ("https://bsky.app/profile/{}.bsky.social",        "code", 200),
    "Mastodon":       ("https://mastodon.social/@{}",                    "code", 200),
    "TikTok":         ("https://www.tiktok.com/@{}",                     "neg",  "Couldn't find this account"),
    "Reddit":         ("https://www.reddit.com/user/{}",                 "neg",  "Sorry, nobody on Reddit"),
    "Pinterest":      ("https://www.pinterest.com/{}/",                  "code", 200),
    "Tumblr":         ("https://{}.tumblr.com",                          "code", 200),
    "Snapchat":       ("https://www.snapchat.com/add/{}",                "code", 200),
    "Quora":          ("https://www.quora.com/profile/{}",               "code", 200),

    # ── Video / Streaming ──
    "YouTube":        ("https://www.youtube.com/@{}",                    "code", 200),
    "Twitch":         ("https://www.twitch.tv/{}",                       "code", 200),
    "Vimeo":          ("https://vimeo.com/{}",                           "code", 200),
    "Dailymotion":    ("https://www.dailymotion.com/{}",                 "code", 200),
    "Kick":           ("https://kick.com/{}",                            "code", 200),
    "Rumble":         ("https://rumble.com/c/{}",                        "code", 200),

    # ── Music / Audio ──
    "SoundCloud":     ("https://soundcloud.com/{}",                      "code", 200),
    "Spotify":        ("https://open.spotify.com/user/{}",               "code", 200),
    "Bandcamp":       ("https://{}.bandcamp.com",                        "code", 200),
    "Last.fm":        ("https://www.last.fm/user/{}",                    "code", 200),
    "Mixcloud":       ("https://www.mixcloud.com/{}/",                   "code", 200),
    "Genius":         ("https://genius.com/{}",                          "code", 200),

    # ── Gaming ──
    "Steam":          ("https://steamcommunity.com/id/{}",               "neg",  "The specified profile could not be found"),
    "Roblox":         ("https://www.roblox.com/user.aspx?username={}",   "code", 200),
    "ItchIO":         ("https://{}.itch.io",                             "code", 200),
    "GameJolt":       ("https://gamejolt.com/@{}",                       "code", 200),
    "Newgrounds":     ("https://{}.newgrounds.com",                      "code", 200),
    "Chess.com":      ("https://www.chess.com/member/{}",                "code", 200),
    "Lichess":        ("https://lichess.org/@/{}",                       "code", 200),
    "Speedrun":       ("https://www.speedrun.com/user/{}",               "code", 200),

    # ── Creative / Design ──
    "Behance":        ("https://www.behance.net/{}",                     "code", 200),
    "Dribbble":       ("https://dribbble.com/{}",                        "code", 200),
    "DeviantArt":     ("https://www.deviantart.com/{}",                  "code", 200),
    "ArtStation":     ("https://www.artstation.com/{}",                  "code", 200),
    "Flickr":         ("https://www.flickr.com/people/{}",               "code", 200),
    "500px":          ("https://500px.com/p/{}",                         "code", 200),
    "Unsplash":       ("https://unsplash.com/@{}",                       "code", 200),
    "Pixiv":          ("https://www.pixiv.net/en/users/{}",              "code", 200),

    # ── Blogging / Writing ──
    "Medium":         ("https://medium.com/@{}",                         "code", 200),
    "Substack":       ("https://{}.substack.com",                        "code", 200),
    "Wordpress":      ("https://{}.wordpress.com",                       "code", 200),
    "Blogger":        ("https://{}.blogspot.com",                        "code", 200),
    "Goodreads":      ("https://www.goodreads.com/{}",                   "code", 200),

    # ── Anime / Otaku ──
    "MyAnimeList":    ("https://myanimelist.net/profile/{}",             "code", 200),
    "AniList":        ("https://anilist.co/user/{}",                     "code", 200),
    "Crunchyroll":    ("https://www.crunchyroll.com/user/{}",            "code", 200),

    # ── Pro / Money / Productivity ──
    "Patreon":        ("https://www.patreon.com/{}",                     "code", 200),
    "BuyMeACoffee":   ("https://www.buymeacoffee.com/{}",                "code", 200),
    "Ko-fi":          ("https://ko-fi.com/{}",                           "code", 200),
    "ProductHunt":    ("https://www.producthunt.com/@{}",                "code", 200),
    "Wellfound":      ("https://wellfound.com/u/{}",                     "code", 200),
    "Fiverr":         ("https://www.fiverr.com/{}",                      "code", 200),
    "Etsy":           ("https://www.etsy.com/shop/{}",                   "code", 200),
    "TradingView":    ("https://www.tradingview.com/u/{}/",              "code", 200),

    # ── Misc / Identity ──
    "Telegram":       ("https://t.me/{}",                                "pos",  "tgme_page_title"),
    "Keybase":        ("https://keybase.io/{}",                          "code", 200),
    "About.me":       ("https://about.me/{}",                            "code", 200),
    "Linktree":       ("https://linktr.ee/{}",                           "code", 200),
    "Carrd":          ("https://{}.carrd.co",                            "code", 200),
    "Gravatar":       ("https://en.gravatar.com/{}",                     "code", 200),
    "Disqus":         ("https://disqus.com/by/{}/",                      "code", 200),
    "Imgur":          ("https://imgur.com/user/{}",                      "code", 200),
    "Pastebin":       ("https://pastebin.com/u/{}",                      "neg",  "Not Found"),
    "VirusTotal":     ("https://www.virustotal.com/gui/user/{}",         "code", 200),
}

def _check_site(name, tmpl, method, expected, username):
    url = tmpl.format(urllib.parse.quote(username))
    status, body, _ = http_get(url, timeout=8)
    if status is None: return name, url, None, None
    if method == "code":
        found = (status == expected)
    elif method == "neg":
        found = (status == 200) and (expected not in body)
    elif method == "pos":
        found = (status == 200) and (expected in body)
    else:
        found = False
    return name, url, found, status

def username_lookup(username):
    section(f"USERNAME → {username}")
    info(f"Scanning {len(SITES)} platforms with 25 worker threads…\n")
    hits, errors = [], 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as pool:
        futures = [
            pool.submit(_check_site, n, t, m, e, username)
            for n,(t,m,e) in SITES.items()
        ]
        for fut in concurrent.futures.as_completed(futures):
            name, url, found, status = fut.result()
            if found is True:
                hit(name, url)
                hits.append({"site": name, "url": url, "status": status})
            elif found is None:
                errors += 1
    print(f"\n{C.G}  ► Found on {len(hits)} platform(s){C.END}"
          f"{C.DIM}  ({errors} requests failed){C.END}")
    return {"username": username, "hits": hits, "errors": errors}


# ════════════════════════════════════════════════════════════════════════════
#  EMAIL LOOKUP
# ════════════════════════════════════════════════════════════════════════════
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

FREE_EMAIL_PROVIDERS = {
    "gmail.com","googlemail.com","yahoo.com","yahoo.co.uk","yahoo.co.in",
    "outlook.com","hotmail.com","live.com","msn.com","aol.com","icloud.com",
    "me.com","mac.com","protonmail.com","proton.me","tutanota.com","tuta.io",
    "zoho.com","gmx.com","mail.com","fastmail.com","pm.me","yandex.com",
    "yandex.ru","rediffmail.com",
}

DISPOSABLE_DOMAINS = {
    "mailinator.com","10minutemail.com","tempmail.com","temp-mail.org",
    "guerrillamail.com","guerrillamail.net","throwawaymail.com","trashmail.com",
    "yopmail.com","fakeinbox.com","getairmail.com","dispostable.com",
    "maildrop.cc","mintemail.com","mohmal.com","sharklasers.com","grr.la",
    "tempmailo.com","tempr.email","mailnesia.com","tempinbox.com",
    "10minemail.com","emailondeck.com","tempmailaddress.com","mytemp.email",
    "harakirimail.com","jetable.org","spamgourmet.com","mail-temp.com",
}

EMAIL_PROVIDER_HINTS = {
    "gmail.com":      "Google → check YouTube, Google Maps reviews, Photos, Drive shares",
    "googlemail.com": "Google → check YouTube, Maps, Photos",
    "outlook.com":    "Microsoft → check Xbox Live, LinkedIn, Skype",
    "hotmail.com":    "Microsoft → check Xbox Live, LinkedIn, Skype",
    "live.com":       "Microsoft → check Xbox Live, LinkedIn, Skype",
    "yahoo.com":      "Yahoo → linked to Flickr, Tumblr",
    "icloud.com":     "Apple ID → may be linked to App Store reviews, Find My",
    "protonmail.com": "Privacy-focused user — assume opsec-aware",
    "proton.me":      "Privacy-focused user — assume opsec-aware",
}

def email_lookup(email):
    section(f"EMAIL → {email}")
    out = {"email": email}

    # 1. Format validation
    if not EMAIL_RE.match(email):
        fail("Invalid email format")
        out["valid_format"] = False
        return out
    out["valid_format"] = True
    local, domain = email.split("@", 1)
    out["local_part"], out["domain"] = local, domain
    ok(f"Format valid       →  local={local}   domain={domain}")

    # 2. Disposable / free / business classification
    if domain.lower() in DISPOSABLE_DOMAINS:
        warn(f"DISPOSABLE email provider — likely throwaway account")
        out["category"] = "disposable"
    elif domain.lower() in FREE_EMAIL_PROVIDERS:
        info(f"Free email provider")
        out["category"] = "free"
    else:
        info(f"Custom/business domain — try whois & domain recon next")
        out["category"] = "business"

    # 3. Provider hint
    hint = EMAIL_PROVIDER_HINTS.get(domain.lower())
    if hint:
        info(f"Hint: {hint}")
        out["provider_hint"] = hint

    # 4. MX records via DoH
    mx = dns_query(domain, "MX")
    if mx:
        ok(f"MX records found ({len(mx)}):")
        for m in mx[:10]:
            print(f"      {C.W}{m}{C.END}")
        out["mx_records"] = mx
    else:
        warn("No MX records — mail likely undeliverable")
        out["mx_records"] = []

    # 5. SPF / DMARC quick check
    txt = dns_query(domain, "TXT")
    spf  = [t for t in txt if "v=spf1" in t.lower()]
    dmarc_txt = dns_query(f"_dmarc.{domain}", "TXT")
    dmarc = [t for t in dmarc_txt if "v=dmarc" in t.lower()]
    if spf:   info(f"SPF:   {spf[0][:100]}")
    if dmarc: info(f"DMARC: {dmarc[0][:100]}")
    out["spf"], out["dmarc"] = spf, dmarc

    # 6. Gravatar
    md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
    out["gravatar_md5"] = md5
    grav_avatar = f"https://www.gravatar.com/avatar/{md5}?d=404"
    grav_profile = f"https://en.gravatar.com/{md5}.json"
    status, _, _ = http_get(grav_avatar, timeout=6, head_only=True)
    if status == 200:
        ok(f"Gravatar found     →  {grav_avatar}")
        out["gravatar_url"] = grav_avatar
        s2, body, _ = http_get(grav_profile, timeout=6)
        if s2 == 200:
            try:
                prof = json.loads(body)
                ok(f"Gravatar profile   →  {grav_profile}")
                out["gravatar_profile"] = prof
            except Exception: pass
    else:
        info("No Gravatar")

    # 7. Try the local-part as a username across all sites
    print()
    info(f"Running local-part '{local}' as a username across all sites:")
    out["username_scan"] = username_lookup(local)

    # 8. Manual breach + lookup links
    enc = urllib.parse.quote_plus(email)
    out["breach_links"] = {
        "HaveIBeenPwned":  f"https://haveibeenpwned.com/account/{enc}",
        "DeHashed":        f"https://dehashed.com/search?query={enc}",
        "IntelligenceX":   f"https://intelx.io/?s={enc}",
        "LeakCheck":       f"https://leakcheck.io/search?query={enc}",
    }
    print()
    info("Manual breach checks (open in browser):")
    for name, link in out["breach_links"].items():
        print(f"      {name:<18} → {link}")
    return out


# ════════════════════════════════════════════════════════════════════════════
#  PHONE LOOKUP — embedded ITU + India + US databases
# ════════════════════════════════════════════════════════════════════════════
# ── ITU E.164 country code → (name, ISO, primary_timezone, expected_nat_len)
COUNTRY_CODES = {
1:("United States/Canada","US/CA","America/New_York",10),7:("Russia/Kazakhstan","RU","Europe/Moscow",10),
20:("Egypt","EG","Africa/Cairo",10),27:("South Africa","ZA","Africa/Johannesburg",9),
30:("Greece","GR","Europe/Athens",10),31:("Netherlands","NL","Europe/Amsterdam",9),
32:("Belgium","BE","Europe/Brussels",9),33:("France","FR","Europe/Paris",9),
34:("Spain","ES","Europe/Madrid",9),36:("Hungary","HU","Europe/Budapest",9),
39:("Italy","IT","Europe/Rome",10),40:("Romania","RO","Europe/Bucharest",9),
41:("Switzerland","CH","Europe/Zurich",9),43:("Austria","AT","Europe/Vienna",10),
44:("United Kingdom","GB","Europe/London",10),45:("Denmark","DK","Europe/Copenhagen",8),
46:("Sweden","SE","Europe/Stockholm",9),47:("Norway","NO","Europe/Oslo",8),
48:("Poland","PL","Europe/Warsaw",9),49:("Germany","DE","Europe/Berlin",11),
51:("Peru","PE","America/Lima",9),52:("Mexico","MX","America/Mexico_City",10),
53:("Cuba","CU","America/Havana",8),54:("Argentina","AR","America/Argentina/Buenos_Aires",10),
55:("Brazil","BR","America/Sao_Paulo",11),56:("Chile","CL","America/Santiago",9),
57:("Colombia","CO","America/Bogota",10),58:("Venezuela","VE","America/Caracas",10),
60:("Malaysia","MY","Asia/Kuala_Lumpur",9),61:("Australia","AU","Australia/Sydney",9),
62:("Indonesia","ID","Asia/Jakarta",10),63:("Philippines","PH","Asia/Manila",10),
64:("New Zealand","NZ","Pacific/Auckland",9),65:("Singapore","SG","Asia/Singapore",8),
66:("Thailand","TH","Asia/Bangkok",9),81:("Japan","JP","Asia/Tokyo",10),
82:("South Korea","KR","Asia/Seoul",10),84:("Vietnam","VN","Asia/Ho_Chi_Minh",9),
86:("China","CN","Asia/Shanghai",11),90:("Turkey","TR","Europe/Istanbul",10),
91:("India","IN","Asia/Kolkata",10),92:("Pakistan","PK","Asia/Karachi",10),
93:("Afghanistan","AF","Asia/Kabul",9),94:("Sri Lanka","LK","Asia/Colombo",9),
95:("Myanmar","MM","Asia/Yangon",9),98:("Iran","IR","Asia/Tehran",10),
211:("South Sudan","SS","Africa/Juba",9),212:("Morocco","MA","Africa/Casablanca",9),
213:("Algeria","DZ","Africa/Algiers",9),216:("Tunisia","TN","Africa/Tunis",8),
218:("Libya","LY","Africa/Tripoli",9),220:("Gambia","GM","Africa/Banjul",7),
221:("Senegal","SN","Africa/Dakar",9),222:("Mauritania","MR","Africa/Nouakchott",8),
223:("Mali","ML","Africa/Bamako",8),224:("Guinea","GN","Africa/Conakry",9),
225:("Ivory Coast","CI","Africa/Abidjan",10),226:("Burkina Faso","BF","Africa/Ouagadougou",8),
227:("Niger","NE","Africa/Niamey",8),228:("Togo","TG","Africa/Lome",8),
229:("Benin","BJ","Africa/Porto-Novo",8),230:("Mauritius","MU","Indian/Mauritius",8),
231:("Liberia","LR","Africa/Monrovia",8),232:("Sierra Leone","SL","Africa/Freetown",8),
233:("Ghana","GH","Africa/Accra",9),234:("Nigeria","NG","Africa/Lagos",10),
235:("Chad","TD","Africa/Ndjamena",8),236:("Central African Republic","CF","Africa/Bangui",8),
237:("Cameroon","CM","Africa/Douala",9),238:("Cape Verde","CV","Atlantic/Cape_Verde",7),
239:("Sao Tome","ST","Africa/Sao_Tome",7),240:("Equatorial Guinea","GQ","Africa/Malabo",9),
241:("Gabon","GA","Africa/Libreville",7),242:("Congo","CG","Africa/Brazzaville",9),
243:("DR Congo","CD","Africa/Kinshasa",9),244:("Angola","AO","Africa/Luanda",9),
245:("Guinea-Bissau","GW","Africa/Bissau",7),248:("Seychelles","SC","Indian/Mahe",7),
249:("Sudan","SD","Africa/Khartoum",9),250:("Rwanda","RW","Africa/Kigali",9),
251:("Ethiopia","ET","Africa/Addis_Ababa",9),252:("Somalia","SO","Africa/Mogadishu",8),
253:("Djibouti","DJ","Africa/Djibouti",8),254:("Kenya","KE","Africa/Nairobi",9),
255:("Tanzania","TZ","Africa/Dar_es_Salaam",9),256:("Uganda","UG","Africa/Kampala",9),
257:("Burundi","BI","Africa/Bujumbura",8),258:("Mozambique","MZ","Africa/Maputo",9),
260:("Zambia","ZM","Africa/Lusaka",9),261:("Madagascar","MG","Indian/Antananarivo",9),
262:("Reunion","RE","Indian/Reunion",9),263:("Zimbabwe","ZW","Africa/Harare",9),
264:("Namibia","NA","Africa/Windhoek",9),265:("Malawi","MW","Africa/Blantyre",9),
266:("Lesotho","LS","Africa/Maseru",8),267:("Botswana","BW","Africa/Gaborone",8),
268:("Eswatini","SZ","Africa/Mbabane",8),269:("Comoros","KM","Indian/Comoro",7),
290:("Saint Helena","SH","Atlantic/St_Helena",4),291:("Eritrea","ER","Africa/Asmara",7),
297:("Aruba","AW","America/Aruba",7),298:("Faroe Islands","FO","Atlantic/Faroe",6),
299:("Greenland","GL","America/Godthab",6),350:("Gibraltar","GI","Europe/Gibraltar",8),
351:("Portugal","PT","Europe/Lisbon",9),352:("Luxembourg","LU","Europe/Luxembourg",9),
353:("Ireland","IE","Europe/Dublin",9),354:("Iceland","IS","Atlantic/Reykjavik",7),
355:("Albania","AL","Europe/Tirane",9),356:("Malta","MT","Europe/Malta",8),
357:("Cyprus","CY","Asia/Nicosia",8),358:("Finland","FI","Europe/Helsinki",9),
359:("Bulgaria","BG","Europe/Sofia",9),370:("Lithuania","LT","Europe/Vilnius",8),
371:("Latvia","LV","Europe/Riga",8),372:("Estonia","EE","Europe/Tallinn",8),
373:("Moldova","MD","Europe/Chisinau",8),374:("Armenia","AM","Asia/Yerevan",8),
375:("Belarus","BY","Europe/Minsk",9),376:("Andorra","AD","Europe/Andorra",6),
377:("Monaco","MC","Europe/Monaco",8),378:("San Marino","SM","Europe/San_Marino",10),
380:("Ukraine","UA","Europe/Kiev",9),381:("Serbia","RS","Europe/Belgrade",9),
382:("Montenegro","ME","Europe/Podgorica",8),383:("Kosovo","XK","Europe/Belgrade",8),
385:("Croatia","HR","Europe/Zagreb",9),386:("Slovenia","SI","Europe/Ljubljana",8),
387:("Bosnia & Herzegovina","BA","Europe/Sarajevo",8),389:("North Macedonia","MK","Europe/Skopje",8),
420:("Czech Republic","CZ","Europe/Prague",9),421:("Slovakia","SK","Europe/Bratislava",9),
423:("Liechtenstein","LI","Europe/Vaduz",7),500:("Falkland Islands","FK","Atlantic/Stanley",5),
501:("Belize","BZ","America/Belize",7),502:("Guatemala","GT","America/Guatemala",8),
503:("El Salvador","SV","America/El_Salvador",8),504:("Honduras","HN","America/Tegucigalpa",8),
505:("Nicaragua","NI","America/Managua",8),506:("Costa Rica","CR","America/Costa_Rica",8),
507:("Panama","PA","America/Panama",8),509:("Haiti","HT","America/Port-au-Prince",8),
591:("Bolivia","BO","America/La_Paz",8),592:("Guyana","GY","America/Guyana",7),
593:("Ecuador","EC","America/Guayaquil",9),595:("Paraguay","PY","America/Asuncion",9),
597:("Suriname","SR","America/Paramaribo",7),598:("Uruguay","UY","America/Montevideo",8),
670:("Timor-Leste","TL","Asia/Dili",8),673:("Brunei","BN","Asia/Brunei",7),
675:("Papua New Guinea","PG","Pacific/Port_Moresby",8),676:("Tonga","TO","Pacific/Tongatapu",7),
679:("Fiji","FJ","Pacific/Fiji",7),680:("Palau","PW","Pacific/Palau",7),
682:("Cook Islands","CK","Pacific/Rarotonga",5),685:("Samoa","WS","Pacific/Apia",7),
686:("Kiribati","KI","Pacific/Tarawa",5),687:("New Caledonia","NC","Pacific/Noumea",6),
689:("French Polynesia","PF","Pacific/Tahiti",8),691:("Micronesia","FM","Pacific/Pohnpei",7),
692:("Marshall Islands","MH","Pacific/Majuro",7),850:("North Korea","KP","Asia/Pyongyang",10),
852:("Hong Kong","HK","Asia/Hong_Kong",8),853:("Macau","MO","Asia/Macau",8),
855:("Cambodia","KH","Asia/Phnom_Penh",8),856:("Laos","LA","Asia/Vientiane",10),
880:("Bangladesh","BD","Asia/Dhaka",10),886:("Taiwan","TW","Asia/Taipei",9),
960:("Maldives","MV","Indian/Maldives",7),961:("Lebanon","LB","Asia/Beirut",8),
962:("Jordan","JO","Asia/Amman",9),963:("Syria","SY","Asia/Damascus",9),
964:("Iraq","IQ","Asia/Baghdad",10),965:("Kuwait","KW","Asia/Kuwait",8),
966:("Saudi Arabia","SA","Asia/Riyadh",9),967:("Yemen","YE","Asia/Aden",9),
968:("Oman","OM","Asia/Muscat",8),970:("Palestine","PS","Asia/Gaza",9),
971:("UAE","AE","Asia/Dubai",9),972:("Israel","IL","Asia/Jerusalem",9),
973:("Bahrain","BH","Asia/Bahrain",8),974:("Qatar","QA","Asia/Qatar",8),
975:("Bhutan","BT","Asia/Thimphu",8),976:("Mongolia","MN","Asia/Ulaanbaatar",8),
977:("Nepal","NP","Asia/Kathmandu",10),992:("Tajikistan","TJ","Asia/Dushanbe",9),
993:("Turkmenistan","TM","Asia/Ashgabat",8),994:("Azerbaijan","AZ","Asia/Baku",9),
995:("Georgia","GE","Asia/Tbilisi",9),996:("Kyrgyzstan","KG","Asia/Bishkek",9),
998:("Uzbekistan","UZ","Asia/Tashkent",9),
}

# ── Indian mobile prefix → operator (best-effort; MNP may have changed actual carrier)
# Based on TRAI block allocations. First 4 digits of a 10-digit mobile number.
INDIAN_MOBILE_HINT = """
60-66 series : Reliance Jio (most blocks)
70-71 series : BSNL / Idea / Vodafone (legacy)
72-75 series : Airtel / Idea / Vodafone (mixed)
76-77 series : Reliance Jio / Airtel
78-79 series : Airtel / Idea / Vodafone
80-81 series : Airtel / Reliance Jio
82-83 series : Vodafone / Idea / Airtel
84-85 series : Vodafone Idea (Vi)
86-87 series : Airtel / Idea
88-89 series : Vodafone Idea (Vi) / Airtel
90-91 series : Airtel / Vodafone
92-93 series : Airtel / Vodafone Idea
94-95 series : Vodafone Idea / BSNL / Airtel
96-97 series : Airtel / Vodafone / Idea
98-99 series : Airtel / Vodafone / BSNL / Idea
NOTE: Mobile Number Portability (MNP) makes prefix→carrier unreliable since 2011.
""".strip()

# ── US area codes (NPA) → State/Region (abridged but covers all assigned NPAs as of 2024)
US_AREA_CODES = {
"201":"NJ","202":"DC","203":"CT","205":"AL","206":"WA","207":"ME","208":"ID","209":"CA","210":"TX",
"212":"NY","213":"CA","214":"TX","215":"PA","216":"OH","217":"IL","218":"MN","219":"IN","220":"OH",
"223":"PA","224":"IL","225":"LA","227":"MD","228":"MS","229":"GA","231":"MI","234":"OH","239":"FL",
"240":"MD","248":"MI","251":"AL","252":"NC","253":"WA","254":"TX","256":"AL","260":"IN","262":"WI",
"267":"PA","269":"MI","270":"KY","272":"PA","276":"VA","281":"TX","301":"MD","302":"DE","303":"CO",
"304":"WV","305":"FL","307":"WY","308":"NE","309":"IL","310":"CA","312":"IL","313":"MI","314":"MO",
"315":"NY","316":"KS","317":"IN","318":"LA","319":"IA","320":"MN","321":"FL","323":"CA","325":"TX",
"330":"OH","331":"IL","332":"NY","334":"AL","336":"NC","337":"LA","339":"MA","346":"TX","347":"NY",
"351":"MA","352":"FL","360":"WA","361":"TX","364":"KY","380":"OH","385":"UT","386":"FL","401":"RI",
"402":"NE","404":"GA","405":"OK","406":"MT","407":"FL","408":"CA","409":"TX","410":"MD","412":"PA",
"413":"MA","414":"WI","415":"CA","417":"MO","419":"OH","423":"TN","424":"CA","425":"WA","430":"TX",
"432":"TX","434":"VA","435":"UT","440":"OH","442":"CA","443":"MD","458":"OR","463":"IN","464":"IL",
"469":"TX","470":"GA","475":"CT","478":"GA","479":"AR","480":"AZ","484":"PA","501":"AR","502":"KY",
"503":"OR","504":"LA","505":"NM","507":"MN","508":"MA","509":"WA","510":"CA","512":"TX","513":"OH",
"515":"IA","516":"NY","517":"MI","518":"NY","520":"AZ","530":"CA","531":"NE","539":"OK","540":"VA",
"541":"OR","551":"NJ","559":"CA","561":"FL","562":"CA","563":"IA","564":"WA","567":"OH","570":"PA",
"571":"VA","573":"MO","574":"IN","575":"NM","580":"OK","585":"NY","586":"MI","601":"MS","602":"AZ",
"603":"NH","605":"SD","606":"KY","607":"NY","608":"WI","609":"NJ","610":"PA","612":"MN","614":"OH",
"615":"TN","616":"MI","617":"MA","618":"IL","619":"CA","620":"KS","623":"AZ","626":"CA","628":"CA",
"629":"TN","630":"IL","631":"NY","636":"MO","641":"IA","646":"NY","650":"CA","651":"MN","657":"CA",
"660":"MO","661":"CA","662":"MS","667":"MD","669":"CA","678":"GA","680":"NY","681":"WV","682":"TX",
"701":"ND","702":"NV","703":"VA","704":"NC","706":"GA","707":"CA","708":"IL","712":"IA","713":"TX",
"714":"CA","715":"WI","716":"NY","717":"PA","718":"NY","719":"CO","720":"CO","724":"PA","725":"NV",
"726":"TX","727":"FL","731":"TN","732":"NJ","734":"MI","737":"TX","740":"OH","743":"NC","747":"CA",
"754":"FL","757":"VA","760":"CA","762":"GA","763":"MN","765":"IN","769":"MS","770":"GA","772":"FL",
"773":"IL","774":"MA","775":"NV","779":"IL","781":"MA","785":"KS","786":"FL","787":"PR","801":"UT",
"802":"VT","803":"SC","804":"VA","805":"CA","806":"TX","808":"HI","810":"MI","812":"IN","813":"FL",
"814":"PA","815":"IL","816":"MO","817":"TX","818":"CA","828":"NC","830":"TX","831":"CA","832":"TX",
"835":"PA","843":"SC","845":"NY","847":"IL","848":"NJ","850":"FL","854":"SC","856":"NJ","857":"MA",
"858":"CA","859":"KY","860":"CT","862":"NJ","863":"FL","864":"SC","865":"TN","870":"AR","872":"IL",
"878":"PA","901":"TN","903":"TX","904":"FL","906":"MI","907":"AK","908":"NJ","909":"CA","910":"NC",
"912":"GA","913":"KS","914":"NY","915":"TX","916":"CA","917":"NY","918":"OK","919":"NC","920":"WI",
"925":"CA","928":"AZ","929":"NY","930":"IN","931":"TN","934":"NY","936":"TX","937":"OH","938":"AL",
"939":"PR","940":"TX","941":"FL","947":"MI","949":"CA","951":"CA","952":"MN","954":"FL","956":"TX",
"959":"CT","970":"CO","971":"OR","972":"TX","973":"NJ","978":"MA","979":"TX","980":"NC","984":"NC",
"985":"LA","989":"MI"
}

def phone_lookup(raw):
    section(f"PHONE → {raw}")
    out = {"raw": raw}
    digits = re.sub(r"\D", "", raw)
    if not digits:
        fail("No digits found"); return out
    if raw.strip().startswith("+"):
        e164 = digits
    elif digits.startswith("00"):
        e164 = digits[2:]
    elif len(digits) == 10:
        warn("No country code — assuming +91 (India). Use +<cc>… for accuracy.")
        e164 = "91" + digits
    else:
        e164 = digits

    # Match country code (longest first)
    cc = None
    for length in (3, 2, 1):
        if len(e164) >= length:
            test = int(e164[:length])
            if test in COUNTRY_CODES:
                cc = test
                national = e164[length:]
                break
    if cc is None:
        fail(f"Could not match a country code in '{e164}'")
        return out

    name, iso, tz, exp_len = COUNTRY_CODES[cc]
    out.update({
        "e164":        "+" + e164,
        "country_code": cc,
        "country":     name,
        "iso":         iso,
        "national":    national,
        "timezone":    tz,
    })

    ok(f"E.164 form     →  +{e164}")
    ok(f"Country        →  {name} ({iso})  [+{cc}]")
    ok(f"National no.   →  {national}")
    ok(f"Timezone       →  {tz}")

    # Length sanity check
    if exp_len:
        if len(national) == exp_len:
            ok(f"Length valid   →  {len(national)} digits (expected {exp_len})")
            out["length_valid"] = True
        else:
            warn(f"Length unusual →  {len(national)} digits (expected ~{exp_len})")
            out["length_valid"] = False

    # India-specific: mobile prefix hint
    if cc == 91 and len(national) == 10:
        first = national[0]
        if first in "6789":
            ok(f"Line type      →  Mobile (prefix {first})")
            out["line_type"] = "Mobile"
            print(f"\n  {C.CY}[i]{C.END} Indian operator hints (best-effort, MNP affects accuracy):")
            for line in INDIAN_MOBILE_HINT.splitlines():
                print(f"      {C.DIM}{line}{C.END}")
            out["india_carrier_hint_table"] = INDIAN_MOBILE_HINT
        else:
            warn(f"Indian number doesn't start with 6-9 — may be landline or invalid")
            out["line_type"] = "Landline / Unknown"

    # US-specific: NPA → state
    if cc == 1 and len(national) == 10:
        npa = national[:3]
        state = US_AREA_CODES.get(npa)
        if state:
            ok(f"US state       →  {state}  (area code {npa})")
            out["us_state"] = state
        else:
            warn(f"Unknown US area code: {npa}")

    # Manual lookup links
    clean = e164
    out["lookup_links"] = {
        "Truecaller":      f"https://www.truecaller.com/search/{iso.lower()}/{national}",
        "WhatsApp":        f"https://wa.me/{clean}",
        "Telegram":        f"https://t.me/+{clean}",
        "Google":          f"https://www.google.com/search?q=%22%2B{clean}%22",
        "Sync.me":         f"https://sync.me/search/?number=%2B{clean}",
        "WhitePages":      f"https://www.whitepages.com/phone/+{clean}",
    }
    print(f"\n  {C.CY}[i]{C.END} Manual lookups:")
    for k, v in out["lookup_links"].items():
        print(f"      {k:<12} → {v}")
    return out


# ════════════════════════════════════════════════════════════════════════════
#  NAME LOOKUP
# ════════════════════════════════════════════════════════════════════════════
def name_lookup(name):
    section(f"NAME → {name}")
    q = urllib.parse.quote_plus(name)
    dorks = {
        "Google exact":      f'https://www.google.com/search?q=%22{q}%22',
        "+ LinkedIn":        f'https://www.google.com/search?q=%22{q}%22+site%3Alinkedin.com',
        "+ Facebook":        f'https://www.google.com/search?q=%22{q}%22+site%3Afacebook.com',
        "+ Twitter/X":       f'https://www.google.com/search?q=%22{q}%22+site%3Ax.com',
        "+ Instagram":       f'https://www.google.com/search?q=%22{q}%22+site%3Ainstagram.com',
        "+ GitHub":          f'https://www.google.com/search?q=%22{q}%22+site%3Agithub.com',
        "+ Reddit":          f'https://www.google.com/search?q=%22{q}%22+site%3Areddit.com',
        "+ YouTube":         f'https://www.google.com/search?q=%22{q}%22+site%3Ayoutube.com',
        "+ PDFs/Docs":       f'https://www.google.com/search?q=%22{q}%22+filetype%3Apdf+OR+filetype%3Adocx',
        "+ Resumes":         f'https://www.google.com/search?q=%22{q}%22+%28resume+OR+cv%29+filetype%3Apdf',
        "+ Court records":   f'https://www.google.com/search?q=%22{q}%22+%28court+OR+arrest+OR+criminal%29',
        "+ Phone/email":     f'https://www.google.com/search?q=%22{q}%22+%28phone+OR+email+OR+contact%29',
        "Bing":              f'https://www.bing.com/search?q=%22{q}%22',
        "DuckDuckGo":        f'https://duckduckgo.com/?q=%22{q}%22',
        "Yandex (intl)":     f'https://yandex.com/search/?text=%22{q}%22',
        "ThatsThem":         f'https://thatsthem.com/name/{urllib.parse.quote(name.replace(" ","-"))}',
        "Google Images":     f'https://www.google.com/search?q=%22{q}%22&tbm=isch',
        "Yandex Images":     f'https://yandex.com/images/search?text=%22{q}%22',
    }
    info(f"Search dorks ({len(dorks)} pre-built links):")
    for label, url in dorks.items():
        print(f"      {label:<18} → {url}")

    # Build username permutations from the name
    parts = [p for p in re.split(r"\s+", name.strip().lower()) if p]
    candidates = set()
    if len(parts) >= 2:
        f, l = parts[0], parts[-1]
        mid = parts[1] if len(parts) > 2 else ""
        candidates.update({
            f+l, f+"."+l, f+"_"+l, f+"-"+l,
            f[0]+l, f+l[0], l+f, l+"."+f,
            l+f[0], f[0]+"."+l, f+l+"1", f+l+"123",
            f+"."+l[0], f[0]+l[0]+l[1:] if len(l)>1 else "",
        })
        if mid:
            candidates.update({f+mid+l, f[0]+mid[0]+l[0] if mid else ""})
    elif parts:
        candidates.update({parts[0], parts[0]+"1", parts[0]+"123"})
    candidates.discard("")

    print(f"\n  {C.M}[*]{C.END} Generated {len(candidates)} username permutation(s); scanning each:")
    all_hits = {}
    for cand in sorted(candidates):
        print(f"\n  {C.DIM}── trying: {cand} ──{C.END}")
        result = username_lookup(cand)
        if result["hits"]:
            all_hits[cand] = result["hits"]
    return {"name": name, "dorks": dorks, "username_results": all_hits}


# ════════════════════════════════════════════════════════════════════════════
#  DOMAIN LOOKUP — WHOIS, DNS, SSL, subdomains, headers, robots, sitemap
# ════════════════════════════════════════════════════════════════════════════
def _parse_whois(text):
    fields = {}
    patterns = {
        "Registrar":        r"(?i)registrar:\s*(.+)",
        "Created":          r"(?i)creat(?:ed|ion date):\s*(.+)",
        "Updated":          r"(?i)updated date:\s*(.+)",
        "Expires":          r"(?i)expir(?:y|ation date):\s*(.+)",
        "Registrant org":   r"(?i)registrant organization:\s*(.+)",
        "Registrant ctry":  r"(?i)registrant country:\s*(.+)",
        "Status":           r"(?i)(?:domain |)status:\s*(.+)",
        "Name servers":     r"(?i)name server:\s*(.+)",
        "DNSSEC":           r"(?i)dnssec:\s*(.+)",
    }
    for k, p in patterns.items():
        matches = re.findall(p, text)
        if matches:
            fields[k] = [m.strip() for m in matches[:5]]
    return fields

def domain_lookup(domain):
    section(f"DOMAIN → {domain}")
    domain = domain.replace("http://", "").replace("https://", "").rstrip("/").split("/")[0]
    out = {"domain": domain}

    # 1. WHOIS
    info("Querying WHOIS over port 43…")
    whois_text = whois_query(domain)
    parsed = _parse_whois(whois_text)
    if parsed:
        for k, v in parsed.items():
            print(f"      {C.W}{k:<18}{C.END} {', '.join(v)}")
        out["whois"] = parsed
    else:
        warn("Couldn't parse WHOIS (raw output saved in JSON if -o used)")
    out["whois_raw"] = whois_text[:5000]

    # 2. DNS
    print()
    info("DNS records (via Google DoH):")
    for qt in ("A","AAAA","MX","NS","TXT","CNAME","SOA"):
        records = dns_query(domain, qt)
        if records:
            print(f"  {C.G}[✓]{C.END} {qt:<6} ({len(records)})")
            for r in records[:8]:
                print(f"        {r}")
            out[f"dns_{qt}"] = records

    # 3. SSL cert
    print()
    info("SSL certificate:")
    cert = get_ssl_cert(domain)
    if cert:
        subj = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        sans = [v for k,v in cert.get("subjectAltName", []) if k=="DNS"]
        print(f"      {C.W}Subject CN     {C.END}{subj.get('commonName','-')}")
        print(f"      {C.W}Issuer         {C.END}{issuer.get('organizationName','-')} / {issuer.get('commonName','-')}")
        print(f"      {C.W}Valid from     {C.END}{cert.get('notBefore','-')}")
        print(f"      {C.W}Valid until    {C.END}{cert.get('notAfter','-')}")
        print(f"      {C.W}SAN ({len(sans)})    {C.END}{', '.join(sans[:8])}{'…' if len(sans)>8 else ''}")
        out["ssl"] = {
            "subject": subj, "issuer": issuer,
            "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"),
            "sans": sans
        }
    else:
        warn("No SSL cert retrieved (HTTPS may be unavailable)")

    # 4. HTTP headers + tech fingerprint
    print()
    info("HTTP response headers (https://):")
    status, body, headers = http_get(f"https://{domain}", timeout=10)
    if status:
        for k in ("Server","X-Powered-By","X-Frame-Options","Strict-Transport-Security",
                  "Content-Security-Policy","Set-Cookie","X-Generator"):
            v = headers.get(k) or headers.get(k.lower())
            if v: print(f"      {C.W}{k:<28}{C.END}{v[:120]}")
        out["http_headers"] = {k:v for k,v in headers.items()}
        out["http_status"] = status
        # Quick tech sniff from body
        techs = []
        body_low = (body or "")[:50000].lower()
        for tech, sig in (
            ("WordPress","wp-content"),("WordPress","wp-includes"),
            ("Shopify","cdn.shopify.com"),("Wix","wix.com"),("Squarespace","squarespace"),
            ("React","__next_data__"),("React","react"),("Vue","__vue"),
            ("Cloudflare","cf-ray"),("jQuery","jquery"),("Bootstrap","bootstrap"),
            ("Google Analytics","google-analytics.com"),("GA4","gtag/js"),
            ("Tailwind","tailwind"),("Webflow","webflow"),
        ):
            if sig in body_low and tech not in techs:
                techs.append(tech)
        if techs:
            ok(f"Tech detected  →  {', '.join(techs)}")
            out["tech_stack"] = techs
    else:
        warn("HTTPS request failed")

    # 5. robots.txt + sitemap
    print()
    info("robots.txt:")
    s, body, _ = http_get(f"https://{domain}/robots.txt", timeout=6)
    if s == 200 and body.strip():
        lines = body.strip().splitlines()
        for line in lines[:15]:
            print(f"      {C.DIM}{line}{C.END}")
        if len(lines) > 15: print(f"      {C.DIM}… ({len(lines)-15} more lines){C.END}")
        out["robots_txt"] = body[:5000]
    else:
        warn("No robots.txt")

    info("sitemap.xml:")
    s, body, _ = http_get(f"https://{domain}/sitemap.xml", timeout=6)
    if s == 200 and "<" in body:
        urls = re.findall(r"<loc>(.*?)</loc>", body)[:10]
        if urls:
            for u in urls: print(f"      {u}")
            out["sitemap_urls"] = urls
    else:
        warn("No sitemap.xml")

    # 6. Subdomain enumeration via crt.sh
    print()
    info("Subdomain enumeration via crt.sh (Certificate Transparency logs):")
    s, body, _ = http_get(f"https://crt.sh/?q={domain}&output=json", timeout=15)
    subs = set()
    if s == 200 and body:
        try:
            data = json.loads(body)
            for entry in data:
                for n in entry.get("name_value","").split("\n"):
                    n = n.strip().lower()
                    if n and "*" not in n and n.endswith(domain):
                        subs.add(n)
        except Exception:
            pass
    if subs:
        ok(f"Found {len(subs)} unique subdomain(s):")
        for s_ in sorted(subs)[:40]:
            print(f"      {s_}")
        if len(subs) > 40: print(f"      {C.DIM}… ({len(subs)-40} more){C.END}")
        out["subdomains"] = sorted(subs)
    else:
        warn("crt.sh returned no results")

    # 7. Wayback Machine
    print()
    info("Wayback Machine snapshots:")
    s, body, _ = http_get(f"http://archive.org/wayback/available?url={domain}", timeout=8)
    if s == 200:
        try:
            data = json.loads(body)
            snap = data.get("archived_snapshots", {}).get("closest")
            if snap:
                print(f"      Latest snapshot: {snap.get('url')}")
                print(f"      Timestamp:       {snap.get('timestamp')}")
                out["wayback"] = snap
        except Exception: pass

    return out


# ════════════════════════════════════════════════════════════════════════════
#  IP LOOKUP — geo, reverse DNS, ASN, hosting
# ════════════════════════════════════════════════════════════════════════════
def ip_lookup(ip):
    section(f"IP → {ip}")
    out = {"ip": ip}

    # Validate
    try:
        socket.inet_aton(ip)
    except OSError:
        fail("Not a valid IPv4 address (use a domain with -d instead)")
        return out

    # Reverse DNS
    try:
        rdns = socket.gethostbyaddr(ip)[0]
        ok(f"Reverse DNS    →  {rdns}")
        out["reverse_dns"] = rdns
    except (socket.herror, socket.gaierror):
        warn("No reverse DNS")

    # IP geolocation (free, no API key)
    s, body, _ = http_get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=8)
    if s == 200:
        try:
            d = json.loads(body)
            if d.get("status") == "success":
                fields = [
                    ("Country",     f"{d.get('country','-')} ({d.get('countryCode','-')})"),
                    ("Region",      f"{d.get('regionName','-')} ({d.get('region','-')})"),
                    ("City",        f"{d.get('city','-')}  ZIP: {d.get('zip','-')}"),
                    ("Coordinates", f"{d.get('lat','-')}, {d.get('lon','-')}"),
                    ("Timezone",    d.get('timezone','-')),
                    ("ISP",         d.get('isp','-')),
                    ("Organization",d.get('org','-')),
                    ("AS",          d.get('as','-')),
                    ("Mobile",      str(d.get('mobile', False))),
                    ("Proxy/VPN",   str(d.get('proxy', False))),
                    ("Hosting",     str(d.get('hosting', False))),
                ]
                for k, v in fields:
                    print(f"      {C.W}{k:<14}{C.END}{v}")
                out["geo"] = d
                lat, lon = d.get("lat"), d.get("lon")
                if lat and lon:
                    info(f"Map: https://www.google.com/maps?q={lat},{lon}")
            else:
                warn(f"ip-api error: {d.get('message')}")
        except Exception as e:
            warn(f"Failed to parse geo response: {e}")
    else:
        warn("Geolocation API unreachable")

    # WHOIS for IP
    print()
    info("IP WHOIS (port 43):")
    text = whois_query(ip)
    if text:
        for line in text.splitlines()[:25]:
            if line.strip() and not line.strip().startswith("#") and not line.strip().startswith("%"):
                print(f"      {C.DIM}{line[:120]}{C.END}")
        out["whois_raw"] = text[:5000]

    # Quick top-port scan (very light, safe)
    print()
    info("Quick port check (top 10 ports, 1s timeout each):")
    common_ports = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
                    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",
                    3306:"MySQL",3389:"RDP",8080:"HTTP-Alt"}
    open_ports = []
    for port, svc in common_ports.items():
        try:
            with socket.create_connection((ip, port), timeout=1):
                ok(f"Open: {port}/tcp ({svc})")
                open_ports.append({"port": port, "service": svc})
        except Exception:
            pass
    if not open_ports:
        info("No common ports responded (filtered or closed)")
    out["open_ports"] = open_ports
    return out


# ════════════════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description=f"recon.py v{__version__} — most powerful OSINT lookup, pure stdlib  •  by {__author__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon.py -u johndoe
  python3 recon.py -e john@example.com
  python3 recon.py -p +14155552671
  python3 recon.py -p +919876543210
  python3 recon.py -n "John Doe"
  python3 recon.py -d example.com
  python3 recon.py -i 8.8.8.8
  python3 recon.py -u johndoe -e a@b.com -p +91... -d a.com -o report.json
""")
    parser.add_argument("-u","--username", help="Username (80+ social/dev/gaming sites)")
    parser.add_argument("-e","--email",    help="Email address (MX, gravatar, breaches, etc.)")
    parser.add_argument("-p","--phone",    help="Phone number with +country code")
    parser.add_argument("-n","--name",     help="Full name (dorks + auto username permutations)")
    parser.add_argument("-d","--domain",   help="Domain (WHOIS/DNS/SSL/subdomains/headers)")
    parser.add_argument("-i","--ip",       help="IPv4 address (geo, ASN, reverse DNS, ports)")
    parser.add_argument("-o","--output",   help="Save full results to JSON file")
    parser.add_argument("-v","--version",  action="version",
                        version=f"recon.py {__version__} • {__github__}")
    args = parser.parse_args()

    if not any([args.username,args.email,args.phone,args.name,args.domain,args.ip]):
        banner(); parser.print_help(); sys.exit(0)

    banner()
    results = {
        "tool":"recon.py","version":__version__,"author":__author__,
        "scan_time": datetime.now(_tz.utc).isoformat(),
        "inputs": {k:v for k,v in vars(args).items() if v and k!="output"},
    }

    if args.username: results["username"] = username_lookup(args.username)
    if args.email:    results["email"]    = email_lookup(args.email)
    if args.phone:    results["phone"]    = phone_lookup(args.phone)
    if args.name:     results["name"]     = name_lookup(args.name)
    if args.domain:   results["domain"]   = domain_lookup(args.domain)
    if args.ip:       results["ip"]       = ip_lookup(args.ip)

    if args.output:
        with open(args.output,"w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n{C.G}[✓] Saved full report → {args.output}{C.END}")

    print(f"\n{C.BOLD}{C.G}[✓] Recon complete.{C.END}")
    print(f"{C.DIM}    Made by {__author__}  •  {__website__}{C.END}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.R}[!] Interrupted by user{C.END}")
        sys.exit(130)
