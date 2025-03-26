"""
Phishing Detector
Creator: Ahmad Haji (https://ahmadhaji.com)
Description:
  Core phishing detection logic incorporating:
  - MetaMask block/allow lists
  - Fuzzy matching (Levenshtein/difflib)
  - Heuristic checks: WHOIS age, punycode, crypto keywords, IP-based domains
"""

import re
import socket
import requests
import datetime
import whois
import tldextract

try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    import difflib
    def levenshtein_distance(a, b):
        seq = difflib.SequenceMatcher(None, a, b)
        ratio = seq.ratio()
        max_len = max(len(a), len(b))
        return int((1 - ratio) * max_len)

# MetaMask config URL
METAMASK_CONFIG_URL = "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json"

# Suspicious keywords
SUSPICIOUS_KEYWORDS = [
    "binance", "wallet", "metamask", "login", "secure", "verify",
    "airdrop", "coinbase", "crypto", "exchange", "free", "bonus",
    "claim", "opensea"
]

# Explicitly safe domain(s) for demonstration
CREATOR_SAFE_DOMAINS = ["ahmadhaji.com"]

def load_metamask_config():
    """
    Loads the MetaMask/eth-phishing-detect config JSON from GitHub
    Returns { "whitelist": [...], "blacklist": [...], "fuzzylist": [...], "tolerance": int }
    """
    try:
        resp = requests.get(METAMASK_CONFIG_URL, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "whitelist": data.get("whitelist", []),
                "blacklist": data.get("blacklist", []),
                "fuzzylist": data.get("fuzzylist", []),
                "tolerance": data.get("tolerance", 1)
            }
        else:
            print(f"[Warning] Could not fetch MetaMask config. Status {resp.status_code}")
            return {}
    except Exception as e:
        print(f"[Error] Failed to load MetaMask config: {e}")
        return {}

def extract_domain(url):
    """
    Extract domain info using tldextract.
    Returns (subdomain, domain, suffix, full_domain)
    """
    ex = tldextract.extract(url)
    subdomain = ex.subdomain
    domain = ex.domain
    suffix = ex.suffix
    if suffix:
        full_domain = f"{domain}.{suffix}"
    else:
        full_domain = domain
    return subdomain, domain, suffix, full_domain

def is_ip_address(host):
    """Check if host is a valid IP address."""
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        return False

def get_domain_age(domain):
    """Get domain age in days from WHOIS, or None if unavailable."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date and isinstance(creation_date, datetime.datetime):
            age = (datetime.datetime.now() - creation_date).days
            return age
    except:
        pass
    return None

def check_punycode(full_domain):
    """Check if domain is using punycode (xn--)."""
    return "xn--" in full_domain

def keyword_score(subdomain, domain):
    """
    Check for suspicious keywords in subdomain+domain.
    Returns an integer risk score.
    """
    score = 0
    combined = (subdomain + domain).lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in combined:
            score += 1
    return score

def fuzzy_check(target_domain, fuzzylist, tolerance=1):
    """
    Check if target_domain is within a certain Levenshtein distance
    of any domain in fuzzylist. Returns True if suspicious, else False.
    """
    td_lower = target_domain.lower()
    for fz in fuzzylist:
        dist = levenshtein_distance(td_lower, fz.lower())
        if dist <= tolerance:
            return True
    return False

def classify_score(score):
    """Convert a numeric risk score into classification labels."""
    if score <= 2:
        return "Safe"
    elif 2 < score <= 5:
        return "Suspicious"
    else:
        return "Phishing"

def check_phishing(url):
    """
    Main function to evaluate a URL. Returns dict with:
    {
      "url": str,
      "classification": "Safe"|"Suspicious"|"Phishing",
      "risk_score": int,
      "domain_age_days": int|None
    }
    """
    # Load metamask config
    mm_config = load_metamask_config()
    whitelist = [d.lower() for d in mm_config.get("whitelist", [])]
    blacklist = [d.lower() for d in mm_config.get("blacklist", [])]
    fuzzylist = mm_config.get("fuzzylist", [])
    tolerance = mm_config.get("tolerance", 1)

    subdomain, domain, suffix, full_domain = extract_domain(url)
    combined_domain = full_domain if not subdomain else f"{subdomain}.{full_domain}"
    combined_domain = combined_domain.lower()

    # 1. Check custom safe domain
    if combined_domain in CREATOR_SAFE_DOMAINS:
        return {
            "url": url,
            "classification": "Safe",
            "risk_score": 0,
            "domain_age_days": None
        }

    # 2. Check metamask whitelist
    if combined_domain in whitelist:
        return {
            "url": url,
            "classification": "Safe",
            "risk_score": 0,
            "domain_age_days": None
        }

    # 3. Check metamask blacklist
    if combined_domain in blacklist:
        return {
            "url": url,
            "classification": "Phishing",
            "risk_score": 999,
            "domain_age_days": None
        }

    # 4. Heuristic scoring
    score = 0

    # IP-based check
    if is_ip_address(domain):
        score += 3

    # Punycode check
    if check_punycode(full_domain):
        score += 2

    # Keyword check
    score += keyword_score(subdomain, domain)

    # WHOIS domain age
    age_days = get_domain_age(full_domain)
    if age_days is not None:
        if age_days < 30:
            score += 3
    else:
        score += 1

    # Fuzzylist check
    if fuzzy_check(combined_domain, fuzzylist, tolerance):
        score += 3

    classification = classify_score(score)

    return {
        "url": url,
        "classification": classification,
        "risk_score": score,
        "domain_age_days": age_days
    }
