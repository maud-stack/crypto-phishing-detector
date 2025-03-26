"""
Creator: Ahmad Haji
Website: https://ahmadhaji.com

Phishing Detection Script - Enhanced
"""

import re
import socket
import requests
import datetime
import whois
import tldextract

try:
    from Levenshtein import distance as levenshtein_distance
    # If not installed, run: pip install python-Levenshtein
except ImportError:
    # Fallback: use difflib's SequenceMatcher (not as direct, but works)
    import difflib
    def levenshtein_distance(a, b):
        """Estimate similarity using a ratio, then convert to a 'distance' approximation."""
        seq = difflib.SequenceMatcher(None, a, b)
        ratio = seq.ratio()
        # Convert ratio (0 to 1) into a rough distance metric
        max_len = max(len(a), len(b))
        return int((1 - ratio) * max_len)

#############################
# Global Constants / Config #
#############################

# Suspicious crypto keywords for heuristic checks
SUSPICIOUS_KEYWORDS = [
    "binance", "wallet", "metamask", "login", "secure", "verify", "airdrop",
    "coinbase", "crypto", "exchange", "free", "bonus", "claim", "opensea"
]

# Our local safe domain (explicitly treat as safe).
CREATOR_SAFE_DOMAINS = ["ahmadhaji.com"]

# Optionally store the metamask config locally, or fetch from GitHub:
METAMASK_CONFIG_URL = (
    "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json"
)
# For performance or reliability, you could store this JSON offline in your repo.
# e.g. "config_metamask.json" => load from file instead of remote URL.

#############################
#          Functions        #
#############################

def load_metamask_config():
    """
    Loads the MetaMask/eth-phishing-detect config JSON from GitHub or local file.
    Returns a dictionary containing:
      {
        "whitelist": [...],
        "blacklist": [...],
        "fuzzylist": [...],
        "tolerance": int
      }
    """
    try:
        response = requests.get(METAMASK_CONFIG_URL, timeout=10)
        if response.status_code == 200:
            data = response.json()
            # We only care about a subset of keys: "whitelist", "blacklist", "fuzzylist", "tolerance"
            return {
                "whitelist": data.get("whitelist", []),
                "blacklist": data.get("blacklist", []),
                "fuzzylist": data.get("fuzzylist", []),
                "tolerance": data.get("tolerance", 1)
            }
        else:
            print(f"[Warning] Failed to fetch MetaMask config. Status: {response.status_code}")
            return {}
    except Exception as e:
        print(f"[Error] Unable to load MetaMask config: {e}")
        return {}

def extract_domain(url):
    """
    Safely extract domain parts using tldextract.
    Handles http/https, subdomains, etc.
    Returns (subdomain, domain, suffix, full_domain)
    """
    extracted = tldextract.extract(url)
    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain

    # Rebuild a full domain (e.g. "example.co.uk")
    if suffix:
        full_domain = f"{domain}.{suffix}"
    else:
        full_domain = domain

    return subdomain, domain, suffix, full_domain

def is_ip_address(host):
    """
    Check if the given host is a valid IP address.
    """
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        return False

def get_domain_age(domain):
    """
    Get the domain's creation date from WHOIS data to measure domain age.
    Returns the number of days since registration or None if unavailable.
    """
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date and isinstance(creation_date, datetime.datetime):
            delta = datetime.datetime.now() - creation_date
            return delta.days
    except Exception:
        pass
    return None

def check_punycode(full_domain):
    """
    Checks if the domain contains punycode (IDN).
    e.g. 'xn--' prefix can disguise characters.
    """
    return "xn--" in full_domain

def keyword_score(subdomain, domain):
    """
    Checks if suspicious crypto/phishing keywords appear in the subdomain or domain.
    Returns an integer score.
    """
    score = 0
    combined = (subdomain + domain).lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in combined:
            score += 1
    return score

def fuzzy_check(target_domain, fuzzylist, tolerance=1):
    """
    Checks if the target_domain is within a certain Levenshtein distance
    (or approximate distance) of any domain in fuzzylist.
    Returns True if suspicious, False otherwise.
    """
    target_domain_lower = target_domain.lower()
    for fz in fuzzylist:
        # e.g. "etherscan.io" or "myetherwallet.com" etc.
        dist = levenshtein_distance(target_domain_lower, fz.lower())
        if dist <= tolerance:
            return True
    return False

def classify_score(score):
    """
    Classify final numeric score into categories.
    Adjust thresholds as needed for your risk tolerance.
    """
    if score <= 2:
        return "Safe"
    elif 2 < score <= 5:
        return "Suspicious"
    else:
        return "Phishing"

def check_phishing(url):
    """
    Main function to evaluate a URL or domain and return:
      - classification (Safe / Suspicious / Phishing)
      - risk_score (integer)
      - domain_age_days (None if unknown)
    """

    # Load external config (blacklist, whitelist, fuzzylist, tolerance).
    mm_config = load_metamask_config()
    blacklist = mm_config.get("blacklist", [])
    whitelist = mm_config.get("whitelist", [])
    fuzzylist = mm_config.get("fuzzylist", [])
    tolerance = mm_config.get("tolerance", 1)

    subdomain, domain, suffix, full_domain = extract_domain(url)
    # For matching on black/white/fuzzy, let's be consistent about the "domain" format
    # We consider subdomain + "." + full_domain in many cases. 
    # But for direct checks, many lists only store the root domain.
    # We’ll check both.

    # 1. Explicit checks against known safe/unsafe lists.

    # Combine subdomain & full_domain to compare with the typical entries in these lists.
    # e.g. "sub.example.com" or just "example.com"
    combined_domain = full_domain if not subdomain else f"{subdomain}.{full_domain}".lower()
    combined_domain = combined_domain.lower()

    # If domain in your personal safe list
    if combined_domain in CREATOR_SAFE_DOMAINS:
        return {
            "url": url,
            "classification": "Safe",
            "risk_score": 0,
            "domain_age_days": None  # or whatever
        }

    # If domain is explicitly in the metamask whitelist
    if combined_domain in [d.lower() for d in whitelist]:
        return {
            "url": url,
            "classification": "Safe",
            "risk_score": 0,
            "domain_age_days": None
        }

    # If domain is explicitly in the metamask blacklist
    if combined_domain in [d.lower() for d in blacklist]:
        return {
            "url": url,
            "classification": "Phishing",
            "risk_score": 999,  # high score
            "domain_age_days": None
        }

    # 2. Start our heuristic scoring
    risk_score = 0

    # A) IP-based domain = suspicious
    if is_ip_address(domain):
        risk_score += 3

    # B) Check for punycode
    if check_punycode(full_domain):
        risk_score += 2

    # C) Suspicious keywords
    risk_score += keyword_score(subdomain, domain)

    # D) WHOIS domain age
    domain_age_days = get_domain_age(full_domain)
    if domain_age_days is not None:
        # If younger than 30 days, big suspicion
        if domain_age_days < 30:
            risk_score += 3
    else:
        # WHOIS info not available -> add mild suspicion
        risk_score += 1

    # E) Fuzzy list check
    # If within the tolerance distance of a known domain => suspicious
    if fuzzy_check(combined_domain, fuzzylist, tolerance):
        risk_score += 3

    # 3. Classification
    classification = classify_score(risk_score)

    return {
        "url": url,
        "classification": classification,
        "risk_score": risk_score,
        "domain_age_days": domain_age_days
    }

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python phishing_detector.py <URL_OR_DOMAIN>")
        sys.exit(1)

    url_input = sys.argv[1]
    result = check_phishing(url_input)

    print(f"URL: {result['url']}")
    print(f"Classification: {result['classification']}")
    print(f"Risk Score: {result['risk_score']}")
    if result["domain_age_days"] is not None:
        print(f"Domain Age (days): {result['domain_age_days']}")
    else:
        print("Domain Age (days): Unknown")
