**Phishing Detection and Prevention System for Crypto Services
A Python-based phishing detector created by Ahmad Haji that integrates MetaMask’s blacklist, whitelist, and fuzzylist for crypto-focused domains, plus additional heuristic checks.**

Table of Contents
Features

Installation

Usage

Project Structure

Configuration

How It Works

Disclaimer

Author

Features
MetaMask Config Integration
Automatically checks input domains against MetaMask’s whitelist, blacklist, and fuzzylist via a remote JSON or local file.

Heuristic Checks

Suspicious Keywords (e.g., binance, airdrop, wallet, etc.)

Punycode Detection (IDN homograph attacks)

WHOIS Domain Age (newly registered domains are suspicious)

IP Address Check (IP-based domains often indicate malicious sites)

Fuzzy Matching

Uses Levenshtein distance to detect near-duplicates (e.g. myetherwal1et.com vs. myetherwallet.com).

Custom Safe List

Automatically considers ahmadhaji.com (or any domains you choose) as “Safe.”

Simple Classification

Returns Safe, Suspicious, or Phishing based on cumulative risk score.

Installation
Clone the Repository:

bash
Copy
git clone https://github.com/yourusername/phishing-detection.git
cd phishing-detection
Install Dependencies:

bash
Copy
pip install -r requirements.txt
The requirements.txt includes:

tldextract

requests

python-whois

python-Levenshtein (optional; the script can fallback to difflib)

Usage
bash
Copy
python phishing_detector.py <URL_OR_DOMAIN>
Example:

bash
Copy
python phishing_detector.py https://example.com
Sample Output:

yaml
Copy
URL: https://example.com
Classification: Safe
Risk Score: 0
Domain Age (days): 8047
Project Structure
bash
Copy
phishing_detection/
├── README.md                # This README file
├── phishing_detector.py     # The main Python script
├── requirements.txt         # Python dependencies
└── ...
Configuration
MetaMask Config URL
In phishing_detector.py, you’ll see a constant:

python
Copy
METAMASK_CONFIG_URL = "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json"
The script pulls the latest whitelist/blacklist/fuzzylist from MetaMask each time it runs.

You can store this JSON locally if you prefer.

You can also adjust the path to any other phishing-data source.

Creator’s Safe Domain

python
Copy
CREATOR_SAFE_DOMAINS = ["ahmadhaji.com"]
Add your personal or corporate domains here to always mark them as safe.

Suspicious Keywords

python
Copy
SUSPICIOUS_KEYWORDS = [
    "binance", "wallet", "metamask", "login", "secure", "verify",
    ...
]
Feel free to modify this list according to your threat intelligence needs.

Heuristic Weighting
Within check_phishing() and helper functions, you can adjust the risk increments:

IP-based domain: risk_score += 3

Punycode detection: risk_score += 2

Keywords: +1 per match

Domain age <30 days: risk_score += 3

WHOIS unavailable: risk_score += 1

Fuzzy match: risk_score += 3

Final classification thresholds: <=2 (Safe), <=5 (Suspicious), else (Phishing)

How It Works
Domain Extraction & Preprocessing
Uses tldextract to correctly parse the domain, subdomain, and suffix from the provided URL.

Check Against Lists

Personal Safe List (ahmadhaji.com)

MetaMask Whitelist

MetaMask Blacklist

MetaMask Fuzzylist (with Levenshtein distance up to the specified tolerance)

Apply Heuristic Rules

WHOIS lookup for domain creation date; consider newly registered domains suspicious.

Check punycode usage.

Keywords in domain or subdomain.

IP-based domain check.

Calculate Risk Score
If the domain is not immediately flagged or whitelisted, each suspicious characteristic increases the score.

Final Classification
Based on the total score, the script returns “Safe,” “Suspicious,” or “Phishing,” along with a risk score and an approximate domain age (if available).

Disclaimer
This script is a demonstration of phishing detection techniques. Use with caution and in combination with other security measures:

False positives may occur.

False negatives may allow some phishing sites to slip by undetected.

Performance: WHOIS lookups and remote list fetches can be slow or rate-limited. Consider caching or offline usage.

For robust production use, integrate multiple data sources (threat intelligence APIs, reputational databases, machine learning, etc.) and maintain ongoing security updates.

Author
Ahmad Haji

Personal Website: https://ahmadhaji.com

Feel free to contribute to the project or adapt it for your specific needs. Pull requests and suggestions are always welcome!
