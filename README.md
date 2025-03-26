<b>Description:</b>

The <b>Phishing Detection and Prevention System for Crypto Services</b> is a Python-based tool created by [Ahmad Haji](https://ahmadhaji.com) to help identify and flag suspicious (potentially phishing) URLs. It incorporates MetaMask’s [eth-phishing-detect](https://github.com/MetaMask/eth-phishing-detect) lists—specifically the whitelist, blacklist, and fuzzylist—and combines them with additional heuristic checks (e.g., WHOIS domain age, punycode detection, suspicious crypto-related keywords). When a domain/URL is entered, the script returns a “Safe,” “Suspicious,” or “Phishing” classification along with an associated risk score.

---

# Phishing Detection and Prevention System for Crypto Services

A Python-based phishing detector created by [Ahmad Haji](https://ahmadhaji.com) that integrates MetaMask’s blacklist, whitelist, and fuzzylist for crypto-focused domains, plus additional heuristic checks.


---

## Features
1. <b>MetaMask Config Integration</b>  
   Automatically checks input domains against MetaMask’s `whitelist`, `blacklist`, and `fuzzylist` via a remote JSON or local file.

2. <b>Heuristic Checks</b>  
   - **Suspicious Keywords** (e.g., `binance`, `airdrop`, `wallet`, etc.)  
   - **Punycode Detection** (IDN homograph attacks)  
   - **WHOIS Domain Age** (newly registered domains are suspicious)  
   - **IP Address Check** (IP-based domains often indicate malicious sites)

3. <b>Fuzzy Matching</b>  
   - Uses Levenshtein distance to detect near-duplicates (e.g. `myetherwal1et.com` vs. `myetherwallet.com`).

4. <b>Custom Safe List</b>  
   - Automatically considers `ahmadhaji.com` (or any domains you choose) as “Safe.”

5. <b>Simple Classification</b>  
   - Returns **Safe**, **Suspicious**, or **Phishing** based on cumulative risk score.

---

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/phishing-detection.git
   cd phishing-detection
