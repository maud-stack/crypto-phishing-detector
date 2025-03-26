# Phishing Detection & Prevention System for Crypto Services

A Python-based tool created by **[Ahmad Haji](https://ahmadhaji.com)** that checks a given domain or URL against **phishing threats**. It leverages:

- **MetaMask’s** [`eth-phishing-detect`](https://github.com/MetaMask/eth-phishing-detect) lists (whitelist, blacklist, fuzzylist)  
- **Heuristic checks** (WHOIS domain age, punycode detection, suspicious crypto keywords, IP-based domain)  
- **Fuzzy matching** (Levenshtein distance) to identify near-duplicate domains (e.g., `myetherwal1et.com` vs. `myetherwallet.com`)

When a URL is submitted, the system returns a **classification**—“Safe,” “Suspicious,” or “Phishing”—along with a **risk score** and the domain’s approximate age in days, if available.

---

## Table of Contents
1. [Features](#features)
2. [Project Structure](#project-structure)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Configuration & Customization](#configuration--customization)
6. [API Endpoint](#api-endpoint)
7. [Examples](#examples)
8. [Disclaimer](#disclaimer)
9. [Author](#author)

---

## Features

1. **MetaMask Config Integration**  
   Checks input domains against MetaMask’s `whitelist`, `blacklist`, and `fuzzylist` (fetched or stored locally).

2. **Heuristic Phishing Detection**  
   - **Suspicious Keywords**: (“binance,” “wallet,” “metamask,” etc.)  
   - **Punycode** (IDN homograph attacks)  
   - **Domain Age** (WHOIS)  
   - **IP-based Domains**  
   - **Fuzzy Matching** to detect near-duplicate phishing domains

3. **Risk Scoring & Classification**  
   A simple scoring mechanism (0 to 999) that classifies domains as **Safe**, **Suspicious**, or **Phishing**.

4. **Custom Safe Domains**  
   Automatically treats certain domains (e.g., `ahmadhaji.com`) as safe.

5. **Flask-based REST API**  
   Allows easy integration with other services or UIs.

---

## Project Structure

