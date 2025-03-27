<h1>🚨 Crypto-Phishing Detector</h1>

img src="https://i.imgur.com/JXGLjL9.png" alt="Phishing Detector Panel">


<p>
  A lightweight yet powerful <b>phishing detection</b> tool tailored for <b>crypto/web3</b> domains.<br>
  This repository includes both a <b>standalone Python script</b> and a <b>Flask REST API</b> for detecting suspicious or malicious URLs.<br>
  It leverages <b>MetaMask</b>’s eth-phishing-detect lists, fuzzy domain matching, WHOIS lookups, punycode checks, and more.
</p>

<hr>

<h2>🔐 Features</h2>

<ul>
  <li><b>MetaMask List Integration</b><br>
      Automatically checks URLs against MetaMask’s official <b>blacklist</b>, <b>whitelist</b>, and <b>fuzzylist</b>.
  </li>
  <li><b>Heuristic Scoring</b><br>
      Flags suspicious URLs using:
      <ul>
        <li>IP-based domains</li>
        <li>Punycode usage</li>
        <li>Crypto-related keywords</li>
        <li>WHOIS-based domain age</li>
      </ul>
  </li>
  <li><b>Fuzzy Matching</b><br>
      Detects typo-squatting using <a href="https://en.wikipedia.org/wiki/Levenshtein_distance">Levenshtein distance</a> (with <code>difflib</code> fallback).<br>
      Example: <code>binanse.com</code> vs <code>binance.com</code>
  </li>
  <li><b>CLI or REST API</b><br>
      <ul>
        <li><b>CLI</b>: Run <code>python phishing_detector.py &lt;URL&gt;</code> for instant analysis</li>
        <li><b>API</b>: Use <code>/api/check_phishing</code> via GET or POST</li>
      </ul>
  </li>
  <li><b>Configurable & Extensible</b><br>
      Easily modify:
      <ul>
        <li>Risk scoring thresholds</li>
        <li>Suspicious keywords</li>
        <li>Custom domain lists</li>
      </ul>
  </li>
</ul>

<hr>

<h2>📁 Repository Structure</h2>

<pre>
crypto-phishing-detector/
├── server_panel/
│   ├── app.py               # Flask API Server
│   ├── phishing_detector.py # Detection logic for API
│   └── requirements.txt     # Server-side dependencies
├── phishing_detector.py     # Standalone CLI script
├── requirements.txt         # CLI dependencies
└── README.md                # This file
</pre>

<blockquote><b>Note:</b> There are two <code>phishing_detector.py</code> files — one in root and one under <code>server_panel/</code>. You may unify or rename them.</blockquote>

<hr>

<h2>⚙️ Installation</h2>

<ol>
  <li><b>Clone the repository:</b><br>
  <pre><code>git clone https://github.com/maud-stack/crypto-phishing-detector.git
cd crypto-phishing-detector</code></pre></li>

  <li><b>Install dependencies (CLI):</b><br>
  <pre><code>pip install -r requirements.txt</code></pre></li>

  <li><b>Install dependencies for Flask API (optional):</b><br>
  <pre><code>pip install -r server_panel/requirements.txt</code></pre></li>

  <li><b>Optional: Better fuzzy matching with python-Levenshtein:</b><br>
  <pre><code>pip install python-Levenshtein</code></pre></li>
</ol>

<hr>

<h2>🚀 Usage</h2>

<h3>A) Command-Line (CLI)</h3>
<pre><code>python phishing_detector.py &lt;URL_OR_DOMAIN&gt;</code></pre>
<b>Example:</b>
<pre><code>python phishing_detector.py https://some-suspicious-domain.xyz</code></pre>
<b>Output:</b>
<pre>
URL: https://some-suspicious-domain.xyz
Classification: Phishing
Risk Score: 7
Domain Age (days): Unknown
</pre>

<h3>B) REST API (Flask)</h3>

<ol>
  <li><b>Navigate to server_panel/ and run:</b><br>
  <pre><code>cd server_panel
python app.py</code></pre></li>

  <li><b>GET request:</b><br>
  <pre><code>curl "http://127.0.0.1:5000/api/check_phishing?url=https://some-domain.com"</code></pre></li>

  <li><b>POST request:</b><br>
  <pre><code>curl -X POST -H "Content-Type: application/json" \
  -d '{"url":"https://some-domain.com"}' \
  http://127.0.0.1:5000/api/check_phishing</code></pre></li>
</ol>

<b>Sample JSON response:</b>
<pre><code>{
  "url": "https://some-domain.com",
  "classification": "Suspicious",
  "risk_score": 4,
  "domain_age_days": 12
}</code></pre>

<hr>

<h2>🛠 Configuration Notes</h2>

<ul>
  <li><b>Scoring Thresholds</b><br>
    Default classification:
    <ul>
      <li><code>score ≤ 2</code> → Safe</li>
      <li><code>2 &lt; score ≤ 5</code> → Suspicious</li>
      <li><code>score &gt; 5</code> → Phishing</li>
    </ul>
    Adjust this logic in the <code>classify_score()</code> function.
  </li>

  <li><b>WHOIS Domain Age</b><br>
    Newly registered domains (&lt; 30 days) are scored higher.<br>
    You can customize this in <code>check_phishing()</code>.
  </li>

  <li><b>MetaMask List Caching</b><br>
    The script fetches MetaMask lists from GitHub.<br>
    For production, consider storing them locally to reduce network calls.
  </li>
</ul>

<hr>

<h2>🤝 Contributing</h2>

<ol>
  <li>Fork the repo and create a feature branch:<br>
  <pre><code>git checkout -b feature/amazing_feature</code></pre></li>

  <li>Commit your changes:<br>
  <pre><code>git commit -m "Add some amazing feature"</code></pre></li>

  <li>Push to your fork:<br>
  <pre><code>git push origin feature/amazing_feature</code></pre></li>

  <li>Open a Pull Request on GitHub</li>
</ol>

<hr>

<h2>📄 License</h2>
<p>
  This project is provided under the <b>MIT License</b>.<br>
  See the <code>LICENSE</code> file for details.
</p>

<hr>

<h2>👨‍💻 Creator</h2>
<p>
  Created by <b>Ahmad Haji</b><br>
  Maintained by <b>maud-stack</b>
</p>
