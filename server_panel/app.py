from flask import Flask, request, jsonify, render_template_string
from phishing_detector import check_phishing

app = Flask(__name__)

# 1) Serve a simple HTML page at "/"
@app.route("/", methods=["GET"])
def index():
    # Inline HTML using render_template_string (simple for demo)
    # Feel free to split into a separate template file if you want.
    html_page = """
    <html>
    <head>
        <title>Phishing Detector Panel</title>
        <style>
            body {
                background-color: #0f1123; 
                color: #fff; 
                font-family: "Courier New", monospace; 
                margin: 0; 
                padding: 0; 
            }
            .container {
                display: flex; 
                flex-direction: column; 
                align-items: center; 
                justify-content: center; 
                height: 100vh; 
            }
            h1 {
                color: #00bcd4; 
                margin-bottom: 1rem;
            }
            .panel {
                background: #1d1f33; 
                padding: 2rem; 
                border-radius: 8px;
                box-shadow: 0 0 20px rgba(0,0,0,0.5);
            }
            input[type="text"] {
                width: 300px; 
                padding: 0.5rem; 
                margin-bottom: 1rem; 
                border: none; 
                border-radius: 4px;
            }
            button {
                padding: 0.6rem 1rem; 
                background-color: #00bcd4; 
                color: #fff; 
                border: none; 
                border-radius: 4px; 
                cursor: pointer;
            }
            button:hover {
                background-color: #0199ad;
            }
            .result {
                margin-top: 1rem;
                color: #ff4081; 
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="panel">
                <h1>Crypto Phishing Detector</h1>
                <form method="POST" action="/">
                    <input type="text" name="url" placeholder="Enter a URL to check..." required/>
                    <br>
                    <button type="submit">Check</button>
                </form>
                {% if result %}
                <div class="result">
                    <strong>URL:</strong> {{ result.url }}<br>
                    <strong>Classification:</strong> {{ result.classification }}<br>
                    <strong>Risk Score:</strong> {{ result.risk_score }}<br>
                    <strong>Domain Age (days):</strong> {{ result.domain_age_days if result.domain_age_days else "Unknown" }}
                </div>
                {% endif %}
            </div>
        </div>
    </body>
    </html>
    """
    # When we GET "/", just return the page with no result
    return render_template_string(html_page)

# 2) Handle the form POST at "/" so we can display results on the same page
@app.route("/", methods=["POST"])
def index_post():
    url = request.form.get("url", "")
    phishing_result = check_phishing(url)

    # We’ll re-render the same page, but pass `result` to display classification, etc.
    html_page = """
    <html>
    <head>
        <title>Phishing Detector Panel</title>
        <style>
            body {
                background-color: #0f1123; 
                color: #fff; 
                font-family: "Courier New", monospace; 
                margin: 0; 
                padding: 0;
            }
            .container {
                display: flex; 
                flex-direction: column; 
                align-items: center; 
                justify-content: center; 
                height: 100vh;
            }
            h1 {
                color: #00bcd4; 
                margin-bottom: 1rem;
            }
            .panel {
                background: #1d1f33; 
                padding: 2rem; 
                border-radius: 8px;
                box-shadow: 0 0 20px rgba(0,0,0,0.5);
            }
            input[type="text"] {
                width: 300px; 
                padding: 0.5rem; 
                margin-bottom: 1rem; 
                border: none; 
                border-radius: 4px;
            }
            button {
                padding: 0.6rem 1rem; 
                background-color: #00bcd4; 
                color: #fff; 
                border: none; 
                border-radius: 4px; 
                cursor: pointer;
            }
            button:hover {
                background-color: #0199ad;
            }
            .result {
                margin-top: 1rem;
                color: #ff4081; 
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="panel">
                <h1>Crypto Phishing Detector</h1>
                <form method="POST" action="/">
                    <input type="text" name="url" placeholder="Enter a URL to check..." required/>
                    <br>
                    <button type="submit">Check</button>
                </form>
                {% if result %}
                <div class="result">
                    <strong>URL:</strong> {{ result.url }}<br>
                    <strong>Classification:</strong> {{ result.classification }}<br>
                    <strong>Risk Score:</strong> {{ result.risk_score }}<br>
                    <strong>Domain Age (days):</strong> {{ result.domain_age_days if result.domain_age_days else "Unknown" }}
                </div>
                {% endif %}
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_page, result=phishing_result)

# 3) Keep your API endpoint as-is for JSON usage
@app.route("/api/check_phishing", methods=["GET", "POST"])
def api_check_phishing():
    if request.method == "GET":
        url = request.args.get("url")
    else:
        data = request.get_json(force=True)
        url = data.get("url", None)

    if not url:
        return jsonify({"error": "No URL provided."}), 400

    result = check_phishing(url)
    return jsonify(result)

# 4) Typical Flask runner
if __name__ == "__main__":
    # You can set debug=False for a production environment
    app.run(host="0.0.0.0", port=5000, debug=True)
