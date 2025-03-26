"""
Flask Server
Creator: Ahmad Haji
Description:
  Provides a REST API for phishing detection. 
  Endpoint: /api/check_phishing?url=<your_url>
"""

from flask import Flask, request, jsonify
from phishing_detector import check_phishing

app = Flask(__name__)

@app.route("/api/check_phishing", methods=["GET", "POST"])
def api_check_phishing():
    """
    Example usage:
    GET /api/check_phishing?url=https://some-domain.com
    POST /api/check_phishing with JSON: {"url": "https://some-domain.com"}
    """
    if request.method == "GET":
        url = request.args.get("url")
    else:
        data = request.get_json(force=True)
        url = data.get("url", None)

    if not url:
        return jsonify({"error": "No URL provided."}), 400

    result = check_phishing(url)
    return jsonify(result)

if __name__ == "__main__":
    # Run in debug for local development
    app.run(host="0.0.0.0", port=5000, debug=True)
