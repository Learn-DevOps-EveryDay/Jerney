from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"})


@app.route("/api/info", methods=["GET"])
def info():
    return jsonify({
        "app": "jerney-api",
        "version": "1.0.0",
        "description": "Python Flask REST API for SBOM master's thesis"
    })


@app.route("/api/data", methods=["POST"])
def data():
    body = request.get_json(force=True)
    return jsonify({"received": body}), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
