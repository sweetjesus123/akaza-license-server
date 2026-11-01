# language: Python 3.10+, file: server.py
# deps: flask
from flask import Flask, request, jsonify
import hashlib
import hmac
import sqlite3
import os

app = Flask(__name__)
SECRET_KEY = b"x7Pq9mK2vL8nR4tF6jH3wY5bN1cD0sA_akaza_zuma"   # CHANGE THIS before deploying
ADMIN_PASSWORD = "AkazaZuma2026!Secure"                # CHANGE THIS before deploying
DB_FILE = "licenses.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("CREATE TABLE IF NOT EXISTS allowed_hwids (hwid TEXT PRIMARY KEY)")
    conn.commit()
    conn.close()

init_db()

@app.route("/", methods=["GET"])
def home():
    return "AKAZA License Server Online"

@app.route("/check", methods=["POST"])
def check_license():
    data = request.json or {}
    hwid = data.get("hwid")
    if not hwid:
        return jsonify({"status": "error", "message": "No HWID"}), 400
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute("SELECT hwid FROM allowed_hwids WHERE hwid = ?", (hwid,)).fetchone()
    conn.close()
    if row:
        sig = hmac.new(SECRET_KEY, hwid.encode(), hashlib.sha256).hexdigest()
        return jsonify({"status": "valid", "signature": sig})
    return jsonify({"status": "invalid", "message": "HWID not authorized"}), 403

@app.route("/add", methods=["POST"])
def add_license():
    data = request.json or {}
    if data.get("admin_pass") != ADMIN_PASSWORD:
        return jsonify({"status": "error"}), 401
    hwid = data.get("hwid")
    if not hwid:
        return jsonify({"status": "error", "message": "No HWID"}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute("INSERT INTO allowed_hwids (hwid) VALUES (?)", (hwid,))
        conn.commit()
        return jsonify({"status": "success"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "already_exists"})
    finally:
        conn.close()

@app.route("/list", methods=["POST"])
def list_licenses():
    data = request.json or {}
    if data.get("admin_pass") != ADMIN_PASSWORD:
        return jsonify({"status": "error"}), 401
    conn = sqlite3.connect(DB_FILE)
    rows = [r[0] for r in conn.execute("SELECT hwid FROM allowed_hwids").fetchall()]
    conn.close()
    return jsonify({"count": len(rows), "hwids": rows})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
