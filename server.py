# language: Python 3.10+, file: server.py
from flask import Flask, request, jsonify
import hashlib
import hmac
import sqlite3
import os
import secrets
import string

app = Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY", "x7Pq9mK2vL8nR4tF6jH3wY5bN1cD0sA_akaza_zuma").encode()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "AkazaZuma2026!Secure")
DB_FILE = "licenses.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            hwid TEXT,
            license_key TEXT UNIQUE,
            activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
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
    key = data.get("license_key")
    
    if not hwid:
        return jsonify({"status": "error", "message": "No HWID"}), 400

    conn = sqlite3.connect(DB_FILE)
    
    if key:
        row = conn.execute("SELECT hwid, license_key FROM licenses WHERE license_key = ?", (key,)).fetchone()
        if row:
            bound_hwid, bound_key = row
            if bound_hwid is None:
                # Key exists but not used yet — bind it to this HWID
                conn.execute("UPDATE licenses SET hwid = ? WHERE license_key = ?", (hwid, key))
                conn.commit()
                conn.close()
                sig = hmac.new(SECRET_KEY, hwid.encode(), hashlib.sha256).hexdigest()
                return jsonify({"status": "valid", "signature": sig})
            elif bound_hwid == hwid:
                conn.close()
                sig = hmac.new(SECRET_KEY, hwid.encode(), hashlib.sha256).hexdigest()
                return jsonify({"status": "valid", "signature": sig})
            else:
                conn.close()
                return jsonify({"status": "invalid", "message": "This key is already in use on another computer."}), 403
        else:
            conn.close()
            return jsonify({"status": "invalid", "message": "Invalid license key."}), 403
    else:
        row = conn.execute("SELECT hwid FROM licenses WHERE hwid = ?", (hwid,)).fetchone()
        conn.close()
        if row:
            sig = hmac.new(SECRET_KEY, hwid.encode(), hashlib.sha256).hexdigest()
            return jsonify({"status": "valid", "signature": sig})
        return jsonify({"status": "need_key", "message": "Please enter a license key."}), 401

@app.route("/generate", methods=["POST"])
def generate_keys():
    data = request.json or {}
    if data.get("admin_pass") != ADMIN_PASSWORD:
        return jsonify({"status": "error"}), 401
    
    count = data.get("count", 1)
    keys = []
    conn = sqlite3.connect(DB_FILE)
    for _ in range(count):
        part1 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
        part2 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
        new_key = f"AKAZA-{part1}-{part2}"
        conn.execute("INSERT INTO licenses (hwid, license_key) VALUES (NULL, ?)", (new_key,))
        keys.append(new_key)
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "keys": keys})

@app.route("/add", methods=["POST"])
def add_license():
    # Kept for backward compat — but the new key system doesn't need it
    data = request.json or {}
    if data.get("admin_pass") != ADMIN_PASSWORD:
        return jsonify({"status": "error"}), 401
    hwid = data.get("hwid")
    key = data.get("license_key")
    if not hwid or not key:
        return jsonify({"status": "error"}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute("DELETE FROM licenses WHERE hwid = ?", (hwid,))
        conn.execute("INSERT INTO licenses (hwid, license_key) VALUES (?, ?)", (hwid, key))
        conn.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    finally:
        conn.close()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
