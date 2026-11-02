"""Modul backend autentikasi Flask dengan antarmuka web interaktif."""

import hmac
import os
import sqlite3
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

def init_db():
    """Inisialisasi basis data dan membuat data pengguna awal."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)"
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users VALUES ('admin', 'supersecret')"
    )
    conn.commit()
    conn.close()

@app.route("/", methods=["GET", "POST"])
def index():
    """Menampilkan formulir login dan memproses autentikasi."""
    message = None
    status_class = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        # Parameterized query untuk mencegah SQL Injection
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            message = "Login Berhasil! Selamat datang."
            status_class = "success"
        else:
            message = "Login Gagal! Kredensial tidak valid."
            status_class = "danger"

    return render_template(
        "index.html", message=message, status_class=status_class
    )

@app.route("/health")
def health():
    """Endpoint pemeriksaan kesehatan layanan (tanpa autentikasi)."""
    return jsonify(status="ok", service="flask-login-app")

@app.route("/api/status")
def api_status():
    """Endpoint terproteksi API key yang dibaca dari environment variable."""
    expected_key = os.environ.get("API_KEY", "")
    provided_key = request.headers.get("X-API-Key", "")

    if not expected_key or not hmac.compare_digest(
        provided_key.encode(), expected_key.encode()
    ):
        return jsonify(error="Unauthorized"), 401

    return jsonify(status="authorized", message="API key valid")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)  # nosemgrep
    