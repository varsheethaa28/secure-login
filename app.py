
from flask import Flask, request, redirect, session, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import pyotp
import time
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this-key")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["20 per minute"],
    storage_uri="memory://"
)

DB = "users.db"
MAX_ATTEMPTS = 3
LOCK_SECONDS = 60

def connect():
    return sqlite3.connect(DB)

def setup_database():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                otp_secret TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                locked_until REAL DEFAULT 0
            )
        """)

setup_database()

PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Secure Login System</title>
<style>
body {
    font-family: Arial;
    background: #101827;
    color: white;
    text-align: center;
    padding: 40px;
}
.box {
    background: #1e293b;
    padding: 30px;
    margin: 30px auto;
    max-width: 380px;
    border-radius: 12px;
}
input {
    display: block;
    width: 90%;
    padding: 12px;
    margin: 12px auto;
    border-radius: 6px;
    border: none;
}
button {
    padding: 12px 25px;
    background: #2563eb;
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
}
a { color: #60a5fa; }
.message { color: #fbbf24; }
</style>
</head>
<body>
<div class="box">
<h1>Secure Login</h1>
<p class="message">{{ message }}</p>

{% if page == 'home' %}
<a href="/register">Register</a> |
<a href="/login">Login</a>

{% elif page == 'register' %}
<form method="POST">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button>Register</button>
</form>

{% elif page == 'login' %}
<form method="POST">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button>Login</button>
</form>

{% elif page == 'mfa' %}
<form method="POST">
<input name="otp" placeholder="6-digit OTP" required>
<button>Verify OTP</button>
</form>

{% elif page == 'dashboard' %}
<h2>Welcome, {{ username }}!</h2>
<p>Your account is protected.</p>
<a href="/logout">Logout</a>
{% endif %}
</div>
</body>
</html>
"""

def page(name, message="", username=""):
    return render_template_string(
        PAGE, page=name, message=message, username=username
    )

@app.route("/")
def home():
    return page("home", "Welcome to Secure Login System")

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if len(username) < 3 or len(password) < 8:
            return page("register", "Username needs 3 characters and password needs 8.")

        secret = pyotp.random_base32()
        hashed = generate_password_hash(password)

        try:
            with connect() as db:
                db.execute(
                    "INSERT INTO users (username, password, otp_secret) VALUES (?, ?, ?)",
                    (username, hashed, secret)
                )
        except sqlite3.IntegrityError:
            return page("register", "Username already exists.")

        session["setup_secret"] = secret
        session["setup_user"] = username

        return (
            f"<h2>Registration successful!</h2>"
            f"<p>Save this MFA secret in your authenticator app:</p>"
            f"<h3>{secret}</h3>"
            f"<p>Enter it in an authenticator app such as Google Authenticator.</p>"
            f'<a href="/login">Continue to Login</a>'
        )

    return page("register", "Create your account")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        with connect() as db:
            user = db.execute(
                "SELECT password, otp_secret, failed_attempts, locked_until FROM users WHERE username=?",
                (username,)
            ).fetchone()

            if not user:
                return page("login", "Invalid username or password.")

            hashed, secret, attempts, locked_until = user

            if time.time() < locked_until:
                return page("login", "Account locked. Try again later.")

            if not check_password_hash(hashed, password):
                attempts += 1
                new_lock = time.time() + LOCK_SECONDS if attempts >= MAX_ATTEMPTS else 0

                db.execute(
                    "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
                    (attempts, new_lock, username)
                )

                if new_lock:
                    return page("login", "Account locked for 60 seconds.")

                return page("login", f"Incorrect password. Attempts: {attempts}/{MAX_ATTEMPTS}")

            db.execute(
                "UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?",
                (username,)
            )

        session["pending_user"] = username
        session["pending_secret"] = secret
        return redirect("/mfa")

    return page("login", "Enter your login credentials")

@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    username = session.get("pending_user")
    secret = session.get("pending_secret")

    if not username or not secret:
        return redirect("/login")

    if request.method == "POST":
        otp = request.form["otp"].strip()

        if pyotp.TOTP(secret).verify(otp, valid_window=1):
            session.clear()
            session["username"] = username
            return redirect("/dashboard")

        return page("mfa", "Invalid OTP. Try again.")

    return page("mfa", "Enter the current code from your authenticator app")

@app.route("/dashboard")
def dashboard():
    username = session.get("username")

    if not username:
        return redirect("/login")

    return page("dashboard", "Login successful!", username)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
