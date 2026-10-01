from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from pathlib import Path
from functools import wraps
import secrets
import hashlib
from datetime import datetime, timedelta, timezone


app = Flask(__name__)
app.secret_key = "abantuverse"


DB_PATH = Path(__file__).with_name("auth.db")
TOKEN_PATH = Path(__file__).with_name("tokens.db")


def get_token():
    db = sqlite3.connect(TOKEN_PATH)
    db.row_factory = sqlite3.Row
    return db


def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("signin"))

        return view(*args, **kwargs)

    return wrapped_view


@app.cli.command("init-db")
def init_db():
    db = get_db()

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            reset_token TEXT,
            reset_token_expires TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    db.commit()
    db.close()

    print("Database is now active.")

    tb = get_token()

    tb.execute(
        """
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    tb.commit()
    tb.close()

    print("Tokens are now live.")


def get_current_user():

    if "user_id" not in session:
        return None

    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    db.close()

    return user


@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not email or not password or not confirm_password:
            return "All fields are required."

        if password != confirm_password:
            return "Passwords do not match."

        if len(password) < 8:
            return "Password must be at least 8 characters."

        if not any(char.isupper() for char in password):
            return "Password must contain at least one uppercase letter."

        if not any(char.islower() for char in password):
            return "Password must contain at least one lowercase letter."

        if not any(char.isdigit() for char in password):
            return "Password must contain at least one number."

        if not any(not char.isalnum() for char in password):
            return "Password must contain at least one special character."

        password_hash = generate_password_hash(password)

        db = get_db()

        existing_user = db.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if existing_user:
            db.close()
            return "An account with this email already exists."

        db.execute(
            """
            INSERT INTO users (name, email, password)
            VALUES (?, ?, ?)
            """,
            (name, email, password_hash)
        )

        db.commit()
        db.close()

        return "Account successfully created."

    return render_template("signup.html")


@app.route("/signin", methods=["GET", "POST"])
def signin():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        db.close()

        if user is None:
            return "Invalid email or password."

        if not check_password_hash(user["password"], password):
            return "Invalid email or password."

        session["user_id"] = user["id"]

        return "Welcome back."

    return render_template("signin.html")


@app.route("/dashboard")
@login_required
def dashboard():

    user = get_current_user()

    return render_template("board.html", user=user)


@app.route("/")
@login_required
def home():

    return render_template("home.html")


@app.route("/signout")
def signout():

    session.clear()

    print("session expired.")

    return redirect(url_for("signin"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        db.close()

        if user is None:
            return "If that email exists, a reset link has been sent."

       
        token = secrets.token_urlsafe(32)

        
        token_hash = hashlib.sha256(
            token.encode()
        ).hexdigest()

       
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

        
        tb = get_token()

        tb.execute(
            """
            INSERT INTO tokens
            (user_id, token_hash, expires_at)
            VALUES (?, ?, ?)
            """,
            (
                user["id"],
                token_hash,
                expires_at.isoformat()
            )
        )

        tb.commit()
        tb.close()

       
        reset_url = url_for(
            "reset_password",
            token=token,
            _external=True
        )

       
        print(reset_url)

        return "Reset token created."

    return render_template("forgot.html")