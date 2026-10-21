
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-to-a-random-secret-key"

DATABASE = "users.db"


# Connect to the database
def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


# Create the users table
def create_table():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        """)


# Landing page
@app.route("/")
def home():
    return render_template("index.html")


# Sign up
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if not name or not email or not password:
            flash("Please fill in all fields.")
            return redirect(url_for("signup"))

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return redirect(url_for("signup"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("signup"))

        try:
            with get_db() as db:
                cursor = db.execute(
                    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                    (name, email, generate_password_hash(password))
                )
                user_id = cursor.lastrowid

            session.clear()
            session["user_id"] = user_id
            return redirect(url_for("dashboard"))

        except sqlite3.IntegrityError:
            flash("This email is already registered.")
            return redirect(url_for("signup"))

    return render_template("signup.html")


# Sign in
@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))

        flash("Incorrect email or password.")

    return render_template("signin.html")


# Dashboard
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("signin"))

    with get_db() as db:
        user = db.execute(
            "SELECT id, name, email FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

    if user is None:
        session.clear()
        return redirect(url_for("signin"))

    return render_template("dashboard.html", user=user)


# Logout
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    create_table()
    app.run(port=5001, debug=True)
