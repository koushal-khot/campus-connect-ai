"""Campus Connect AI - Phase 1 (auth + student dashboard)."""
import os
import re
import sqlite3
from functools import wraps

from flask import (Flask, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "campus_connect.db")

# Phase 1: no admin screen exists yet, so new accounts are approved instantly.
# Set to True in Phase 5 (admin panel) to hold registrations as 'pending'.
REQUIRE_APPROVAL = False

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------- database helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------- auth helpers ----------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                flash("You don't have access to that page.", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.template_filter("csv")
def csv_filter(value):
    """'Python, Flask' -> ['Python', 'Flask'] (used for skill chips)."""
    return [p.strip() for p in (value or "").split(",") if p.strip()]


@app.template_filter("day")
def day_filter(value):
    """'2026-10-10 12:30:00' -> '10 Oct 2026'."""
    from datetime import datetime
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime("%d %b %Y")
    except (TypeError, ValueError):
        return value or ""


# ---------- public routes ----------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "student")
        branch = request.form.get("branch", "").strip()
        year = request.form.get("year", "").strip()

        error = None
        if not full_name:
            error = "Enter your full name."
        elif not EMAIL_RE.match(email):
            error = "Enter a valid email address."
        elif len(password) < 6:
            error = "Use a password with at least 6 characters."
        elif role not in ("student", "faculty"):
            error = "Choose student or faculty."
        elif role == "student" and year and (not year.isdigit() or not 1 <= int(year) <= 5):
            error = "Year must be between 1 and 5."

        if error is None:
            db = get_db()
            if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                error = "An account with this email already exists."
            else:
                status = "pending" if REQUIRE_APPROVAL else "approved"
                db.execute(
                    """INSERT INTO users
                       (full_name, email, password_hash, role, status, branch, year)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (full_name, email, generate_password_hash(password), role, status,
                     branch or None, int(year) if role == "student" and year else None),
                )
                db.commit()
                flash("Account created. Log in to get started.", "success")
                return redirect(url_for("login"))

        flash(error, "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Email or password is incorrect.", "error")
        elif user["status"] == "pending":
            flash("Your account is waiting for admin approval.", "error")
        elif user["status"] == "rejected":
            flash("Your registration was not approved. Contact your college admin.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["name"] = user["full_name"]
            return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You're logged out.", "success")
    return redirect(url_for("login"))


# ---------- dashboards ----------
@app.route("/dashboard")
@login_required
def dashboard():
    if session["role"] == "student":
        return redirect(url_for("student_dashboard"))
    return render_template("coming_soon.html", role=session["role"])


@app.route("/student/dashboard")
@role_required("student")
def student_dashboard():
    db = get_db()
    uid = session["user_id"]

    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    announcements = db.execute(
        """SELECT a.*, u.full_name AS author_name
           FROM announcements a JOIN users u ON u.id = a.author_id
           ORDER BY a.created_at DESC, a.id DESC LIMIT 5"""
    ).fetchall()
    projects = db.execute(
        """SELECT p.*, u.full_name AS owner_name
           FROM projects p JOIN users u ON u.id = p.owner_id
           ORDER BY p.created_at DESC, p.id DESC LIMIT 20"""
    ).fetchall()
    stats = {
        "my_projects": db.execute(
            "SELECT COUNT(*) FROM projects WHERE owner_id = ?", (uid,)).fetchone()[0],
        "open_projects": db.execute(
            "SELECT COUNT(*) FROM projects WHERE status = 'open'").fetchone()[0],
        "students": db.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'student' AND status = 'approved'"
        ).fetchone()[0],
    }
    return render_template("student_dashboard.html", user=user,
                           announcements=announcements, projects=projects, stats=stats)


@app.route("/student/profile", methods=["POST"])
@role_required("student")
def update_profile():
    year = request.form.get("year", "").strip()
    if year and (not year.isdigit() or not 1 <= int(year) <= 5):
        flash("Year must be between 1 and 5.", "error")
        return redirect(url_for("student_dashboard"))

    get_db().execute(
        "UPDATE users SET branch = ?, year = ?, skills = ?, bio = ? WHERE id = ?",
        (request.form.get("branch", "").strip() or None,
         int(year) if year else None,
         request.form.get("skills", "").strip() or None,
         request.form.get("bio", "").strip() or None,
         session["user_id"]),
    )
    get_db().commit()
    flash("Profile saved.", "success")
    return redirect(url_for("student_dashboard"))


@app.route("/student/projects", methods=["POST"])
@role_required("student")
def create_project():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    if not title or not description:
        flash("Add a title and a short description for your project.", "error")
        return redirect(url_for("student_dashboard"))

    db = get_db()
    db.execute(
        """INSERT INTO projects (owner_id, title, description, tech_stack, looking_for, github_url)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (session["user_id"], title, description,
         request.form.get("tech_stack", "").strip() or None,
         request.form.get("looking_for", "").strip() or None,
         request.form.get("github_url", "").strip() or None),
    )
    db.commit()
    flash("Project posted.", "success")
    return redirect(url_for("student_dashboard"))


if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        print("Database not found. Run `python init_db.py` first.")
    app.run(debug=True)
