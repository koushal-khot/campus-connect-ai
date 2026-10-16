"""Campus Connect AI - Phase 2: secure user authentication.

Adds to Phase 1:
  * registration for Student / Faculty / Admin (admin needs an invite code)
  * Werkzeug password hashing, password rules, generic login errors
  * login throttling, safe "next" redirects, POST-only logout
  * CSRF protection on every POST form, hardened session cookies
"""
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, flash, g, redirect, render_template, request,
                   session, url_for, abort)
from werkzeug.security import check_password_hash, generate_password_hash

try:  # optional: read SECRET_KEY etc. from a local .env file
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "campus_connect.db")

# ---------- settings ----------
ROLES = ("student", "faculty", "admin")
ANNOUNCEMENT_CATEGORIES = ("general", "research", "lab", "event")
VERDICTS = ("approved", "needs_changes", "mentoring")
REQUIRE_APPROVAL = os.environ.get("REQUIRE_APPROVAL", "false").lower() == "true"
ADMIN_INVITE_CODE = os.environ.get("ADMIN_INVITE_CODE", "")
MAX_FAILED_ATTEMPTS = 5          # wrong passwords / codes allowed ...
LOCKOUT_SECONDS = 600            # ... within this window (10 minutes)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or "dev-only-change-me",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=1024 * 1024,
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Checked against when the email is unknown, so response time doesn't reveal
# which emails are registered.
DUMMY_HASH = generate_password_hash("not-a-real-password")


# ---------- database ----------
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


# ---------- CSRF protection ----------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_from_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("_csrf", "")
        if not expected or not secrets.compare_digest(sent.encode(), expected.encode()):
            abort(400)


@app.errorhandler(400)
def bad_request(_err):
    flash("That page expired. Please try again.", "error")
    return redirect(url_for("login"))


# ---------- current user, headers ----------
@app.before_request
def load_current_user():
    """Load the logged-in user fresh from the DB on every request, so a
    deleted or un-approved account loses access immediately."""
    g.user = None
    if request.endpoint == "static":
        return
    uid = session.get("user_id")
    if uid is not None:
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if user is not None and user["status"] == "approved":
            g.user = user
        else:
            session.clear()


@app.context_processor
def inject_user():
    return {"current_user": g.get("user")}


@app.after_request
def set_security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"  # no back-button after logout
    return resp


# ---------- access control ----------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in to continue.", "error")
            nxt = request.path if request.method == "GET" else None
            return redirect(url_for("login", next=nxt))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] not in roles:
                flash("You don't have access to that page.", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ---------- throttling (in memory: resets when the server restarts) ----------
_failures = defaultdict(deque)


def _prune(key):
    q, now = _failures[key], time.time()
    while q and now - q[0] > LOCKOUT_SECONDS:
        q.popleft()
    return q


def is_locked(key):
    return len(_prune(key)) >= MAX_FAILED_ATTEMPTS


def record_failure(key):
    _prune(key).append(time.time())


def clear_failures(key):
    _failures.pop(key, None)


# ---------- validation helpers ----------
def validate_password(password):
    if len(password) < 8:
        return "Use a password with at least 8 characters."
    if len(password) > 128:
        return "Use a password with at most 128 characters."
    if not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
        return "Include at least one letter and one number in your password."
    return None


def check_admin_code(code):
    if not ADMIN_INVITE_CODE:
        return "Admin sign-up is turned off. Ask your IT team for an invite code."
    key = f"admin-code|{request.remote_addr}"
    if is_locked(key):
        return "Too many wrong codes. Try again in a few minutes."
    if not secrets.compare_digest(code.encode(), ADMIN_INVITE_CODE.encode()):
        record_failure(key)
        return "That invite code is not valid."
    clear_failures(key)
    return None


def safe_next(target):
    """Only allow redirects to paths on this site (blocks open redirects)."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return None
    parts = urlparse(target)
    if parts.scheme or parts.netloc:
        return None
    return target


# ---------- template filters ----------
@app.template_filter("csv")
def csv_filter(value):
    """'Python, Flask' -> ['Python', 'Flask'] (used for skill chips)."""
    return [p.strip() for p in (value or "").split(",") if p.strip()]


@app.template_filter("day")
def day_filter(value):
    """'2026-10-10 12:30:00' -> '10 Oct 2026'."""
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime("%d %b %Y")
    except (TypeError, ValueError):
        return value or ""


# ---------- auth routes ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if g.user else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))

    form = {}
    if request.method == "POST":
        form = request.form
        full_name = form.get("full_name", "").strip()
        email = form.get("email", "").strip().lower()
        password = form.get("password", "")
        confirm = form.get("confirm_password", "")
        role = form.get("role", "")
        branch = form.get("branch", "").strip()[:50]
        year = form.get("year", "").strip()
        admin_code = form.get("admin_code", "")

        error = None
        if not full_name or len(full_name) > 100:
            error = "Enter your full name (up to 100 characters)."
        elif not EMAIL_RE.match(email) or len(email) > 254:
            error = "Enter a valid email address."
        elif role not in ROLES:
            error = "Choose Student, Faculty, or Admin."
        elif validate_password(password):
            error = validate_password(password)
        elif password != confirm:
            error = "The two passwords don't match."
        elif role == "student" and year and (not year.isdigit() or not 1 <= int(year) <= 5):
            error = "Year must be between 1 and 5."
        elif role == "admin":
            error = check_admin_code(admin_code)

        if error is None:
            # Admins are verified by the invite code; others may need approval.
            status = "pending" if (REQUIRE_APPROVAL and role != "admin") else "approved"
            try:
                db = get_db()
                db.execute(
                    """INSERT INTO users
                       (full_name, email, password_hash, role, status, branch, year)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (full_name, email, generate_password_hash(password), role, status,
                     branch or None,
                     int(year) if role == "student" and year else None),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "An account with this email already exists."
            else:
                if status == "pending":
                    flash("Account created. An admin must approve it before you can log in.",
                          "success")
                else:
                    flash("Account created. Log in to get started.", "success")
                return redirect(url_for("login"))

        flash(error, "error")

    return render_template("register.html", form=form,
                           admin_enabled=bool(ADMIN_INVITE_CODE))


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))

    next_url = request.values.get("next", "")
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        key = f"login|{request.remote_addr}|{email}"

        if is_locked(key):
            flash("Too many failed attempts. Try again in 10 minutes.", "error")
        else:
            user = get_db().execute(
                "SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            password_ok = check_password_hash(
                user["password_hash"] if user else DUMMY_HASH, password)

            if user is None or not password_ok:
                record_failure(key)
                flash("Email or password is incorrect.", "error")
            elif user["status"] == "pending":
                flash("Your account is waiting for admin approval.", "error")
            elif user["status"] == "rejected":
                flash("Your registration wasn't approved. Contact your college admin.", "error")
            else:
                clear_failures(key)
                session.clear()                  # new session id/CSRF token on login
                session.permanent = True
                session["user_id"] = user["id"]
                return redirect(safe_next(next_url) or url_for("dashboard"))

    return render_template("login.html", next_url=safe_next(next_url) or "")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You're logged out.", "success")
    return redirect(url_for("login"))


# ---------- dashboards ----------
@app.route("/dashboard")
@login_required
def dashboard():
    if g.user["role"] == "student":
        return redirect(url_for("student_dashboard"))
    return render_template("coming_soon.html", role=g.user["role"])


@app.route("/student/dashboard")
@role_required("student")
def student_dashboard():
    db = get_db()
    uid = g.user["id"]

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
    return render_template("student_dashboard.html", user=g.user,
                           announcements=announcements, projects=projects, stats=stats)


@app.route("/student/profile", methods=["POST"])
@role_required("student")
def update_profile():
    year = request.form.get("year", "").strip()
    if year and (not year.isdigit() or not 1 <= int(year) <= 5):
        flash("Year must be between 1 and 5.", "error")
        return redirect(url_for("student_dashboard"))

    db = get_db()
    db.execute(
        "UPDATE users SET branch = ?, year = ?, skills = ?, bio = ? WHERE id = ?",
        (request.form.get("branch", "").strip() or None,
         int(year) if year else None,
         request.form.get("skills", "").strip() or None,
         request.form.get("bio", "").strip() or None,
         g.user["id"]),
    )
    db.commit()
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
        (g.user["id"], title, description,
         request.form.get("tech_stack", "").strip() or None,
         request.form.get("looking_for", "").strip() or None,
         request.form.get("github_url", "").strip() or None),
    )
    db.commit()
    flash("Project posted.", "success")
    return redirect(url_for("student_dashboard"))
# ---------- faculty ----------
@app.route("/faculty/dashboard")
@role_required("faculty")
def faculty_dashboard():
    db = get_db()
    uid = g.user["id"]

    my_announcements = db.execute(
        "SELECT * FROM announcements WHERE author_id = ? ORDER BY created_at DESC, id DESC",
        (uid,)).fetchall()
    # Projects nobody has reviewed yet come first, then newest.
    projects = db.execute(
        """SELECT p.*, u.full_name AS owner_name, u.branch AS owner_branch,
                  u.year AS owner_year,
                  r.verdict AS review_verdict, r.comment AS review_comment,
                  f.full_name AS reviewer_name
           FROM projects p JOIN users u ON u.id = p.owner_id
           LEFT JOIN project_reviews r
                  ON r.id = (SELECT MAX(id) FROM project_reviews WHERE project_id = p.id)
           LEFT JOIN users f ON f.id = r.faculty_id
           ORDER BY (r.id IS NULL) DESC, p.created_at DESC, p.id DESC LIMIT 50"""
    ).fetchall()
    stats = {
        "unreviewed": db.execute(
            """SELECT COUNT(*) FROM projects p
               WHERE NOT EXISTS (SELECT 1 FROM project_reviews WHERE project_id = p.id)"""
        ).fetchone()[0],
        "my_reviews": db.execute(
            "SELECT COUNT(*) FROM project_reviews WHERE faculty_id = ?", (uid,)).fetchone()[0],
        "my_announcements": len(my_announcements),
    }
    return render_template("faculty_dashboard.html", projects=projects,
                           my_announcements=my_announcements, stats=stats,
                           categories=ANNOUNCEMENT_CATEGORIES, verdicts=VERDICTS)


@app.route("/faculty/announcements", methods=["POST"])
@role_required("faculty")
def create_announcement():
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    category = request.form.get("category", "general")

    if not title or len(title) > 120:
        flash("Add a title (up to 120 characters).", "error")
    elif not body or len(body) > 1000:
        flash("Add the announcement text (up to 1000 characters).", "error")
    elif category not in ANNOUNCEMENT_CATEGORIES:
        flash("Pick a valid category.", "error")
    else:
        db = get_db()
        db.execute(
            "INSERT INTO announcements (author_id, title, body, category) VALUES (?, ?, ?, ?)",
            (g.user["id"], title, body, category))
        db.commit()
        flash("Announcement posted. Students can see it now.", "success")
    return redirect(url_for("faculty_dashboard"))


@app.route("/faculty/announcements/<int:announcement_id>/delete", methods=["POST"])
@role_required("faculty")
def delete_announcement(announcement_id):
    db = get_db()
    # author_id in the WHERE clause: faculty can only delete their own posts
    cur = db.execute("DELETE FROM announcements WHERE id = ? AND author_id = ?",
                     (announcement_id, g.user["id"]))
    db.commit()
    flash("Announcement deleted." if cur.rowcount else "Announcement not found.",
          "success" if cur.rowcount else "error")
    return redirect(url_for("faculty_dashboard"))


@app.route("/faculty/projects/<int:project_id>/review", methods=["POST"])
@role_required("faculty")
def review_project(project_id):
    verdict = request.form.get("verdict", "")
    comment = request.form.get("comment", "").strip()
    db = get_db()

    if db.execute("SELECT 1 FROM projects WHERE id = ?", (project_id,)).fetchone() is None:
        flash("That project no longer exists.", "error")
    elif verdict not in VERDICTS:
        flash("Choose a verdict for the project.", "error")
    elif not comment or len(comment) > 1000:
        flash("Write some feedback (up to 1000 characters).", "error")
    else:
        db.execute(
            "INSERT INTO project_reviews (project_id, faculty_id, verdict, comment) "
            "VALUES (?, ?, ?, ?)", (project_id, g.user["id"], verdict, comment))
        db.commit()
        flash("Feedback sent to the student.", "success")
    return redirect(url_for("faculty_dashboard"))



if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        print("Database not found. Run `python init_db.py` first.")
    if app.config["SECRET_KEY"] == "dev-only-change-me":
        print("Warning: using the default SECRET_KEY. Set one in .env before deploying.")
    app.run(debug=True)
