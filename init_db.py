"""Create campus_connect.db from database.sql and add demo accounts.

Run once:  python init_db.py
Re-running is safe: existing demo rows are left alone.
"""
import os
import sqlite3

from werkzeug.security import generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "campus_connect.db")
SCHEMA = os.path.join(BASE_DIR, "database.sql")

DEMO_USERS = [
    # full_name, email, password, role, branch, year, skills, bio
    ("Campus Admin", "admin@campus.edu", "admin123", "admin", None, None, None, None),
    ("Dr. Meera Kulkarni", "faculty@campus.edu", "faculty123", "faculty",
     "CSE", None, "Machine Learning, Databases", "Mentors final-year and research projects."),
    ("Aarav Patil", "student@campus.edu", "student123", "student",
     "CSE", 2, "Python, Flask, HTML/CSS", "Likes building small web tools."),
]


def main():
    conn = sqlite3.connect(DATABASE)
    conn.execute("PRAGMA foreign_keys = ON")
    with open(SCHEMA, encoding="utf-8") as f:
        conn.executescript(f.read())
    
    
    for name, email, pw, role, branch, year, skills, bio in DEMO_USERS:
        conn.execute(
            """INSERT OR IGNORE INTO users
               (full_name, email, password_hash, role, status, branch, year, skills, bio)
               VALUES (?, ?, ?, ?, 'approved', ?, ?, ?, ?)""",
            (name, email, generate_password_hash(pw), role, branch, year, skills, bio),
        )

    conn.execute(
        """INSERT OR IGNORE INTO users
           (full_name, email, password_hash, role, status, branch, year, skills)
           VALUES ('Riya Deshmukh', 'riya@campus.edu', ?, 'student', 'pending',
                   'ECE', 2, 'Embedded C, IoT')""",
        (generate_password_hash("riya12345"),),
    )

    faculty = conn.execute("SELECT id FROM users WHERE email = 'faculty@campus.edu'").fetchone()
    student = conn.execute("SELECT id FROM users WHERE email = 'student@campus.edu'").fetchone()

    if conn.execute("SELECT COUNT(*) FROM announcements").fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO announcements (author_id, title, body, category) VALUES (?, ?, ?, ?)",
            (faculty[0], "Research assistants wanted: ML lab",
             "The ML lab is taking two 2nd/3rd year students for a data-labelling and "
             "model-evaluation project. Basic Python is enough to start.", "research"),
        )
        conn.execute(
            "INSERT INTO announcements (author_id, title, body, category) VALUES (?, ?, ?, ?)",
            (faculty[0], "Project proposal review slots open",
             "Book a 15-minute slot to get feedback on your project idea before the "
             "end of the month.", "general"),
        )

    if conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 0:
        conn.execute(
            """INSERT INTO projects (owner_id, title, description, tech_stack, looking_for)
               VALUES (?, ?, ?, ?, ?)""",
            (student[0], "Bus Tracker for Campus",
             "Live location of college buses on a simple map so students stop waiting at the gate.",
             "Flask, SQLite, Leaflet.js", "Android, UI design"),
        )

    conn.commit()
    conn.close()
    print(f"Database ready at {DATABASE}")
    print("Demo logins: student@campus.edu / student123, "
          "faculty@campus.edu / faculty123, admin@campus.edu / admin123")
    print("Delete or change these demo accounts before deploying anywhere public.")

if __name__ == "__main__":
    main()
