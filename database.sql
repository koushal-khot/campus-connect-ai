-- Campus Connect AI - Phase 1 schema (SQLite)
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name     TEXT    NOT NULL,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('student', 'faculty', 'admin')),
    status        TEXT    NOT NULL DEFAULT 'approved'
                          CHECK (status IN ('pending', 'approved', 'rejected')),
    branch        TEXT,                -- e.g. CSE, ECE
    year          INTEGER CHECK (year BETWEEN 1 AND 5),
    skills        TEXT,                -- comma-separated: "Python, Flask, SQL"
    bio           TEXT,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS projects (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title        TEXT    NOT NULL,
    description  TEXT    NOT NULL,
    tech_stack   TEXT,                 -- comma-separated
    looking_for  TEXT,                 -- skills the team still needs
    github_url   TEXT,
    status       TEXT    NOT NULL DEFAULT 'open'
                         CHECK (status IN ('open', 'in_progress', 'completed')),
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS announcements (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       TEXT    NOT NULL,
    body        TEXT    NOT NULL,
    category    TEXT    NOT NULL DEFAULT 'general'
                        CHECK (category IN ('general', 'research', 'lab', 'event')),
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_projects_owner      ON projects(owner_id);
CREATE INDEX IF NOT EXISTS idx_projects_created    ON projects(created_at);
CREATE INDEX IF NOT EXISTS idx_announcements_date  ON announcements(created_at);
