CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name     TEXT    NOT NULL,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('student', 'faculty', 'admin')),
    status        TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    branch        TEXT,
    year          INTEGER,
    skills        TEXT,
    bio           TEXT,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       TEXT    NOT NULL,
    description TEXT    NOT NULL,
    tech_stack  TEXT    NOT NULL,
    looking_for TEXT,
    github_link TEXT,
    status      TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'completed')),
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS announcements (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       TEXT    NOT NULL,
    body        TEXT    NOT NULL,
    category    TEXT    NOT NULL DEFAULT 'general'
                        CHECK (category IN ('general', 'research', 'lab', 'event')),
    is_broadcast INTEGER DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS project_reviews (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    faculty_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    feedback    TEXT    NOT NULL,
    rating      INTEGER,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);