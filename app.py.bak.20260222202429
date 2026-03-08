# /var/www/tasklist/app.py

import os
import json
import base64
import uuid
import hashlib
import logging
import sqlite3
from datetime import datetime, date, timedelta, timezone
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, g
from dotenv import load_dotenv
import bleach

# Load environment variables from .env
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tasklist")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "tasks.db")

# Keep your original static URL behavior
app = Flask(__name__, static_url_path="/tasks/static", static_folder="static")
app.secret_key = os.getenv("SECRET_KEY", "change-me")

app.config["SESSION_COOKIE_DOMAIN"] = ".blahpunk.com"
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["PREFERRED_URL_SCHEME"] = "https"

# --- Sanitization (Bleach) ---
ALLOWED_TAGS = [
    "p", "br", "strong", "em", "u", "s",
    "ul", "ol", "li",
    "blockquote",
    "h1", "h2", "h3",
    "a",
    "code", "pre",
    "span",
]
ALLOWED_ATTRIBUTES = {
    "a": ["href", "title", "target", "rel"],
    "span": ["class"],
}
ALLOWED_PROTOCOLS = ["http", "https", "mailto"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def iso_date_today() -> date:
    return datetime.now().date()


def parse_iso_date(d: Optional[str]) -> Optional[date]:
    if not d:
        return None
    try:
        return date.fromisoformat(d)
    except Exception:
        return None


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def user_storage_id(email: str) -> str:
    email_n = normalize_email(email)
    return hashlib.sha256(email_n.encode("utf-8")).hexdigest()


def sanitize_html(html: str) -> str:
    cleaned = bleach.clean(
        html or "",
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
    )
    cleaned = bleach.linkify(cleaned or "")
    return cleaned


def html_to_text(html: str) -> str:
    # Very simple strip; sanitize first to reduce surprises, then strip tags.
    safe = sanitize_html(html or "")
    text = bleach.clean(safe, tags=[], attributes={}, strip=True)
    return " ".join((text or "").split())


# --- DB helpers ---
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    os.makedirs(BASE_DIR, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    try:
        db.execute("PRAGMA foreign_keys = ON;")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description_html TEXT NOT NULL,
                description_text TEXT NOT NULL,
                due_date TEXT NULL,
                priority INTEGER NOT NULL DEFAULT 1,
                completed INTEGER NOT NULL DEFAULT 0,
                completed_at TEXT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                sort_order INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_tasks_user_sort
            ON tasks(user_id, sort_order);
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_tasks_user_completed
            ON tasks(user_id, completed);
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_tasks_user_due
            ON tasks(user_id, due_date);
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS tags (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, name)
            );
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS task_tags (
                task_id TEXT NOT NULL,
                tag_id TEXT NOT NULL,
                PRIMARY KEY(task_id, tag_id),
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE
            );
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_task_tags_task
            ON task_tags(task_id);
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_task_tags_tag
            ON task_tags(tag_id);
            """
        )
        db.commit()
    finally:
        db.close()


init_db()


# --- Auth/session bootstrap ---
@app.before_request
def load_user_from_cookie():
    logger.debug("Incoming cookies: %s", request.cookies)

    if "google_id" not in session:
        user_cookie = request.cookies.get("user")
        if user_cookie:
            try:
                decoded = base64.urlsafe_b64decode(user_cookie.encode("utf-8")).decode("utf-8")
                user_info = json.loads(decoded)
                email = user_info.get("email")
                if email:
                    session["google_id"] = email
                    session["user"] = user_info
            except Exception as e:
                logger.warning("Error decoding user cookie: %s", e)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "google_id" not in session:
            return redirect(url_for("login_prompt"))
        return f(*args, **kwargs)
    return decorated_function


def api_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "google_id" not in session:
            return jsonify({"error": "not_authenticated"}), 401
        return f(*args, **kwargs)
    return decorated_function


def ensure_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = uuid.uuid4().hex
        session["csrf_token"] = token
    return token


def csrf_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get("csrf_token")
        header = request.headers.get("X-CSRF-Token")
        if not token or not header or header != token:
            return jsonify({"error": "csrf_failed"}), 403
        return f(*args, **kwargs)
    return decorated_function


def current_user_email() -> str:
    return session.get("google_id", "")


def current_user_id() -> str:
    return user_storage_id(current_user_email())


# --- Migration from legacy JSON (per user) ---
def legacy_tasks_file_for_email(email: str) -> str:
    # Old system used tasks_{email}.json in BASE_DIR
    return os.path.join(BASE_DIR, f"tasks_{email}.json")


def user_has_any_tasks(user_id: str) -> bool:
    db = get_db()
    row = db.execute("SELECT 1 FROM tasks WHERE user_id = ? LIMIT 1;", (user_id,)).fetchone()
    return row is not None


def parse_legacy_due_to_iso(due: Optional[str]) -> Optional[str]:
    # Best-effort: legacy stored locale string; do not guess aggressively.
    # If it already looks ISO, keep it.
    if not due:
        return None
    s = due.strip()
    if len(s) == 10 and s[4] == "-" and s[7] == "-":
        return s  # YYYY-MM-DD
    # Try a few common US formats: M/D/YYYY or MM/DD/YYYY
    for fmt in ("%m/%d/%Y", "%-m/%-d/%Y", "%m/%d/%y"):
        try:
            dt = datetime.strptime(s, fmt).date()
            return dt.isoformat()
        except Exception:
            continue
    return None


def migrate_legacy_tasks_if_needed(user_email: str) -> None:
    user_id = user_storage_id(user_email)
    if user_has_any_tasks(user_id):
        return

    legacy_path = legacy_tasks_file_for_email(user_email)
    if not os.path.exists(legacy_path):
        return

    try:
        with open(legacy_path, "r", encoding="utf-8") as f:
            legacy_tasks = json.load(f) or []
    except Exception as e:
        logger.warning("Legacy migration failed reading %s: %s", legacy_path, e)
        return

    db = get_db()
    now = utc_now_iso()

    # Legacy tasks used index; keep the same ordering.
    # Normalize sort_order ascending.
    def legacy_index(t: Dict[str, Any]) -> int:
        try:
            return int(t.get("index", 0))
        except Exception:
            return 0

    legacy_tasks_sorted = sorted(legacy_tasks, key=legacy_index)

    inserted = 0
    for i, t in enumerate(legacy_tasks_sorted):
        title = (t.get("title") or "").strip()
        desc_html = (t.get("description") or "").strip()
        if not title:
            continue
        safe_html = sanitize_html(desc_html)
        desc_text = html_to_text(safe_html)
        due_iso = parse_legacy_due_to_iso(t.get("dueDate"))
        created_at = now
        updated_at = now

        task_id = str(uuid.uuid4())
        db.execute(
            """
            INSERT INTO tasks
              (id, user_id, title, description_html, description_text, due_date, priority,
               completed, completed_at, created_at, updated_at, sort_order)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                task_id,
                user_id,
                title,
                safe_html,
                desc_text,
                due_iso,
                1,
                0,
                None,
                created_at,
                updated_at,
                i,
            ),
        )
        inserted += 1

    db.commit()
    logger.info("Migrated %d legacy tasks for %s", inserted, user_email)


# --- Tags helpers ---
def normalize_tag_name(name: str) -> str:
    return " ".join((name or "").strip().lower().split())


def upsert_tags(user_id: str, tag_names: List[str]) -> List[str]:
    """
    Returns list of tag IDs corresponding to provided tag names (normalized).
    """
    db = get_db()
    ids: List[str] = []
    now = utc_now_iso()

    for raw in tag_names:
        name = normalize_tag_name(raw)
        if not name:
            continue
        row = db.execute(
            "SELECT id FROM tags WHERE user_id = ? AND name = ?;",
            (user_id, name),
        ).fetchone()
        if row:
            ids.append(row["id"])
            continue
        tag_id = str(uuid.uuid4())
        try:
            db.execute(
                "INSERT INTO tags (id, user_id, name, created_at) VALUES (?, ?, ?, ?);",
                (tag_id, user_id, name, now),
            )
            ids.append(tag_id)
        except sqlite3.IntegrityError:
            # Another request inserted it; fetch again
            row2 = db.execute(
                "SELECT id FROM tags WHERE user_id = ? AND name = ?;",
                (user_id, name),
            ).fetchone()
            if row2:
                ids.append(row2["id"])

    return ids


def set_task_tags(task_id: str, user_id: str, tag_names: List[str]) -> None:
    db = get_db()
    tag_ids = upsert_tags(user_id, tag_names)

    db.execute("DELETE FROM task_tags WHERE task_id = ?;", (task_id,))
    for tag_id in tag_ids:
        db.execute(
            "INSERT OR IGNORE INTO task_tags (task_id, tag_id) VALUES (?, ?);",
            (task_id, tag_id),
        )


def get_task_tags(task_id: str, user_id: str) -> List[str]:
    db = get_db()
    rows = db.execute(
        """
        SELECT t.name
        FROM tags t
        JOIN task_tags tt ON tt.tag_id = t.id
        WHERE tt.task_id = ? AND t.user_id = ?
        ORDER BY t.name ASC;
        """,
        (task_id, user_id),
    ).fetchall()
    return [r["name"] for r in rows]


# --- API serialization ---
def row_to_task(row: sqlite3.Row, user_id: str) -> Dict[str, Any]:
    task = {
        "id": row["id"],
        "title": row["title"],
        "description_html": row["description_html"],
        "due_date": row["due_date"],
        "priority": row["priority"],
        "completed": bool(row["completed"]),
        "completed_at": row["completed_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "sort_order": row["sort_order"],
        "tags": get_task_tags(row["id"], user_id),
    }
    return task


def parse_priority(val: Any) -> int:
    try:
        p = int(val)
    except Exception:
        return 1
    return max(0, min(2, p))


def parse_tags(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x) for x in val]
    if isinstance(val, str):
        # comma-separated
        parts = [p.strip() for p in val.split(",")]
        return [p for p in parts if p]
    return []


# --- Pages ---
@app.route("/")
def index():
    if "google_id" in session:
        ensure_csrf_token()
        return render_template("index.html", csrf_token=session["csrf_token"])
    return redirect(url_for("login_prompt"))


@app.route("/login")
def login_prompt():
    login_url = "https://secure.blahpunk.com/oauth_login?next=https://tasks.blahpunk.com"
    return render_template("login_prompt.html", login_url=login_url)


@app.route("/logout")
def logout():
    session.clear()
    response = redirect(url_for("login_prompt"))
    response.delete_cookie("user", domain=".blahpunk.com", path="/")
    return response


# --- API v1 ---
@app.route("/api/v1/tasks", methods=["GET"])
@api_login_required
def api_list_tasks():
    email = current_user_email()
    user_id = current_user_id()
    migrate_legacy_tasks_if_needed(email)

    q = (request.args.get("q") or "").strip().lower()
    status = (request.args.get("status") or "all").strip().lower()  # all|active|completed
    special = (request.args.get("special") or "").strip().lower()   # overdue|dueSoon
    sort = (request.args.get("sort") or "manual").strip().lower()   # manual|due|created|updated|priority|title
    hide_completed = (request.args.get("hide_completed") or "0").strip() == "1"

    db = get_db()

    where = ["user_id = ?"]
    params: List[Any] = [user_id]

    if q:
        where.append("(LOWER(title) LIKE ? OR LOWER(description_text) LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like])

    if status == "active":
        where.append("completed = 0")
    elif status == "completed":
        where.append("completed = 1")

    if hide_completed:
        where.append("completed = 0")

    today = iso_date_today()
    if special == "overdue":
        where.append("completed = 0")
        where.append("due_date IS NOT NULL AND due_date < ?")
        params.append(today.isoformat())
    elif special == "duesoon":
        where.append("completed = 0")
        where.append("due_date IS NOT NULL AND due_date >= ? AND due_date <= ?")
        params.append(today.isoformat())
        params.append((today + timedelta(days=7)).isoformat())

    where_sql = " AND ".join(where)

    if sort == "due":
        order_sql = "CASE WHEN due_date IS NULL THEN 1 ELSE 0 END, due_date ASC, sort_order ASC"
    elif sort == "created":
        order_sql = "created_at DESC, sort_order ASC"
    elif sort == "updated":
        order_sql = "updated_at DESC, sort_order ASC"
    elif sort == "priority":
        order_sql = "priority DESC, CASE WHEN due_date IS NULL THEN 1 ELSE 0 END, due_date ASC, sort_order ASC"
    elif sort == "title":
        order_sql = "LOWER(title) ASC, sort_order ASC"
    else:
        order_sql = "sort_order ASC"

    rows = db.execute(
        f"""
        SELECT *
        FROM tasks
        WHERE {where_sql}
        ORDER BY {order_sql};
        """,
        tuple(params),
    ).fetchall()

    tasks = [row_to_task(r, user_id) for r in rows]
    return jsonify(tasks)


@app.route("/api/v1/tasks", methods=["POST"])
@api_login_required
@csrf_required
def api_create_task():
    user_id = current_user_id()
    payload = request.get_json(force=True, silent=True) or {}

    title = (payload.get("title") or "").strip()
    description_html = (payload.get("description_html") or "").strip()
    due_date = (payload.get("due_date") or "").strip() or None
    priority = parse_priority(payload.get("priority"))
    tags = parse_tags(payload.get("tags"))

    if not title:
        return jsonify({"error": "title_required"}), 400

    # Validate due_date ISO if present
    if due_date and parse_iso_date(due_date) is None:
        return jsonify({"error": "invalid_due_date"}), 400

    safe_html = sanitize_html(description_html)
    desc_text = html_to_text(safe_html)

    db = get_db()
    now = utc_now_iso()

    # Put new tasks at the top in manual order: shift existing sort_order +1
    db.execute("UPDATE tasks SET sort_order = sort_order + 1 WHERE user_id = ?;", (user_id,))

    task_id = str(uuid.uuid4())
    db.execute(
        """
        INSERT INTO tasks
          (id, user_id, title, description_html, description_text, due_date, priority,
           completed, completed_at, created_at, updated_at, sort_order)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, 0);
        """,
        (
            task_id,
            user_id,
            title,
            safe_html,
            desc_text,
            due_date,
            priority,
            now,
            now,
        ),
    )
    set_task_tags(task_id, user_id, tags)
    db.commit()

    row = db.execute("SELECT * FROM tasks WHERE id = ? AND user_id = ?;", (task_id, user_id)).fetchone()
    return jsonify(row_to_task(row, user_id)), 201


@app.route("/api/v1/tasks/<task_id>", methods=["PUT"])
@api_login_required
@csrf_required
def api_update_task(task_id: str):
    user_id = current_user_id()
    payload = request.get_json(force=True, silent=True) or {}

    db = get_db()
    existing = db.execute("SELECT * FROM tasks WHERE id = ? AND user_id = ?;", (task_id, user_id)).fetchone()
    if not existing:
        return jsonify({"error": "not_found"}), 404

    title = (payload.get("title") or existing["title"]).strip()
    description_html = (payload.get("description_html") if "description_html" in payload else existing["description_html"]) or ""
    due_date = (payload.get("due_date") if "due_date" in payload else existing["due_date"]) or None
    priority = parse_priority(payload.get("priority") if "priority" in payload else existing["priority"])
    completed = bool(payload.get("completed")) if "completed" in payload else bool(existing["completed"])
    tags = parse_tags(payload.get("tags")) if "tags" in payload else get_task_tags(task_id, user_id)

    if not title:
        return jsonify({"error": "title_required"}), 400

    if due_date and parse_iso_date(due_date) is None:
        return jsonify({"error": "invalid_due_date"}), 400

    safe_html = sanitize_html(description_html)
    desc_text = html_to_text(safe_html)

    now = utc_now_iso()
    completed_at = existing["completed_at"]
    if completed and not bool(existing["completed"]):
        completed_at = now
    if not completed:
        completed_at = None

    db.execute(
        """
        UPDATE tasks
        SET title = ?, description_html = ?, description_text = ?,
            due_date = ?, priority = ?, completed = ?, completed_at = ?,
            updated_at = ?
        WHERE id = ? AND user_id = ?;
        """,
        (
            title,
            safe_html,
            desc_text,
            due_date,
            priority,
            1 if completed else 0,
            completed_at,
            now,
            task_id,
            user_id,
        ),
    )
    set_task_tags(task_id, user_id, tags)
    db.commit()

    row = db.execute("SELECT * FROM tasks WHERE id = ? AND user_id = ?;", (task_id, user_id)).fetchone()
    return jsonify(row_to_task(row, user_id))


@app.route("/api/v1/tasks/<task_id>", methods=["DELETE"])
@api_login_required
@csrf_required
def api_delete_task(task_id: str):
    user_id = current_user_id()
    db = get_db()

    row = db.execute("SELECT sort_order FROM tasks WHERE id = ? AND user_id = ?;", (task_id, user_id)).fetchone()
    if not row:
        return jsonify({"error": "not_found"}), 404
    deleted_order = int(row["sort_order"])

    db.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?;", (task_id, user_id))
    # Compact manual ordering
    db.execute(
        "UPDATE tasks SET sort_order = sort_order - 1 WHERE user_id = ? AND sort_order > ?;",
        (user_id, deleted_order),
    )
    db.commit()
    return "", 204


@app.route("/api/v1/tasks/reorder", methods=["POST"])
@api_login_required
@csrf_required
def api_reorder_tasks():
    user_id = current_user_id()
    payload = request.get_json(force=True, silent=True) or {}
    ordered_ids = payload.get("ordered_ids")

    if not isinstance(ordered_ids, list) or not all(isinstance(x, str) for x in ordered_ids):
        return jsonify({"error": "ordered_ids_required"}), 400

    db = get_db()

    # Ensure all IDs belong to this user
    rows = db.execute(
        f"SELECT id FROM tasks WHERE user_id = ? AND id IN ({','.join(['?'] * len(ordered_ids))});",
        tuple([user_id] + ordered_ids),
    ).fetchall()
    found = set(r["id"] for r in rows)
    if set(ordered_ids) != found:
        return jsonify({"error": "invalid_task_ids"}), 400

    for i, tid in enumerate(ordered_ids):
        db.execute(
            "UPDATE tasks SET sort_order = ?, updated_at = ? WHERE id = ? AND user_id = ?;",
            (i, utc_now_iso(), tid, user_id),
        )

    db.commit()
    return "", 204


@app.route("/api/v1/tags", methods=["GET"])
@api_login_required
def api_list_tags():
    user_id = current_user_id()
    db = get_db()
    rows = db.execute(
        "SELECT name FROM tags WHERE user_id = ? ORDER BY name ASC;",
        (user_id,),
    ).fetchall()
    return jsonify([r["name"] for r in rows])


# --- Back-compat endpoints (optional) ---
@app.route("/api/tasks", methods=["GET"])
@login_required
def compat_get_tasks():
    return api_list_tasks()


@app.route("/api/tasks", methods=["POST"])
@login_required
def compat_add_task():
    # Require CSRF for back-compat too
    return api_create_task()


@app.route("/api/tasks/order", methods=["POST"])
@login_required
def compat_save_order():
    return api_reorder_tasks()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5151, debug=True)
