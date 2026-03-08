# /var/www/tasklist/app.py

import os
import json
import base64
import uuid
import hashlib
import hmac
import logging
import re
import sqlite3
import time
from datetime import datetime, date, timedelta, timezone
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, g
from dotenv import load_dotenv
import bleach
from cryptography.fernet import Fernet, InvalidToken

# Load environment variables from .env
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tasklist")


def env_int(name: str, default: int) -> int:
    raw = (os.getenv(name, str(default)) or "").strip()
    try:
        return int(raw)
    except Exception as exc:
        raise RuntimeError(f"{name} must be an integer.") from exc


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv("DATA_DIR", BASE_DIR)
DB_PATH = os.getenv("DB_PATH", os.path.join(DATA_DIR, "tasks.db"))
STATIC_ASSET_VERSION = (os.getenv("STATIC_ASSET_VERSION", "") or "").strip()

# Keep your original static URL behavior
app = Flask(__name__, static_url_path="/tasks/static", static_folder="static")
SECRET_KEY = os.getenv("SECRET_KEY", "")
if not SECRET_KEY or SECRET_KEY == "change-me":
    raise RuntimeError("SECRET_KEY must be set to a non-default value.")
app.secret_key = SECRET_KEY
SECURE_AUTH_SECRET = os.getenv("SECURE_AUTH_SECRET", "")
USER_ID_SECRET = os.getenv("USER_ID_SECRET", "").strip()
DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY", "").strip()
BOOTSTRAP_COOKIE_AUDIENCE = (os.getenv("BOOTSTRAP_COOKIE_AUDIENCE", "tasks.blahpunk.com") or "").strip().lower()
BOOTSTRAP_COOKIE_MAX_AGE_SECONDS = env_int("BOOTSTRAP_COOKIE_MAX_AGE_SECONDS", 300)
BOOTSTRAP_COOKIE_CLOCK_SKEW_SECONDS = env_int("BOOTSTRAP_COOKIE_CLOCK_SKEW_SECONDS", 60)

# Keep session host-only to avoid leaking it across sibling subdomains.
app.config["SESSION_COOKIE_DOMAIN"] = None
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["PREFERRED_URL_SCHEME"] = "https"
if not SECURE_AUTH_SECRET:
    logger.warning("SECURE_AUTH_SECRET is not configured; user cookie bootstrap is disabled.")
if not USER_ID_SECRET:
    raise RuntimeError("USER_ID_SECRET must be set to a non-default value.")
if not DATA_ENCRYPTION_KEY:
    raise RuntimeError("DATA_ENCRYPTION_KEY must be set to a valid Fernet key.")
if not BOOTSTRAP_COOKIE_AUDIENCE:
    raise RuntimeError("BOOTSTRAP_COOKIE_AUDIENCE must be set.")
try:
    DATA_FERNET = Fernet(DATA_ENCRYPTION_KEY.encode("utf-8"))
except Exception as exc:
    raise RuntimeError("DATA_ENCRYPTION_KEY must be a valid Fernet key.") from exc


def asset_version(filename: str) -> str:
    if STATIC_ASSET_VERSION:
        return STATIC_ASSET_VERSION
    try:
        path = os.path.join(app.static_folder or "", filename)
        version = str(int(os.path.getmtime(path)))
    except Exception:
        version = "1"
    return version


@app.context_processor
def inject_asset_version():
    return {"asset_version": asset_version}


ENC_PREFIX = "enc:v1:"

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

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
    "li": ["data-list", "class"],
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


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_RE.fullmatch(normalize_email(email)))


def legacy_user_storage_id(email: str) -> str:
    email_n = normalize_email(email)
    return hashlib.sha256(email_n.encode("utf-8")).hexdigest()


def user_storage_id(email: str) -> str:
    email_n = normalize_email(email)
    digest = hmac.new(
        USER_ID_SECRET.encode("utf-8"),
        email_n.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest


def is_encrypted_value(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(ENC_PREFIX)


def encrypt_text(value: Optional[str]) -> str:
    plaintext = (value or "").encode("utf-8")
    token = DATA_FERNET.encrypt(plaintext).decode("utf-8")
    return f"{ENC_PREFIX}{token}"


def decrypt_text(value: Optional[str]) -> str:
    if value is None:
        return ""
    if not is_encrypted_value(value):
        return value
    token = value[len(ENC_PREFIX):]
    try:
        raw = DATA_FERNET.decrypt(token.encode("utf-8"))
        return raw.decode("utf-8")
    except InvalidToken:
        logger.error("Failed to decrypt ciphertext in tasks DB; check DATA_ENCRYPTION_KEY.")
        return ""


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


def verify_user_cookie_signature(user_cookie: str, user_sig: Optional[str]) -> bool:
    if not SECURE_AUTH_SECRET or not user_cookie or not user_sig:
        return False
    expected = hmac.new(
        SECURE_AUTH_SECRET.encode("utf-8"),
        user_cookie.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, user_sig)


def decode_user_cookie(user_cookie: str) -> Optional[Dict[str, Any]]:
    try:
        padding = "=" * (-len(user_cookie) % 4)
        decoded = base64.urlsafe_b64decode((user_cookie + padding).encode("utf-8")).decode("utf-8")
        parsed = json.loads(decoded)
        if not isinstance(parsed, dict):
            return None
        return parsed
    except Exception:
        return None


def parse_epoch_seconds(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        s = value.strip()
        if s and (s.lstrip("-").isdigit()):
            try:
                return int(s)
            except Exception:
                return None
    return None


def audience_matches(aud_claim: Any, expected: str) -> bool:
    expected_n = (expected or "").strip().lower()
    if not expected_n:
        return False
    if isinstance(aud_claim, str):
        return aud_claim.strip().lower() == expected_n
    if isinstance(aud_claim, list):
        for part in aud_claim:
            if isinstance(part, str) and part.strip().lower() == expected_n:
                return True
    return False


def validate_bootstrap_claims(user_info: Dict[str, Any]) -> Tuple[bool, str]:
    now = int(time.time())
    skew = max(0, BOOTSTRAP_COOKIE_CLOCK_SKEW_SECONDS)
    max_age = max(30, BOOTSTRAP_COOKIE_MAX_AGE_SECONDS)

    aud = user_info.get("aud")
    if not audience_matches(aud, BOOTSTRAP_COOKIE_AUDIENCE):
        return False, "audience_mismatch"

    exp = parse_epoch_seconds(user_info.get("exp"))
    iat = parse_epoch_seconds(user_info.get("iat"))
    nbf = parse_epoch_seconds(user_info.get("nbf"))

    if exp is None or iat is None:
        return False, "missing_required_time_claims"
    if exp <= iat:
        return False, "invalid_claim_window"
    if iat > now + skew:
        return False, "token_issued_in_future"
    if nbf is not None and now + skew < nbf:
        return False, "token_not_yet_valid"
    if exp < now - skew:
        return False, "token_expired"
    if (exp - iat) > (max_age + skew):
        return False, "token_ttl_too_long"
    if (now - iat) > (max_age + skew):
        return False, "token_too_old"
    return True, ""


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


def encrypt_existing_task_content(db: sqlite3.Connection) -> None:
    rows = db.execute(
        "SELECT id, title, description_html, description_text FROM tasks;"
    ).fetchall()
    changed = 0
    for row in rows:
        title = row["title"]
        description_html = row["description_html"]
        description_text = row["description_text"]

        new_title = title if is_encrypted_value(title) else encrypt_text(title)
        new_description_html = description_html if is_encrypted_value(description_html) else encrypt_text(description_html)
        new_description_text = description_text if is_encrypted_value(description_text) else encrypt_text(description_text)

        if (
            new_title != title
            or new_description_html != description_html
            or new_description_text != description_text
        ):
            db.execute(
                """
                UPDATE tasks
                SET title = ?, description_html = ?, description_text = ?
                WHERE id = ?;
                """,
                (new_title, new_description_html, new_description_text, row["id"]),
            )
            changed += 1
    if changed:
        logger.info("Encrypted plaintext task content for %d row(s).", changed)


def init_db() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    try:
        db.row_factory = sqlite3.Row
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
        encrypt_existing_task_content(db)
        db.commit()
    finally:
        db.close()


init_db()


# --- Auth/session bootstrap ---
@app.before_request
def load_user_from_cookie():
    if "google_id" in session:
        return

    user_cookie = request.cookies.get("user")
    user_sig = request.cookies.get("user_sig")
    if not user_cookie:
        return

    ip = request.headers.get("CF-Connecting-IP") or request.remote_addr or "unknown"
    if not verify_user_cookie_signature(user_cookie, user_sig):
        logger.warning("Rejected user bootstrap cookie with invalid signature from %s", ip)
        return

    user_info = decode_user_cookie(user_cookie)
    if not user_info:
        logger.warning("Rejected malformed user bootstrap cookie from %s", ip)
        return

    email = normalize_email(str(user_info.get("email") or ""))
    if not is_valid_email(email):
        logger.warning("Rejected user bootstrap cookie with invalid email from %s", ip)
        return

    claims_ok, claims_reason = validate_bootstrap_claims(user_info)
    if not claims_ok:
        logger.warning("Rejected bootstrap cookie from %s: %s", ip, claims_reason)
        return

    session["google_id"] = email
    # Do not store profile fields in the signed cookie session.
    ensure_csrf_token()


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


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
    email = current_user_email()
    migrate_user_namespace_if_needed(email)
    return user_storage_id(email)


def migrate_user_namespace_if_needed(email: str) -> None:
    email_n = normalize_email(email)
    if not is_valid_email(email_n):
        return

    secure_id = user_storage_id(email_n)
    legacy_id = legacy_user_storage_id(email_n)
    if secure_id == legacy_id:
        return

    db = get_db()
    old_count_row = db.execute(
        "SELECT COUNT(1) AS c FROM tasks WHERE user_id = ?;",
        (legacy_id,),
    ).fetchone()
    old_count = int(old_count_row["c"]) if old_count_row else 0
    if old_count <= 0:
        return

    new_count_row = db.execute(
        "SELECT COUNT(1) AS c FROM tasks WHERE user_id = ?;",
        (secure_id,),
    ).fetchone()
    new_count = int(new_count_row["c"]) if new_count_row else 0
    if new_count > 0:
        logger.warning(
            "Skipped user_id namespace migration for %s due to existing secure records.",
            email_n,
        )
        return

    db.execute("UPDATE tasks SET user_id = ? WHERE user_id = ?;", (secure_id, legacy_id))
    db.execute("UPDATE tags SET user_id = ? WHERE user_id = ?;", (secure_id, legacy_id))
    db.commit()
    logger.info("Migrated user namespace to secure ids for %s", email_n)


# --- Migration from legacy JSON (per user) ---
def legacy_tasks_file_for_email(email: str) -> Optional[str]:
    # Old system used tasks_{email}.json in data dir
    email_n = normalize_email(email)
    if not is_valid_email(email_n):
        return None
    return os.path.join(DATA_DIR, f"tasks_{email_n}.json")


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
    if not legacy_path or not os.path.exists(legacy_path):
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
                encrypt_text(title),
                encrypt_text(safe_html),
                encrypt_text(desc_text),
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
        "title": decrypt_text(row["title"]),
        "description_html": decrypt_text(row["description_html"]),
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
    login_query = urlencode(
        {
            "next": "https://tasks.blahpunk.com",
            "aud": BOOTSTRAP_COOKIE_AUDIENCE,
            "max_age": str(BOOTSTRAP_COOKIE_MAX_AGE_SECONDS),
        }
    )
    login_url = f"https://secure.blahpunk.com/oauth_login?{login_query}"
    return render_template("login_prompt.html", login_url=login_url)


@app.route("/logout")
def logout():
    session.clear()
    response = redirect(url_for("login_prompt"))
    response.delete_cookie("user", domain=".blahpunk.com", path="/")
    response.delete_cookie("user_sig", domain=".blahpunk.com", path="/")
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
        order_sql = "sort_order ASC"
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

    tasks: List[Dict[str, Any]] = []
    for r in rows:
        task = row_to_task(r, user_id)
        if q:
            title_l = (task.get("title") or "").lower()
            desc_l = decrypt_text(r["description_text"]).lower()
            if q not in title_l and q not in desc_l:
                continue
        tasks.append(task)

    if sort == "title":
        tasks.sort(key=lambda t: ((t.get("title") or "").lower(), int(t.get("sort_order") or 0)))

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
            encrypt_text(title),
            encrypt_text(safe_html),
            encrypt_text(desc_text),
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

    existing_title = decrypt_text(existing["title"])
    existing_description_html = decrypt_text(existing["description_html"])

    title = (payload.get("title") or existing_title).strip()
    description_html = (payload.get("description_html") if "description_html" in payload else existing_description_html) or ""
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
            encrypt_text(title),
            encrypt_text(safe_html),
            encrypt_text(desc_text),
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
    app.run(host="0.0.0.0", port=5151, debug=False)
