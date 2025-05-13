import os
import json
import base64
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from functools import wraps
import logging
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_url_path='/tasks/static', static_folder='static')
app.secret_key = os.getenv("SECRET_KEY")

app.config['SESSION_COOKIE_DOMAIN'] = '.blahpunk.com'
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PREFERRED_URL_SCHEME'] = 'https'

@app.before_request
def load_user_from_cookie():
    logger.debug("Incoming cookies: %s", request.cookies)
    if 'google_id' not in session:
        user_cookie = request.cookies.get('user')
        if user_cookie:
            try:
                decoded = base64.urlsafe_b64decode(user_cookie.encode('utf-8')).decode('utf-8')
                logger.debug("Decoded user cookie: %s", decoded)
                user_info = json.loads(decoded)
                session['google_id'] = user_info.get('email')
                session['user'] = user_info
                logger.debug("Session updated with user: %s", session.get('user'))
            except Exception as e:
                logger.error("Error decoding user cookie: %s", e)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'google_id' not in session:
            return redirect(url_for('login_prompt'))
        return f(*args, **kwargs)
    return decorated_function

def get_tasks_file_for_user(user_id):
    return os.path.join(BASE_DIR, f"tasks_{user_id}.json")

def load_user_tasks(user_id):
    tasks_file = get_tasks_file_for_user(user_id)
    if os.path.exists(tasks_file):
        with open(tasks_file, 'r') as file:
            tasks = json.load(file)
            logger.debug("Loaded tasks for %s: %s", user_id, tasks)
            return tasks
    logger.debug("No tasks file for %s, returning empty list", user_id)
    return []

def save_user_tasks(user_id, tasks):
    with open(get_tasks_file_for_user(user_id), 'w') as file:
        json.dump(tasks, file, indent=4)
    logger.debug("Saved tasks for %s: %s", user_id, tasks)

@app.route("/")
def index():
    if 'google_id' in session:
        return render_template("index.html")
    else:
        return redirect(url_for('login_prompt'))

@app.route("/login")
def login_prompt():
    login_url = "https://secure.blahpunk.com/oauth_login?next=https://tasks.blahpunk.com"
    return render_template("login_prompt.html", login_url=login_url)

@app.route("/logout")
def logout():
    session.clear()
    response = redirect(url_for('login_prompt'))
    response.delete_cookie('user', domain='.blahpunk.com', path='/')
    return response

@app.route("/api/tasks", methods=["GET"])
@login_required
def get_tasks():
    user_id = session["google_id"]
    tasks = load_user_tasks(user_id)
    tasks.sort(key=lambda t: t.get('index', 0))
    return jsonify(tasks)

@app.route("/api/tasks", methods=["POST"])
@login_required
def add_task():
    user_id = session["google_id"]
    new_task = request.json
    tasks = load_user_tasks(user_id)
    new_task['index'] = -1  # temporary
    tasks.insert(0, new_task)
    for i, task in enumerate(tasks):
        task['index'] = i
    save_user_tasks(user_id, tasks)
    return jsonify(new_task), 201

@app.route("/api/tasks/<int:task_id>", methods=["PUT"])
@login_required
def update_task(task_id):
    user_id = session["google_id"]
    tasks = load_user_tasks(user_id)
    if 0 <= task_id < len(tasks):
        updated_task = request.json
        updated_task['index'] = tasks[task_id]['index']
        tasks[task_id] = updated_task
        save_user_tasks(user_id, tasks)
        return jsonify(updated_task)
    else:
        return jsonify({"error": "Task ID out of range"}), 404

@app.route("/api/tasks/<int:task_id>", methods=["DELETE"])
@login_required
def delete_task(task_id):
    user_id = session["google_id"]
    tasks = load_user_tasks(user_id)
    if 0 <= task_id < len(tasks):
        tasks.pop(task_id)
        save_user_tasks(user_id, tasks)
        return '', 204
    else:
        return jsonify({"error": "Task ID out of range"}), 404

@app.route("/api/tasks/order", methods=["POST"])
@login_required
def save_order():
    user_id = session["google_id"]
    ordered_tasks = request.json
    for i, task in enumerate(ordered_tasks):
        task['index'] = i
    save_user_tasks(user_id, ordered_tasks)
    return '', 204

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5151, debug=True)
