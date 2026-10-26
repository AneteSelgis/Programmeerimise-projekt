import os
import re
import secrets
import time
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, session, abort, jsonify
from tinydb import TinyDB, Query
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)


# ---------- Secret key (signs the login cookie, must stay private) ----------
def load_secret_key():
    # 1. Use the SECRET_KEY environment variable if it exists
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    # 2. Otherwise create a random key once and keep it in secret_key.txt
    path = os.path.join(BASE_DIR, "secret_key.txt")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w") as f:
        f.write(key)
    return key


app.secret_key = load_secret_key()

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # JavaScript can't read the login cookie
    SESSION_COOKIE_SAMESITE="Lax",      # cookie isn't sent on cross-site POSTs
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),  # auto logout after 8 hours
    # SESSION_COOKIE_SECURE=True,       # turn on once the site runs on HTTPS
)

db = TinyDB(os.path.join(BASE_DIR, "db.projekt"))
Users = Query()
Todos = db.table("todos")      # <-- uus: ülesanded
TodoQ = Query()

# ---------- Settings ----------
USERNAME_RE = re.compile(r"^\w{3,20}$")   # letters, digits, underscore
MIN_PASSWORD = 8
MAX_PASSWORD = 128
MAX_ATTEMPTS = 3          # wrong tries (wrong username OR password) before the lock (testing value, normal: 5)
LOCK_SECONDS = 120        # locked this many seconds (testing value, normal: 300)

# Used so a wrong username takes as long to check as a wrong password
DUMMY_HASH = generate_password_hash("dummy-password")

failed_logins = {}        # ip address -> {"count": n, "last": time, "until": time}


def is_locked(key):
    entry = failed_logins.get(key)
    return bool(entry and entry["until"] > time.time())


def lock_message(key):
    seconds = max(1, int(failed_logins[key]["until"] - time.time()))
    minutes = (seconds + 59) // 60
    return f"Liiga palju katseid. Proovi uuesti umbes {minutes} min pärast."


def register_failure(key):
    """Counts one wrong try (wrong username or wrong password).
    Returns how many tries are left (0 = now locked)."""
    now = time.time()
    entry = failed_logins.get(key)
    # Start counting from zero if there is no record yet, or if the last
    # wrong password was more than LOCK_SECONDS ago (the gap is measured from
    # the LAST wrong try, so slow tries still add up).
    if entry is None or now - entry["last"] > LOCK_SECONDS:
        entry = {"count": 0, "last": now, "until": 0}
        failed_logins[key] = entry
    entry["count"] += 1
    entry["last"] = now
    # Shows in Thonny's shell so you can see the counter working
    print(f"[login] wrong try: key={key} count={entry['count']}/{MAX_ATTEMPTS}")
    if entry["count"] >= MAX_ATTEMPTS:
        entry["until"] = now + LOCK_SECONDS
        entry["count"] = 0
        print(f"[login] LOCKED for {LOCK_SECONDS} s: key={key}")
        return 0
    return MAX_ATTEMPTS - entry["count"]


# ---------- CSRF protection (blocks forms submitted from other websites) ----------
def get_csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        real = session.get("csrf", "")
        if not real or not secrets.compare_digest(sent, real):
            abort(400)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    if request.endpoint != "static":
        # stops the Back button from showing the calendar after logging out
        response.headers["Cache-Control"] = "no-store"
    return response


# ---------- Routes ----------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    # One counter per computer: every wrong try counts, whatever username was typed
    key = request.remote_addr

    if is_locked(key):
        return render_template("index.html", error=lock_message(key)), 429

    user = db.get(Users.username == username)
    stored_hash = user["password"] if user else DUMMY_HASH
    password_ok = check_password_hash(stored_hash, password[:MAX_PASSWORD])

    # Same message for wrong username and wrong password
    if not user or not password_ok:
        left = register_failure(key)
        if left == 0:
            return render_template("index.html", error=lock_message(key)), 429
        return render_template(
            "index.html",
            error=f"Vale kasutajanimi või parool! Katseid jäänud: {left}",
        ), 401

    failed_logins.pop(key, None)   # a correct login resets the counter
    session.clear()               # new session after login
    session.permanent = True
    session["user"] = username
    return redirect("/calendar")


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not USERNAME_RE.match(username):
        return render_template(
            "index.html",
            error="Kasutajanimi peab olema 3-20 märki (tähed, numbrid, _).",
        ), 400

    if len(password) < MIN_PASSWORD or len(password) > MAX_PASSWORD:
        return render_template(
            "index.html",
            error=f"Parool peab olema {MIN_PASSWORD}-{MAX_PASSWORD} märki pikk.",
        ), 400

    if db.get(Users.username == username):
        return render_template("index.html", error="Kasutajanimi on juba võetud!"), 409

    db.insert({"username": username, "password": generate_password_hash(password)})

    session.clear()
    session.permanent = True
    session["user"] = username
    return redirect("/calendar")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---- CALENDAR PART (your friend can work here and in templates/calendar.html) ----
@app.route("/calendar")
def calendar():
    if "user" not in session:
        return redirect("/")
    return render_template("calendar.html", user=session["user"])


# ---------- TO DO JA HÕIVATUD AEG (kalender) ----------
TODO_TEXT_MAX = 200
BUSY_TEXT_MAX = 100
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
DEFAULT_TODO_COLOR = "#3788d8"
DEFAULT_BUSY_COLOR = "#b0bec5"

busy_table = db.table("busy")
BusyQ = Query()


def current_user():
    user = session.get("user")
    if not user:
        abort(401)
    return user


def clean_color(value, default):
    value = str(value or "").strip()
    return value.lower() if COLOR_RE.match(value) else default


def valid_date(value):
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return True
    except (TypeError, ValueError):
        return False


def read_todo(data):
    """Checks the data a todo form sends. Returns (fields, None) or (None, error)."""
    text = str(data.get("text") or "").strip()
    date = str(data.get("date") or "")
    time_ = str(data.get("time") or "")
    if not 1 <= len(text) <= TODO_TEXT_MAX:
        return None, "Vigane nimi."
    if date and not valid_date(date):
        return None, "Vigane kuupäev."
    if time_ and not (date and TIME_RE.match(time_)):
        return None, "Vigane kellaaeg."
    return {"text": text, "date": date, "time": time_,
            "color": clean_color(data.get("color"), DEFAULT_TODO_COLOR)}, None


def todo_json(t):
    return {"id": t["id"], "text": t["text"], "done": t["done"],
            "date": t.get("date", ""), "time": t.get("time", ""),
            "color": clean_color(t.get("color"), DEFAULT_TODO_COLOR)}


def own_todo(todo_id, user):
    return Todos.get((TodoQ.id == todo_id) & (TodoQ.user == user))


@app.route("/api/todos", methods=["GET"])
def api_get_todos():
    user = current_user()
    return jsonify([todo_json(t) for t in Todos.search(TodoQ.user == user)])


@app.route("/api/todos", methods=["POST"])
def api_add_todo():
    user = current_user()
    fields, problem = read_todo(request.get_json(silent=True) or {})
    if problem:
        return jsonify({"error": problem}), 400
    todo = {"id": secrets.token_hex(8), "user": user, "done": False, **fields}
    Todos.insert(todo)
    return jsonify(todo_json(todo)), 201


@app.route("/api/todos/<todo_id>/update", methods=["POST"])
def api_update_todo(todo_id):
    user = current_user()
    if own_todo(todo_id, user) is None:
        return jsonify({"error": "not found"}), 404
    fields, problem = read_todo(request.get_json(silent=True) or {})
    if problem:
        return jsonify({"error": problem}), 400
    Todos.update(fields, (TodoQ.id == todo_id) & (TodoQ.user == user))
    return jsonify(todo_json(own_todo(todo_id, user)))


@app.route("/api/todos/<todo_id>/toggle", methods=["POST"])
def api_toggle_todo(todo_id):
    user = current_user()
    data = request.get_json(silent=True) or {}
    Todos.update({"done": bool(data.get("done"))},
                 (TodoQ.id == todo_id) & (TodoQ.user == user))
    return jsonify({"ok": True})


@app.route("/api/todos/<todo_id>/delete", methods=["POST"])
def api_delete_todo(todo_id):
    user = current_user()
    Todos.remove((TodoQ.id == todo_id) & (TodoQ.user == user))
    return jsonify({"ok": True})


# ---------- HÕIVATUD AEG (tunniplaan) ----------
def read_busy(data):
    """Checks the data the busy-time form sends. Returns (fields, None) or (None, error)."""
    text = str(data.get("text") or "").strip()
    repeat = data.get("repeat")
    date = str(data.get("date") or "")
    start = str(data.get("start") or "")
    end = str(data.get("end") or "")
    if not 1 <= len(text) <= BUSY_TEXT_MAX:
        return None, "Vigane nimi."
    if not isinstance(repeat, bool):
        return None, "Vigane kordus."
    if not (TIME_RE.match(start) and TIME_RE.match(end)) or end <= start:
        return None, "Vigased kellaajad."
    if repeat:
        day = data.get("day")
        if not isinstance(day, int) or isinstance(day, bool) or day not in range(7):
            return None, "Vigane nädalapäev."
        date = ""
    else:
        if not valid_date(date):
            return None, "Vigane kuupäev."
        day = (datetime.strptime(date, "%Y-%m-%d").weekday() + 1) % 7   # 0 = pühapäev
    return {"text": text, "day": day, "start": start, "end": end, "repeat": repeat,
            "date": date, "color": clean_color(data.get("color"), DEFAULT_BUSY_COLOR)}, None


def busy_json(row):
    repeat = row.get("repeat")
    if repeat is None:                       # old rows saved before "repeat" existed
        repeat = not row.get("date")
    return {
        "id": row.doc_id,
        "text": row["text"],
        "day": row["day"],
        "start": row["start"],
        "end": row["end"],
        "repeat": bool(repeat),
        "date": row.get("date", ""),
        "color": clean_color(row.get("color"), DEFAULT_BUSY_COLOR),
    }


def own_busy(busy_id, user):
    row = busy_table.get(doc_id=busy_id)
    return row if row and row.get("user") == user else None


@app.route("/api/busy", methods=["GET"])
def get_busy():
    user = session.get("user")
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    rows = busy_table.search(BusyQ.user == user)
    return jsonify([busy_json(r) for r in rows])


@app.route("/api/busy", methods=["POST"])
def add_busy():
    user = session.get("user")
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    fields, problem = read_busy(request.get_json(silent=True) or {})
    if problem:
        return jsonify({"error": problem}), 400
    doc_id = busy_table.insert({"user": user, **fields})
    return jsonify(busy_json(busy_table.get(doc_id=doc_id)))


@app.route("/api/busy/<int:busy_id>/update", methods=["POST"])
def update_busy(busy_id):
    user = session.get("user")
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    if own_busy(busy_id, user) is None:
        return jsonify({"error": "not found"}), 404
    fields, problem = read_busy(request.get_json(silent=True) or {})
    if problem:
        return jsonify({"error": problem}), 400
    busy_table.update(fields, doc_ids=[busy_id])
    return jsonify(busy_json(busy_table.get(doc_id=busy_id)))


@app.route("/api/busy/<int:busy_id>/delete", methods=["POST"])
def delete_busy(busy_id):
    user = session.get("user")
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    if own_busy(busy_id, user) is None:
        return jsonify({"error": "not found"}), 404
    busy_table.remove(doc_ids=[busy_id])
    return jsonify({"ok": True})
# ---- END CALENDAR PART ----


if __name__ == "__main__":
    # debug=True shows an interactive debugger to anyone who triggers an error,
    # so keep it False unless you are only testing on your own computer.
    app.run(debug=False, port=5001)