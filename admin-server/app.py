"""Private, same-origin mentor administration service."""
import hashlib
import io
import json
import os
import re
import secrets
import sqlite3
import subprocess
import time
import warnings
from contextlib import contextmanager
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from authlib.integrations.flask_client import OAuth
from flask import Flask, Response, abort, jsonify, redirect, request, send_from_directory, session
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.exceptions import HTTPException

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = "beyond-cafe.com"
SESSION_AGE = 8 * 3600
INVITE_AGE = 7 * 86400
EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
TYPE = re.compile(r"[AD][CS][TI][GP]")
ADMIN_FILES = {"style.css", "app.js", "students.js", "photos/placeholder.svg"}


def public_profiles():
    command = [
        "node", "-e",
        "global.window={};require('./mentors-data.js');"
        "process.stdout.write(JSON.stringify(window.MENTORS))",
    ]
    return json.loads(subprocess.check_output(command, cwd=ROOT, timeout=15))


def fail(message, status=400):
    abort(status, description=message)


def clean(value, limit, required=False):
    if not isinstance(value, str) or len(value.strip()) > limit or (required and not value.strip()):
        fail("入力内容と文字数を確認してください。")
    return value.strip()


def email_address(value):
    email = clean(value, 254, required=True).lower()
    if not EMAIL.fullmatch(email):
        fail("メールアドレスを確認してください。")
    return email


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def create_app(settings=None):
    app = Flask(__name__, static_folder=None)
    app.config.update(
        SECRET_KEY=os.environ.get("TAMA_SESSION_KEY"),
        GOOGLE_CLIENT_ID=os.environ.get("TAMA_GOOGLE_CLIENT_ID"),
        GOOGLE_CLIENT_SECRET=os.environ.get("TAMA_GOOGLE_CLIENT_SECRET"),
        PUBLIC_ORIGIN=os.environ.get("TAMA_ADMIN_ORIGIN", "").rstrip("/"),
        DATABASE=os.environ.get("TAMA_ADMIN_DB", ""),
        SESSION_COOKIE_NAME="tama_mentor_session",
        SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=SESSION_AGE),
        SESSION_REFRESH_EACH_REQUEST=False,
        MAX_CONTENT_LENGTH=6 * 1024 * 1024,
    )
    if settings:
        app.config.update(settings)
    origin = app.config["PUBLIC_ORIGIN"]
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):
        raise RuntimeError("TAMA_ADMIN_ORIGIN must be the canonical HTTPS origin")
    if not app.secret_key or len(app.secret_key) < 32 or not app.config["DATABASE"]:
        raise RuntimeError("Configure TAMA_SESSION_KEY and TAMA_ADMIN_DB")
    db_path = Path(app.config["DATABASE"]).resolve()
    if db_path.is_relative_to(ROOT):
        raise RuntimeError("TAMA_ADMIN_DB must be outside the deployed checkout")
    ready = bool(app.config["GOOGLE_CLIENT_ID"] and app.config["GOOGLE_CLIENT_SECRET"])
    oauth = OAuth(app)
    google = oauth.register(
        name="google",
        client_id=app.config["GOOGLE_CLIENT_ID"],
        client_secret=app.config["GOOGLE_CLIENT_SECRET"],
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email", "code_challenge_method": "S256"},
    )

    @contextmanager
    def connect(write=False):
        db = sqlite3.connect(db_path, timeout=10)
        try:
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            if write:
                db.commit()
        finally:
            db.close()

    with connect(write=True) as db:
        db.execute("CREATE TABLE IF NOT EXISTS workspace (id INTEGER PRIMARY KEY, data TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS login_session (id TEXT PRIMARY KEY, expires INTEGER NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS photo (id TEXT PRIMARY KEY, image BLOB NOT NULL)")
        if db.execute("SELECT 1 FROM workspace WHERE id=1").fetchone() is None:
            profiles = {
                m["id"]: {**m, "photo": "/" + m["photo"], "version": 1, "updatedAt": 0}
                for m in public_profiles()
            }
            initial = dict(mentors=profiles, accounts={}, invites={}, students={}, events=[])
            db.execute("INSERT INTO workspace VALUES (1, ?)", (json.dumps(initial),))

    def get_data(db):
        return json.loads(db.execute("SELECT data FROM workspace WHERE id=1").fetchone()[0])

    def save(db, data):
        db.execute("UPDATE workspace SET data=? WHERE id=1", (json.dumps(data),))

    def audit(data, email, action, target):
        data["events"].insert(0, dict(actor=email, action=action, target=target, created_at=int(time.time())))

    def identity(db, data):
        email = session.get("email")
        account = data["accounts"].get(email)
        row = db.execute("SELECT expires FROM login_session WHERE id=?", (session.get("sid"),)).fetchone()
        if (not account or not account["active"] or account["sub"] != session.get("sub")
                or not row or row[0] <= time.time()):
            fail("Googleでログインしてください。", 401)
        mentor_id = account.get("mentor_id")
        return dict(email=email, role=account["role"], mentorId=mentor_id, csrf=session["csrf"])

    def require_admin(user):
        if user["role"] != "admin":
            fail("管理者のみ操作できます。", 403)

    def mentor_for(data, mentor_id):
        if not isinstance(mentor_id, str) or mentor_id not in data["mentors"]:
            fail("メンターが見つかりません。", 404)
        return data["mentors"][mentor_id]

    def student_allowed(user, mentor_id):
        return user["role"] == "admin" or user["mentorId"] == mentor_id

    @app.after_request
    def headers(response):
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        if not request.path.startswith("/assets/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response

    @app.errorhandler(HTTPException)
    def handle_http(exc):
        return jsonify(error=exc.description), exc.code

    @app.get("/")
    def index():
        return redirect("/mentor-admin/")

    @app.get("/mentor-admin/")
    def workspace():
        html = (ROOT / "mentor-admin/index.html").read_text()
        html = re.sub(r'^  <script src="(?:\.\./mentors-data\.js|\./(?:seed|demo-api)\.js[^"]*)" defer></script>\n',
                      "", html, flags=re.M)
        return (html.replace("タマ活｜メンター管理デモ", "タマ活｜メンター管理")
                .replace('name="referrer" content="no-referrer"', 'name="referrer" content="same-origin"')
                .replace("form-action 'self'", "form-action 'self' https://accounts.google.com"))

    @app.get("/mentor-admin/<path:filename>")
    def admin_file(filename):
        if filename not in ADMIN_FILES:
            abort(404)
        return send_from_directory(ROOT / "mentor-admin", filename)

    @app.get("/assets/<path:filename>")
    def asset(filename):
        return send_from_directory(ROOT / "assets", filename)

    @app.get("/api/config")
    def config():
        return jsonify(mode="production", googleReady=ready,
                       publicSite="https://beyond-cafe-team.github.io/tamakatsu-preview/")

    @app.post("/auth/google")
    def start_login():
        if request.headers.get("Origin") != origin:
            fail("管理画面からログインしてください。", 403)
        if not ready:
            return redirect("/mentor-admin/?auth=setup")
        raw = request.form.get("invite", "")
        if raw and not re.fullmatch(r"[A-Za-z0-9_-]{43}", raw):
            return redirect("/mentor-admin/?auth=invite")
        invite_key = digest(raw) if raw else None
        if invite_key:
            with connect() as db:
                invite = get_data(db)["invites"].get(invite_key)
                if not invite or invite["expires"] <= time.time():
                    return redirect("/mentor-admin/?auth=invite")
        if session.get("sid"):
            with connect(write=True) as db:
                db.execute("DELETE FROM login_session WHERE id=?", (session["sid"],))
        session.clear()
        state = secrets.token_urlsafe(32)
        session["login"] = {"state": state, "invite": invite_key, "expires": time.time() + 600}
        try:
            return google.authorize_redirect(
                origin + "/auth/google/callback", state=state,
                nonce=secrets.token_urlsafe(32), prompt="select_account",
            )
        except Exception:
            app.logger.warning("Google authorization discovery failed")
            return redirect("/mentor-admin/?auth=failed")

    @app.get("/auth/google/callback")
    def finish_login():
        login = session.pop("login", {})
        callback_state = request.args.get("state", "")
        if (not login or login["expires"] <= time.time()
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", callback_state)
                or not secrets.compare_digest(login["state"], callback_state)):
            return redirect("/mentor-admin/?auth=failed")
        try:
            claims = google.authorize_access_token()["userinfo"]
            email = str(claims["email"]).strip().lower()
            sub = claims["sub"]
            hosted = str(claims.get("hd", "")).lower()
            if (claims.get("email_verified") is not True or not EMAIL.fullmatch(email)
                    or not isinstance(sub, str) or not sub):
                return redirect("/mentor-admin/?auth=denied")
        except Exception:
            return redirect("/mentor-admin/?auth=failed")
        admin = hosted == DOMAIN and email.endswith("@" + DOMAIN)
        sid = secrets.token_urlsafe(32)
        expires = int(time.time()) + SESSION_AGE
        with connect(write=True) as db:
            data = get_data(db)
            accounts = data["accounts"]
            account = accounts.get(email)
            if account and (not account["active"] or account["sub"] != sub):
                return redirect("/mentor-admin/?auth=denied")
            if login["invite"]:
                invite = data["invites"].get(login["invite"])
                if not invite or invite["expires"] <= time.time():
                    return redirect("/mentor-admin/?auth=invite")
                if invite["email"] != email or admin:
                    return redirect("/mentor-admin/?auth=match")
                if account and account["mentor_id"] != invite["mentor_id"]:
                    return redirect("/mentor-admin/?auth=denied")
                mentor = mentor_for(data, invite["mentor_id"])
                previous = accounts.get(mentor.get("ownerEmail"))
                if previous and previous is not account:
                    previous.update(active=False, mentor_id=None)
                mentor.update(ownerEmail=email, version=mentor["version"] + 1)
                account = dict(sub=sub, role="mentor", active=True, mentor_id=mentor["id"])
                accounts[email] = account
                del data["invites"][login["invite"]]
                audit(data, email, "mentor.accept_invite", mentor["id"])
            elif admin:
                if account and account["role"] != "admin":
                    return redirect("/mentor-admin/?auth=denied")
                accounts[email] = dict(sub=sub, role="admin", active=True, mentor_id=None)
            elif not account or account["role"] != "mentor":
                return redirect("/mentor-admin/?auth=denied")
            save(db, data)
            db.execute("DELETE FROM login_session WHERE expires <= ?", (int(time.time()),))
            db.execute("INSERT INTO login_session VALUES (?, ?)", (sid, expires))
        session.clear()
        session.permanent = True
        session.update(email=email, sub=sub, csrf=secrets.token_urlsafe(32), sid=sid)
        return redirect("/mentor-admin/")

    @app.route("/api/<path:resource>", methods=["GET", "POST", "PUT", "PATCH"])
    def private_api(resource):
        method = request.method
        write = method != "GET"
        with connect(write=write) as db:
            data = get_data(db)
            user = identity(db, data)
            if write and (request.headers.get("Origin") != origin or
                          not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), user["csrf"])):
                fail("ページを開き直してから再度お試しください。", 403)
            body = request.get_json(silent=True) if request.is_json else {}
            if not isinstance(body, dict):
                fail("入力内容を確認してください。")
            result = dispatch(db, data, user, resource, method, body)
            if write:
                save(db, data)
            return result

    def dispatch(db, data, user, resource, method, body):
        email = user["email"]
        if resource == "me" and method == "GET":
            return jsonify(user)
        if resource == "logout" and method == "POST":
            db.execute("DELETE FROM login_session WHERE id=?", (session["sid"],))
            session.clear()
            return jsonify(ok=True)
        if resource == "accounts" and method == "GET":
            require_admin(user)
            return jsonify(accounts=[dict(email=address, role=a["role"], mentor_id=a.get("mentor_id"),
                                          active=a["active"]) for address, a in data["accounts"].items()])
        if resource == "audit" and method == "GET":
            require_admin(user)
            return jsonify(events=data["events"][:100])
        if resource == "reviews" and method == "GET":
            return jsonify(reviews=[])
        if resource == "mentor-invites" and method == "POST":
            require_admin(user)
            address = email_address(body.get("email"))
            if address.endswith("@" + DOMAIN):
                fail("運営アカウントはGoogleログインからアクセスしてください。")
            mid = body.get("mentorId")
            if mid:
                mentor_for(data, mid)
            else:
                name = clean(body.get("name"), 40, required=True)
                mid = "mentor-" + secrets.token_hex(12)
                data["mentors"][mid] = dict(
                    id=mid, name=name, photo="/mentor-admin/photos/placeholder.svg", type="ACTG",
                    grade="", catch="", theme="", bio="", style="", university="", plans=[],
                    features=[], topics=[], recommend=[], career=[], version=1, updatedAt=0,
                )
            existing = data["accounts"].get(address)
            if existing and (not existing["active"] or existing["mentor_id"] != mid):
                fail("このメールアドレスは別の登録に使われています。", 409)
            now = time.time()
            data["invites"] = {key: value for key, value in data["invites"].items()
                               if value["expires"] > now and value["mentor_id"] != mid
                               and value["email"] != address}
            token = secrets.token_urlsafe(32)
            data["invites"][digest(token)] = dict(email=address, mentor_id=mid, expires=now + INVITE_AGE)
            audit(data, email, "mentor.invite", mid)
            return jsonify(url=origin + "/mentor-admin/#invite=" + token, id=mid), 201
        if resource == "mentors" and method == "GET":
            profiles = []
            for mid, mentor in data["mentors"].items():
                view = {**mentor, "canEdit": user["mentorId"] == mid}
                if user["role"] != "admin" and not view["canEdit"]:
                    view.pop("ownerEmail", None)
                profiles.append(view)
            return jsonify(mentors=profiles)
        profile_match = re.fullmatch(r"mentors/(mentor-[a-f0-9]+)(/photo)?", resource)
        if profile_match:
            mid, photo = profile_match.groups()
            mentor = mentor_for(data, mid)
            if photo and method == "GET":
                row = db.execute("SELECT image FROM photo WHERE id=?", (mid,)).fetchone()
                if not row:
                    abort(404)
                return Response(row[0], mimetype="image/webp")
            if user["mentorId"] != mid:
                fail("紐づけられたアカウントだけが編集できます。", 403)
            if photo and method == "POST":
                upload = request.files.get("photo")
                if not upload:
                    fail("写真を選択してください。")
                encoded = encode_photo(upload.stream.read(5 * 1024 * 1024 + 1))
                db.execute("INSERT OR REPLACE INTO photo VALUES (?,?)", (mid, encoded))
                mentor["photo"] = f"/api/mentors/{mid}/photo"
                action = "photo.update"
            elif not photo and method == "PUT":
                check_version(body, mentor)
                mentor.update(profile_values(body))
                action = "profile.update"
            else:
                abort(405)
            mentor.update(version=mentor["version"] + 1, updatedAt=int(time.time()))
            audit(data, email, action, mid)
            return jsonify(ok=True)
        if resource == "students" and method == "GET":
            return jsonify(students=[student_view(s) for s in data["students"].values()
                                     if student_allowed(user, s["mentorId"])])
        student_match = re.fullmatch(r"students/(student-[a-f0-9]+)", resource)
        if (resource == "students" and method == "POST") or student_match:
            students = data["students"]
            if student_match:
                sid = student_match.group(1)
                student = students.get(sid)
                if not student or not student_allowed(user, student["mentorId"]):
                    fail("学生が見つかりません。", 404)
                if method == "GET":
                    return jsonify(student=student_view(student), events=student["events"])
                if method != "PUT":
                    abort(405)
                check_version(body, student)
                mid = student["mentorId"]
                if body.get("mentorId") not in (None, mid):
                    fail("担当メンターは変更できません。")
                action = "student.update"
            else:
                sid = "student-" + secrets.token_hex(12)
                mid = mentor_for(data, body.get("mentorId"))["id"]
                if not student_allowed(user, mid):
                    fail("担当メンターを確認してください。", 403)
                student = dict(id=sid, mentorId=mid, version=0, events=[])
                action = "student.create"
            values = student_values(body)
            if values["email"] and any(s["id"] != sid and s["mentorId"] == mid and s["email"] == values["email"]
                                       for s in students.values()):
                fail("このメールアドレスの学生は登録済みです。", 409)
            now = int(time.time())
            student.update(values, updatedAt=now, version=student["version"] + 1)
            student["events"].insert(0, {**values, "at": now, "actor": email})
            students[sid] = student
            audit(data, email, action, sid)
            return jsonify(ok=True, id=sid), 201 if action == "student.create" else 200
        abort(404)

    return app


def student_view(student):
    return {key: value for key, value in student.items() if key != "events"}


def check_version(body, record):
    if body.get("version") != record["version"]:
        fail("ほかの画面で更新されています。再読み込みしてください。", 409)


def profile_values(body):
    fields = {"name": 40, "catch": 60, "theme": 120, "bio": 5000, "style": 2000, "university": 40}
    value = {k: clean(body.get(k), limit, required=k == "name") for k, limit in fields.items()}
    value["type"] = clean(body.get("type"), 4, True)
    value["grade"] = clean(body.get("grade"), 2)
    if not TYPE.fullmatch(value["type"]) or value["grade"] not in ("", "27", "28", "29"):
        fail("診断タイプと卒業年度を確認してください。")
    for key, count, limit in (("features", 3, 40), ("topics", 12, 60), ("recommend", 8, 200)):
        entries = body.get(key)
        if not isinstance(entries, list) or len(entries) > count:
            fail("入力数を確認してください。")
        value[key] = [clean(item, limit, True) for item in entries]
    career = body.get("career")
    if not isinstance(career, list) or len(career) > 8:
        fail("業種・職種を確認してください。")
    if any(not isinstance(item, dict) or item.get("kind") not in ("industry", "job", "status") for item in career):
        fail("業種・職種を確認してください。")
    value["career"] = [dict(kind=item["kind"], label=clean(item.get("label"), 60, True)) for item in career]
    plans = body.get("plans")
    if not isinstance(plans, list) or len(plans) > 3 or any(not isinstance(p, dict) for p in plans):
        fail("面談プランを確認してください。")
    value["plans"] = [
        dict(title=clean(p.get("title"), 50, True), text=clean(p.get("text"), 200),
             duration=clean(p.get("duration"), 20), place=clean(p.get("place"), 40) or "オンライン")
        for p in plans
    ]
    return value


def student_values(body):
    fields = dict(name=80, email=254, phone=40, university=120, graduation=4,
                  diagnosis=4, selectedAt=10, nextActionAt=10, notes=5000)
    value = {k: clean(body.get(k, ""), limit, required=k == "name") for k, limit in fields.items()}
    if value["email"]:
        value["email"] = email_address(value["email"])
    if value["graduation"] and not re.fullmatch(r"20\d{2}", value["graduation"]):
        fail("卒業年は西暦4桁で入力してください。")
    if value["diagnosis"] and not TYPE.fullmatch(value["diagnosis"]):
        fail("診断タイプを確認してください。")
    for field in ("selectedAt", "nextActionAt"):
        if value[field]:
            try:
                if date.fromisoformat(value[field]).isoformat() != value[field]:
                    raise ValueError()
            except ValueError:
                fail("日付を確認してください。")
    status = body.get("status")
    if status not in ("new", "contacted", "scheduled", "interviewed", "supporting", "completed", "closed"):
        fail("進捗を確認してください。")
    value["status"] = status
    return value


def encode_photo(raw):
    if len(raw) > 5 * 1024 * 1024:
        fail("画像は5MB以下にしてください。")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw), formats=["JPEG", "PNG", "WEBP"]) as image:
                if image.width * image.height > 20_000_000:
                    fail("画像の解像度が大きすぎます。")
                image = ImageOps.exif_transpose(image).convert("RGB")
                image.thumbnail((1000, 1000))
                output = io.BytesIO()
                image.save(output, "WEBP", quality=86)
                return output.getvalue()
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError,
            Image.DecompressionBombWarning):
        fail("JPEG・PNG・WebPの画像を選択してください。")
