import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from authlib.integrations.flask_client.apps import FlaskOAuth2App

from app import create_app


ORIGIN = "https://admin.example.test"


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.database = str(Path(folder.name) / "app.sqlite3")
        self.app = create_app({
            "TESTING": True, "PUBLIC_ORIGIN": ORIGIN, "DATABASE": self.database,
            "SECRET_KEY": "test session key only, never used for deployment",
            "GOOGLE_CLIENT_ID": "client", "GOOGLE_CLIENT_SECRET": "test",
        })
        self.admin = self.app.test_client()

    def get(self, client, path):
        return client.get(path, base_url=ORIGIN)

    def write(self, client, path, body=None, method="POST", csrf=True):
        headers = {"Origin": ORIGIN}
        if csrf:
            headers["X-CSRF-Token"] = self.get(client, "/api/me").json["csrf"]
        return client.open(path, json=body, method=method, base_url=ORIGIN, headers=headers)

    def sign_in(self, client, email, hd=None, verified=True, invite="", state_override=None, sub=None):
        metadata = {"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth"}
        with patch.object(FlaskOAuth2App, "load_server_metadata", return_value=metadata):
            response = client.post("/auth/google", data={"invite": invite}, base_url=ORIGIN,
                                   headers={"Origin": ORIGIN})
        if not response.location.startswith("https://accounts.google.com/"):
            return response.location
        query = parse_qs(urlsplit(response.location).query)
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["redirect_uri"], [ORIGIN + "/auth/google/callback"])
        self.assertTrue(query["nonce"][0])
        claims = {"email": email, "sub": sub or email, "hd": hd, "email_verified": verified}
        with patch.object(FlaskOAuth2App, "authorize_access_token", return_value={"userinfo": claims}):
            callback = client.get("/auth/google/callback", query_string={
                "state": state_override or query["state"][0], "code": "provider-code",
            }, base_url=ORIGIN)
        return callback.location

    def login_admin(self):
        self.assertEqual(self.sign_in(self.admin, "staff@beyond-cafe.com", "beyond-cafe.com"), "/mentor-admin/")

    def issue(self, email, mentor_id="mentor-01"):
        response = self.write(self.admin, "/api/mentor-invites", {"email": email, "mentorId": mentor_id})
        self.assertEqual(response.status_code, 201, response.json)
        return urlsplit(response.json["url"]).fragment.split("=", 1)[1]

    def test_domain_and_email_must_both_be_verified(self):
        self.assertEqual(self.get(self.admin, "/api/mentors").status_code, 401)
        self.assertIn("denied", self.sign_in(self.admin, "staff@beyond-cafe.com", "other.test"))
        self.assertIn("denied", self.sign_in(self.admin, "external@example.test", "beyond-cafe.com"))
        self.assertIn("denied", self.sign_in(self.admin, "staff@beyond-cafe.com", "beyond-cafe.com", False))
        self.assertIn("failed", self.sign_in(self.admin, "staff@beyond-cafe.com", "beyond-cafe.com",
                                             state_override="different"))
        self.login_admin()
        self.assertEqual(self.get(self.admin, "/api/me").json["role"], "admin")

    def test_invite_is_email_bound_once_and_mentor_permissions_are_scoped(self):
        self.login_admin()
        email = "mentor@gmail.com"
        self.assertEqual(self.write(self.admin, "/api/mentor-invites", {"email": email}, csrf=False).status_code, 403)
        token = self.issue(email)
        client = self.app.test_client()
        self.assertIn("denied", self.sign_in(client, email))
        self.assertIn("match", self.sign_in(client, "someone@gmail.com", invite=token))
        self.assertEqual(self.sign_in(client, email, invite=token), "/mentor-admin/")
        self.assertEqual(self.get(client, "/api/me").json["mentorId"], "mentor-01")
        self.assertEqual(self.write(client, "/api/mentor-invites", {"email": "other@gmail.com"}).status_code, 403)
        self.assertEqual(self.write(client, "/api/mentors/mentor-02", {}, "PUT").status_code, 403)
        profile = next(p for p in self.get(client, "/api/mentors").json["mentors"] if p["canEdit"])
        profile["catch"] = "更新"
        self.assertEqual(self.write(client, "/api/mentors/mentor-01", profile, "PUT").status_code, 200)
        student = self.write(client, "/api/students", {"mentorId": "mentor-01", "name": "確認用", "status": "new"})
        self.assertEqual(student.status_code, 201)
        other = self.app.test_client()
        self.assertIn("invite", self.sign_in(other, email, invite=token))
        self.assertEqual(self.sign_in(other, email), "/mentor-admin/")
        self.assertEqual(self.get(other, "/api/students/" + student.json["id"]).status_code, 200)
        another_token = self.issue("other@gmail.com", "mentor-02")
        self.assertEqual(self.sign_in(other, "other@gmail.com", invite=another_token), "/mentor-admin/")
        self.assertEqual(self.get(other, "/api/students").json["students"], [])
        self.assertEqual(self.get(other, "/api/students/" + student.json["id"]).status_code, 404)
        self.assertEqual(self.get(other, "/api/accounts").status_code, 403)

    def test_reissue_expiry_and_logout(self):
        self.login_admin()
        first = self.issue("mentor@gmail.com")
        second = self.issue("mentor@gmail.com")
        client = self.app.test_client()
        self.assertIn("invite", self.sign_in(client, "mentor@gmail.com", invite=first))
        with sqlite3.connect(self.database) as db:
            data = json.loads(db.execute("SELECT data FROM workspace").fetchone()[0])
            next(iter(data["invites"].values()))["expires"] = 0
            db.execute("UPDATE workspace SET data=?", (json.dumps(data),))
        self.assertIn("invite", self.sign_in(client, "mentor@gmail.com", invite=second))
        before_logout = self.admin.get_cookie(self.app.config["SESSION_COOKIE_NAME"], domain="admin.example.test")
        self.assertTrue(before_logout.secure)
        self.assertTrue(before_logout.http_only)
        self.assertEqual(self.write(self.admin, "/api/logout").status_code, 200)
        self.admin.set_cookie(before_logout.key, before_logout.value, domain=before_logout.domain)
        self.assertEqual(self.get(self.admin, "/api/me").status_code, 401)

    def test_production_page_excludes_demo_and_accepts_google_form_navigation(self):
        html = self.get(self.admin, "/mentor-admin/").get_data(as_text=True)
        self.assertNotIn("demo-api.js", html)
        self.assertNotIn("seed.js", html)
        self.assertIn("form-action 'self' https://accounts.google.com", html)
        self.assertEqual(self.get(self.admin, "/mentor-admin/demo-api.js").status_code, 404)
