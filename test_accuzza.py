import os
import re
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("MASTER_PASSWORD", "test-master-password")

TEST_DB = "/tmp/accuzza_test.db"


def _clean_db():
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


@pytest.fixture(autouse=True)
def _setup_env_and_db():
    os.environ["ACCUZZA_DB_PATH"] = TEST_DB
    _clean_db()
    from server import init_db
    init_db()
    yield
    _clean_db()


@pytest.fixture
def client():
    from server import app
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth_client():
    from server import app
    with TestClient(app) as c:
        r = c.post("/api/login", json={"password": "test-master-password"})
        assert r.status_code == 200, "login must succeed for auth_client fixture"
        yield c


# ─── Auth ──────────────────────────────────────────────────


class TestAuth:
    def test_login_with_wrong_password_returns_401(self, client):
        r = client.post("/api/login", json={"password": "wrong"})
        assert r.status_code == 401
        assert r.json()["detail"] == "Invalid master password"

    def test_login_with_correct_password_returns_200_and_sets_cookie(self, client):
        r = client.post("/api/login", json={"password": "test-master-password"})
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert "session_id" in r.cookies

    def test_check_returns_401_without_auth(self, client):
        r = client.get("/api/check")
        assert r.status_code == 401

    def test_check_returns_200_with_valid_session(self, auth_client):
        r = auth_client.get("/api/check")
        assert r.status_code == 200
        assert r.json()["ok"] is True


# ─── Link creation ─────────────────────────────────────────


class TestCreateLink:
    def test_create_requires_auth(self, client):
        r = client.post("/api/links", json={"url": "https://example.com"})
        assert r.status_code == 401

    def test_create_auto_generates_6_char_code(self, auth_client):
        r = auth_client.post("/api/links", json={"url": "https://example.com"})
        assert r.status_code == 200
        code = r.json()["code"]
        assert re.match(r"^[a-z0-9]{6}$", code), f"expected 6-char code, got {code!r}"

    def test_create_with_custom_code(self, auth_client):
        r = auth_client.post("/api/links", json={
            "url": "https://example.com", "code": "my-link"
        })
        assert r.status_code == 200
        assert r.json()["code"] == "my-link"

    def test_create_duplicate_code_returns_409(self, auth_client):
        auth_client.post("/api/links", json={
            "url": "https://a.com", "code": "dup"
        })
        r = auth_client.post("/api/links", json={
            "url": "https://b.com", "code": "dup"
        })
        assert r.status_code == 409
        assert "already taken" in r.json()["detail"].lower()

    def test_create_invalid_code_returns_400(self, auth_client):
        r = auth_client.post("/api/links", json={
            "url": "https://example.com", "code": "invalid chars!!!"
        })
        assert r.status_code == 400

    def test_create_with_password(self, auth_client):
        r = auth_client.post("/api/links", json={
            "url": "https://example.com", "code": "pwd-link",
            "password": "hunter2"
        })
        assert r.status_code == 200
        assert r.json()["code"] == "pwd-link"

    def test_create_empty_url_returns_400(self, auth_client):
        r = auth_client.post("/api/links", json={"url": ""})
        assert r.status_code == 400

    def test_create_prepends_https(self, auth_client):
        r = auth_client.post("/api/links", json={"url": "example.com"})
        assert r.status_code == 200
        r2 = auth_client.get("/api/links")
        assert r2.json()["links"][0]["url"] == "https://example.com"


# ─── Link listing ──────────────────────────────────────────


class TestListLinks:
    def test_list_requires_auth(self, client):
        r = client.get("/api/links")
        assert r.status_code == 401

    def test_list_returns_all_links(self, auth_client):
        auth_client.post("/api/links", json={
            "url": "https://a.com", "code": "a"
        })
        auth_client.post("/api/links", json={
            "url": "https://b.com", "code": "b"
        })
        r = auth_client.get("/api/links")
        assert r.status_code == 200
        assert len(r.json()["links"]) == 2

    def test_list_shows_click_count(self, auth_client):
        auth_client.post("/api/links", json={
            "url": "https://example.com", "code": "cnt"
        })
        r = auth_client.get("/api/links")
        assert r.json()["links"][0]["click_count"] == 0

    def test_list_shows_has_password(self, auth_client):
        auth_client.post("/api/links", json={
            "url": "https://a.com", "code": "open"
        })
        auth_client.post("/api/links", json={
            "url": "https://b.com", "code": "locked",
            "password": "secret"
        })
        r = auth_client.get("/api/links")
        links = {l["code"]: l for l in r.json()["links"]}
        assert links["open"]["has_password"] == 0
        assert links["locked"]["has_password"] == 1

    def test_list_empty_returns_empty_array(self, auth_client):
        r = auth_client.get("/api/links")
        assert r.json()["links"] == []


# ─── Redirect (unprotected) ────────────────────────────────


class TestRedirectUnprotected:
    def test_redirect_unknown_code_returns_404(self, client):
        r = client.get("/nosuchcode")
        assert r.status_code == 404

    def test_redirect_unprotected_link_returns_302(self, auth_client):
        auth_client.post("/api/links", json={
            "url": "https://example.com", "code": "go"
        })
        r = auth_client.get("/go", follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "https://example.com"

    def test_redirect_unprotected_increments_click_count(self, auth_client):
        auth_client.post("/api/links", json={
            "url": "https://example.com", "code": "cc"
        })
        client = auth_client
        client.get("/cc", follow_redirects=False)
        r = client.get("/api/links")
        assert r.json()["links"][0]["click_count"] == 1

    def test_redirect_multiple_clicks_increment(self, auth_client):
        auth_client.post("/api/links", json={
            "url": "https://example.com", "code": "mc"
        })
        for _ in range(5):
            auth_client.get("/mc", follow_redirects=False)
        r = auth_client.get("/api/links")
        assert r.json()["links"][0]["click_count"] == 5


# ─── Redirect (password-protected) ────────────────────────


class TestRedirectProtected:
    @pytest.fixture(autouse=True)
    def _create_protected(self, auth_client):
        auth_client.post("/api/links", json={
            "url": "https://secret.example.com",
            "code": "secret",
            "password": "opensesame"
        })
        self.link_code = "secret"
        self.link_pwd = "opensesame"

    def test_visit_password_link_returns_html_page(self, client):
        r = client.get(f"/{self.link_code}")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert "Protected Link" in r.text
        assert "Unlock" in r.text

    def test_password_submit_wrong_password_returns_403(self, client):
        r = client.post(f"/{self.link_code}", json={"password": "wrong"})
        assert r.status_code == 403
        assert "Wrong password" in r.json()["detail"]

    def test_password_submit_correct_returns_redirect_json(self, client):
        r = client.post(f"/{self.link_code}", json={"password": self.link_pwd})
        assert r.status_code == 200
        data = r.json()
        assert data["redirect"] == "https://secret.example.com"

    def test_password_submit_correct_increments_click_count(self, auth_client, client):
        client.post(f"/{self.link_code}", json={"password": self.link_pwd})
        r = auth_client.get("/api/links")
        assert r.json()["links"][0]["click_count"] == 1

    def test_password_submit_wrong_does_not_increment(self, auth_client, client):
        client.post(f"/{self.link_code}", json={"password": "wrong"})
        r = auth_client.get("/api/links")
        assert r.json()["links"][0]["click_count"] == 0

    def test_password_page_js_has_no_unescaped_double_braces(self, client):
        r = client.get(f"/{self.link_code}")
        assert "{{" not in r.text, "password page has unescaped {{ in output"
        assert "function unlock()" in r.text
        assert "document.getElementById('pwd').addEventListener" in r.text


# ─── Delete ────────────────────────────────────────────────


class TestDelete:
    def test_delete_requires_auth(self, client, auth_client):
        auth_client.post("/api/links", json={
            "url": "https://example.com", "code": "delme"
        })
        r = auth_client.get("/api/links")
        link_id = r.json()["links"][0]["id"]

        r2 = client.delete(f"/api/links/{link_id}")
        assert r2.status_code == 401

    def test_delete_removes_link(self, auth_client):
        auth_client.post("/api/links", json={
            "url": "https://example.com", "code": "delme"
        })
        r = auth_client.get("/api/links")
        assert len(r.json()["links"]) == 1
        link_id = r.json()["links"][0]["id"]

        r2 = auth_client.delete(f"/api/links/{link_id}")
        assert r2.status_code == 200

        r3 = auth_client.get("/api/links")
        assert r3.json()["links"] == []

    def test_delete_non_existent_returns_404(self, auth_client):
        r = auth_client.delete("/api/links/99999")
        assert r.status_code == 404
