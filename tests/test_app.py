"""
Unit tests for the GCP User Portal Flask application.
"""

import os
import tempfile
import pytest

os.environ["SECRET_KEY"] = "test-secret-key"

from app import app, init_db  # noqa: E402


@pytest.fixture
def client():
    """Create a test client with a fresh temporary database for every test."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    app.config["TESTING"] = True
    app.config["DATABASE"] = db_path

    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client

    os.close(db_fd)
    os.unlink(db_path)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def signup_user(client, username="testuser", email="test@example.com", password="password123"):
    return client.post(
        "/signup",
        data={
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password,
        },
        follow_redirects=True,
    )


def login_user(client, identifier="testuser", password="password123"):
    return client.post(
        "/login",
        data={"identifier": identifier, "password": password},
        follow_redirects=True,
    )


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------

class TestIndex:
    def test_index_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_index_shows_links_when_logged_out(self, client):
        response = client.get("/")
        assert b"Sign Up" in response.data
        assert b"Login" in response.data


# ---------------------------------------------------------------------------
# Sign Up
# ---------------------------------------------------------------------------

class TestSignup:
    def test_signup_page_loads(self, client):
        response = client.get("/signup")
        assert response.status_code == 200
        assert b"Create an Account" in response.data

    def test_signup_success(self, client):
        response = signup_user(client)
        assert response.status_code == 200
        assert b"Account created" in response.data

    def test_signup_duplicate_username(self, client):
        signup_user(client, username="duplicate", email="a@example.com")
        response = signup_user(client, username="duplicate", email="b@example.com")
        assert b"Username is already taken" in response.data

    def test_signup_duplicate_email(self, client):
        signup_user(client, username="user1", email="dup@example.com")
        response = signup_user(client, username="user2", email="dup@example.com")
        assert b"An account with that email already exists" in response.data

    def test_signup_short_password(self, client):
        response = client.post(
            "/signup",
            data={
                "username": "shortpass",
                "email": "short@example.com",
                "password": "abc",
                "confirm_password": "abc",
            },
            follow_redirects=True,
        )
        assert b"at least 8 characters" in response.data

    def test_signup_password_mismatch(self, client):
        response = client.post(
            "/signup",
            data={
                "username": "mismatch",
                "email": "mm@example.com",
                "password": "password123",
                "confirm_password": "different123",
            },
            follow_redirects=True,
        )
        assert b"do not match" in response.data

    def test_signup_missing_fields(self, client):
        response = client.post(
            "/signup",
            data={"username": "", "email": "", "password": "", "confirm_password": ""},
            follow_redirects=True,
        )
        assert b"required" in response.data


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

class TestLogin:
    def test_login_page_loads(self, client):
        response = client.get("/login")
        assert response.status_code == 200
        assert b"Log In" in response.data

    def test_login_success_with_username(self, client):
        signup_user(client)
        response = login_user(client, identifier="testuser")
        assert b"Welcome back" in response.data

    def test_login_success_with_email(self, client):
        signup_user(client, email="login@example.com")
        response = login_user(client, identifier="login@example.com")
        assert b"Welcome back" in response.data

    def test_login_wrong_password(self, client):
        signup_user(client)
        response = login_user(client, password="wrongpassword")
        assert b"Invalid username/email or password" in response.data

    def test_login_unknown_user(self, client):
        response = login_user(client, identifier="nobody")
        assert b"Invalid username/email or password" in response.data


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

class TestLogout:
    def test_logout_redirects_unauthenticated(self, client):
        response = client.get("/logout", follow_redirects=True)
        assert b"Please log in" in response.data

    def test_logout_clears_session(self, client):
        signup_user(client)
        login_user(client)
        response = client.get("/logout", follow_redirects=True)
        assert b"logged out" in response.data


# ---------------------------------------------------------------------------
# Forgot Password / Reset Password
# ---------------------------------------------------------------------------

class TestForgotPassword:
    def test_forgot_password_page_loads(self, client):
        response = client.get("/forgot-password")
        assert response.status_code == 200
        assert b"Reset Your Password" in response.data

    def test_forgot_password_known_email(self, client):
        signup_user(client, email="fp@example.com")
        response = client.post(
            "/forgot-password",
            data={"email": "fp@example.com"},
            follow_redirects=True,
        )
        assert b"reset link" in response.data.lower()

    def test_forgot_password_unknown_email(self, client):
        response = client.post(
            "/forgot-password",
            data={"email": "nobody@example.com"},
            follow_redirects=True,
        )
        # Should show the same generic message (no user enumeration)
        assert response.status_code == 200

    def test_reset_password_invalid_token(self, client):
        response = client.get("/reset-password/invalidtoken", follow_redirects=True)
        assert b"Invalid or expired" in response.data

    def test_reset_password_full_flow(self, client):
        signup_user(client, email="reset@example.com")

        # Request a reset token
        client.post("/forgot-password", data={"email": "reset@example.com"})

        # Retrieve the token directly from the DB
        with app.app_context():
            from app import get_db
            user = get_db().execute(
                "SELECT reset_token FROM users WHERE email = ?", ("reset@example.com",)
            ).fetchone()
            token = user["reset_token"]

        assert token is not None

        # Use the token to set a new password
        response = client.post(
            f"/reset-password/{token}",
            data={"password": "newpassword1", "confirm_password": "newpassword1"},
            follow_redirects=True,
        )
        assert b"Password updated successfully" in response.data

        # Login with new password
        response = login_user(client, identifier="testuser", password="newpassword1")
        assert b"Welcome back" in response.data


# ---------------------------------------------------------------------------
# Forgot Username
# ---------------------------------------------------------------------------

class TestForgotUsername:
    def test_forgot_username_page_loads(self, client):
        response = client.get("/forgot-username")
        assert response.status_code == 200
        assert b"Find Your Username" in response.data

    def test_forgot_username_known_email(self, client):
        signup_user(client, username="findme", email="findme@example.com")
        response = client.post(
            "/forgot-username",
            data={"email": "findme@example.com"},
            follow_redirects=True,
        )
        assert b"findme" in response.data

    def test_forgot_username_unknown_email(self, client):
        response = client.post(
            "/forgot-username",
            data={"email": "nobody@example.com"},
            follow_redirects=True,
        )
        assert response.status_code == 200
