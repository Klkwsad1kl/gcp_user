"""
GCP User Management Application
Supports: sign-up, login, forgot password, forgot username
"""

import os
import secrets
from functools import wraps
from typing import Optional
from urllib.parse import quote_plus

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import create_engine, text
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from google.cloud import secretmanager
except ImportError:  # pragma: no cover - only needed when using Secret Manager
    secretmanager = None

app = Flask(__name__)
app.config.setdefault("DATABASE_URL", os.environ.get("DATABASE_URL"))


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    """Return a per-request SQLAlchemy connection."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = get_engine().connect()
    return db


def get_database_url():
    """Resolve active database URL from config/env."""
    database_url = app.config.get("DATABASE_URL")
    if database_url:
        return database_url

    instance_connection_name = os.environ.get("INSTANCE_CONNECTION_NAME")
    db_host = os.environ.get("DB_HOST")
    db_name = os.environ.get("DB_NAME")
    db_user = os.environ.get("DB_USER")
    db_password = os.environ.get("DB_PASSWORD") or get_secret_from_env(
        "DB_PASSWORD_SECRET"
    )
    db_port = os.environ.get("DB_PORT", "3306")

    if all([instance_connection_name, db_name, db_user, db_password]):
        return (
            "mysql+pymysql://"
            f"{quote_plus(db_user)}:{quote_plus(db_password)}"
            f"@/{db_name}?unix_socket=/cloudsql/{instance_connection_name}"
        )

    if all([db_host, db_name, db_user, db_password]):
        return (
            "mysql+pymysql://"
            f"{quote_plus(db_user)}:{quote_plus(db_password)}"
            f"@{db_host}:{db_port}/{db_name}"
        )

    raise RuntimeError(
        "Database configuration is required. Set DATABASE_URL or "
        "INSTANCE_CONNECTION_NAME, DB_NAME, DB_USER, and DB_PASSWORD "
        "(or DB_PASSWORD_SECRET), or DB_HOST, DB_PORT, DB_NAME, DB_USER, "
        "and DB_PASSWORD (or DB_PASSWORD_SECRET)."
    )


def get_secret_from_env(secret_env_var: str) -> Optional[str]:
    """Resolve a secret value from Secret Manager using env var resource name."""
    secret_resource_name = os.environ.get(secret_env_var)
    if not secret_resource_name:
        return None

    if secretmanager is None:
        raise RuntimeError(
            "google-cloud-secret-manager is required when using "
            f"{secret_env_var}."
        )

    cache_attr = f"_cached_{secret_env_var.lower()}"
    cached_value = getattr(app, cache_attr, None)
    if cached_value:
        return cached_value

    client = secretmanager.SecretManagerServiceClient()
    response = client.access_secret_version(name=secret_resource_name)
    secret_value = response.payload.data.decode("utf-8")
    setattr(app, cache_attr, secret_value)
    return secret_value


app.secret_key = (
    os.environ.get("SECRET_KEY")
    or get_secret_from_env("SECRET_KEY_SECRET")
    or secrets.token_hex(32)
)


def get_engine():
    """Return (and cache) the SQLAlchemy engine on the Flask app."""
    database_url = get_database_url()
    cached_engine = getattr(app, "_engine", None)
    cached_url = getattr(app, "_engine_url", None)

    if cached_engine is None or cached_url != database_url:
        app._engine = create_engine(database_url, future=True, pool_pre_ping=True)
        app._engine_url = database_url

    return app._engine


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables if they do not exist."""
    with app.app_context():
        engine = get_engine()
        if engine.dialect.name == "postgresql":
            create_users_sql = text(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id              SERIAL PRIMARY KEY,
                    username        VARCHAR(255) NOT NULL UNIQUE,
                    email           VARCHAR(255) NOT NULL UNIQUE,
                    password_hash   TEXT NOT NULL,
                    reset_token     TEXT,
                    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        elif engine.dialect.name == "mysql":
            create_users_sql = text(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id              INTEGER PRIMARY KEY AUTO_INCREMENT,
                    username        VARCHAR(255) NOT NULL UNIQUE,
                    email           VARCHAR(255) NOT NULL UNIQUE,
                    password_hash   TEXT NOT NULL,
                    reset_token     TEXT,
                    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        elif engine.dialect.name == "sqlite":
            create_users_sql = text(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    username        TEXT    NOT NULL UNIQUE,
                    email           TEXT    NOT NULL UNIQUE,
                    password_hash   TEXT    NOT NULL,
                    reset_token     TEXT,
                    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        else:
            raise RuntimeError(f"Unsupported database dialect: {engine.dialect.name}")

        with engine.begin() as connection:
            connection.execute(create_users_sql)
        app._initialized_db_url = get_database_url()


def ensure_db_initialized():
    """Initialize the database once per configured database URL."""
    database_url = get_database_url()
    if getattr(app, "_initialized_db_url", None) == database_url:
        return
    init_db()


@app.before_request
def initialize_database_on_first_request():
    ensure_db_initialized()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def get_user_by_id(user_id):
    return get_db().execute(
        text("SELECT * FROM users WHERE id = :id"), {"id": user_id}
    ).mappings().fetchone()


def get_user_by_email(email):
    return get_db().execute(
        text("SELECT * FROM users WHERE email = :email"), {"email": email.lower()}
    ).mappings().fetchone()


def get_user_by_username(username):
    return get_db().execute(
        text("SELECT * FROM users WHERE username = :username"), {"username": username}
    ).mappings().fetchone()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    user = None
    if "user_id" in session:
        user = get_user_by_id(session["user_id"])
    return render_template("index.html", user=user)


# -- Sign Up ------------------------------------------------------------------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = []
        if not username:
            errors.append("Username is required.")
        if not email:
            errors.append("Email is required.")
        if not password:
            errors.append("Password is required.")
        elif len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        elif password != confirm:
            errors.append("Passwords do not match.")

        if not errors:
            db = get_db()
            if db.execute(
                text("SELECT id FROM users WHERE username = :username"),
                {"username": username},
            ).fetchone():
                errors.append("Username is already taken.")
            if db.execute(
                text("SELECT id FROM users WHERE email = :email"),
                {"email": email},
            ).fetchone():
                errors.append("An account with that email already exists.")

        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("signup.html", username=username, email=email)

        engine = get_engine()
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO users (username, email, password_hash) "
                    "VALUES (:username, :email, :password_hash)"
                ),
                {
                    "username": username,
                    "email": email,
                    "password_hash": generate_password_hash(password),
                },
            )
        flash("Account created! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


# -- Login --------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        user = None
        if "@" in identifier:
            user = get_user_by_email(identifier)
        else:
            user = get_user_by_username(identifier)

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username/email or password.", "danger")
            return render_template("login.html", identifier=identifier)

        session.clear()
        session["user_id"] = user["id"]
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for("index"))

    return render_template("login.html")


# -- Logout -------------------------------------------------------------------

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# -- Forgot Password ----------------------------------------------------------

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("Please enter your email address.", "danger")
            return render_template("forgot_password.html")

        user = get_user_by_email(email)
        if user:
            token = secrets.token_urlsafe(32)
            engine = get_engine()
            with engine.begin() as connection:
                connection.execute(
                    text("UPDATE users SET reset_token = :token WHERE id = :id"),
                    {"token": token, "id": user["id"]},
                )
            # In a real app we would email the reset link.
            # For demo purposes we surface the link directly.
            reset_url = url_for("reset_password", token=token, _external=True)
            flash(
                f"A password reset link has been generated. "
                f"Reset link: {reset_url}",
                "info",
            )
        else:
            # Avoid user-enumeration by showing the same message.
            flash(
                "If that email is registered, a reset link has been generated.",
                "info",
            )
        return redirect(url_for("forgot_password"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db = get_db()
    user = db.execute(
        text("SELECT * FROM users WHERE reset_token = :token"), {"token": token}
    ).mappings().fetchone()

    if user is None:
        flash("Invalid or expired reset token.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not password or len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("reset_password.html", token=token)
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)

        engine = get_engine()
        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE users "
                    "SET password_hash = :password_hash, reset_token = NULL "
                    "WHERE id = :id"
                ),
                {"password_hash": generate_password_hash(password), "id": user["id"]},
            )
        flash("Password updated successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


# -- Forgot Username ----------------------------------------------------------

@app.route("/forgot-username", methods=["GET", "POST"])
def forgot_username():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("Please enter your email address.", "danger")
            return render_template("forgot_username.html")

        user = get_user_by_email(email)
        if user:
            flash(f"Your username is: {user['username']}", "success")
        else:
            flash(
                "If that email is registered, the username has been shown above.",
                "info",
            )
        return redirect(url_for("forgot_username"))

    return render_template("forgot_username.html")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ensure_db_initialized()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
