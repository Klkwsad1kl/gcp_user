# gcp_user

Simple Flask user portal with:
- Sign up
- Log in / log out
- Forgot username
- Forgot password with reset token flow

## Project Structure

- `app.py` – Flask app and routes
- `templates/` – HTML templates
- `static/` – CSS

## Requirements

- Python 3.10+

Dependencies are listed in `requirements.txt`.

## Local Setup

From the project root:

1. Create a virtual environment:
	- macOS/Linux: `python3 -m venv .venv`

2. Activate it:
	- macOS/Linux: `source .venv/bin/activate`

3. Install dependencies:
	- `pip install -r requirements.txt`

## Run the App

Run:

- `DATABASE_URL=sqlite:///users.db python app.py`

The app starts on `http://127.0.0.1:8080` by default.

You can override the port:

- `PORT=5000 DATABASE_URL=sqlite:///users.db python app.py`

## Environment Variables

- `SECRET_KEY` (optional): Flask secret key.
- `SECRET_KEY_SECRET` (recommended for GCP): Secret Manager version resource for the Flask secret key.
- `DATABASE_URL`: SQLAlchemy DB URL.
- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`:
	alternative to `DATABASE_URL`; if `DATABASE_URL` is not set, all DB_* values are required.
- `DB_PASSWORD_SECRET`:
	Secret Manager version resource. If set, it is used when `DB_PASSWORD` is not set.

Example Cloud SQL PostgreSQL URL:

- `mysql+pymysql://DB_USER:DB_PASS@DB_HOST:3306/DB_NAME`

## Deploy Notes

The repository includes:
- `app.yaml`
- `Dockerfile`

These can be used as a base for Google Cloud deployment workflows.

### Deploy to App Engine + Cloud SQL (MySQL)

1. Create a Cloud SQL MySQL instance and database.
2. Enable required APIs (`appengine.googleapis.com`, `sqladmin.googleapis.com`).
3. Set DB settings in `app.yaml` (`INSTANCE_CONNECTION_NAME`, `DB_NAME`, `DB_USER`).
4. Create Secret Manager secrets for the Flask secret key and DB password.
5. Set `SECRET_KEY_SECRET` and `DB_PASSWORD_SECRET` in `app.yaml` to:
	`projects/PROJECT_ID/secrets/flask-secret-key/versions/latest`
	`projects/PROJECT_ID/secrets/db-password/versions/latest`
6. Grant the App Engine default service account `roles/secretmanager.secretAccessor`.
7. Grant the App Engine default service account `roles/cloudsql.client`.
8. Deploy:
	- `gcloud app deploy`

The app will auto-create the `users` table at startup if it does not exist.
