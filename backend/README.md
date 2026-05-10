# SQLHawk Backend

FastAPI backend for SQLHawk. It keeps the API data (users, scans) separate from the target database being analyzed.

## Features
- JWT auth (register/login)
- API DB (Supabase Postgres supported) and target DB are separate
- Metadata-only vulnerability checks for MySQL, MySQL Workbench, and PostgreSQL
- Risk score and strength score
- Report output in JSON, HTML, or PDF

## Quick start
1) Create and activate a virtual environment
2) Install dependencies
3) Configure .env
4) Run the server

Example:
```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Key endpoints
- POST /auth/register
- POST /auth/login
- GET /auth/me
- PUT /users/me
- POST /scans
- GET /scans
- GET /scans/{id}
- GET /reports/{id}?format=html|json|pdf

## Example scan request
```
POST /scans
{
  "target_name": "db-produccion",
  "target": {
    "db_type": "postgres",
    "host": "127.0.0.1",
    "port": 5432,
    "username": "readonly",
    "password": "secret",
    "database": "app_db",
    "ssl": false
  }
}
```

## Supabase setup
- Set `API_DATABASE_URL` to your Supabase Postgres connection string.
- Keep `sslmode=require` in the URL so connections are encrypted.
- The PDF reports are stored in `REPORTS_DIR` (default `./data/reports`).

## Notes
- The scanner reads metadata only and does not modify the target database.
- python-nmap is included for an optional port exposure check. Install the nmap binary if you want that check enabled.
