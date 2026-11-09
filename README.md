# Store Account

Python 3.12 / FastAPI. PostgreSQL via `DATABASE_URL`. Requires random `JWT_SECRET` and `INTERNAL_AUTH_KEY` with at least 32 characters.

Endpoints: `POST /accounts`, `GET /accounts/me`, internal `POST /internal/credentials/verify`, `/health-check`, `/ready`, `/metrics`. Email is unique and normalized; passwords are hashed using Argon2id. Account identity comes from a validated JWT, never a client header.

From this directory: `pip install -r requirements.txt` then `python -m pytest -q`. Production execution: `uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-access-log`.

Dockerfile, Jenkinsfile and `k8s/k8s.yaml` belong to this repository. For integration, local database, secrets and deployment instructions, see [store-root](https://github.com/Microserv-1/store-root) and [documentation](https://github.com/Microserv-1/store-docs-a). Routes are provisional until the official Account exercise is reviewed.
