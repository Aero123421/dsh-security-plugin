# fastapi-notes (intentionally vulnerable test fixture)

> **INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy, do not install, do not run.**
> This directory is evaluation data for the dsh-security-plugin scanner. Nothing here is
> executed or installed by the test suite. Every credential-looking value is fake.

A multi-tenant note-taking API on FastAPI and the standard-library `sqlite3` module.
Users belong to an organization (`users.org_id`) and authenticate with an
itsdangerous-signed bearer token (`app/auth.py`).

## Layout

| Path | Purpose |
| --- | --- |
| `app/main.py` | App factory, router registration, `/auth/login` |
| `app/config.py` | Settings, including `SECRET_KEY` |
| `app/auth.py` | `get_current_user` dependency, password hashing |
| `app/db.py` | Per-request `sqlite3` connection dependency |
| `app/routers/notes.py` | Notes CRUD and search |
| `app/routers/preferences.py` | UI preferences stored in a cookie |
| `app/routers/diagnostics.py` | Ping and deployed-version endpoints |
| `app/routers/links.py` | Link preview for the editor |
| `app/routers/reports.py` | Organization activity report |
| `app/integrations/importer.py` | YAML note import |
| `requirements.txt` | Pinned production dependencies |

## Planted issues

See [`expected.json`](./expected.json) for exact lines, CWE, severity and expected detectors.

- **FN-01** IDOR: `GET /notes/{note_id}` requires a user but never compares `owner_id`.
- **FN-02** SQL injection: note search interpolates `q` into an f-string query.
- **FN-03** Insecure deserialization: the `notes_prefs` cookie is `pickle.loads`-ed.
- **FN-04** Command injection: `POST /diagnostics/ping` runs `ping` through a shell with the host.
- **FN-05** SSRF: `POST /links/preview` fetches any http(s) URL, following redirects.
- **FN-06** Tenant isolation: `POST /reports/activity` reads `org_id` from the request body
  instead of the caller's organization, so an admin of one org can read another org's members.
- **FN-07** Hard-coded `SECRET_KEY` (signs every bearer token).
- **FN-08 / FN-09** `requirements.txt` pins `PyYAML==5.3` and `requests==2.19.0`.

## Negative controls (must not be reported)

- Parameterized queries: `cursor.execute("... WHERE id = ?", (note_id,))` and friends.
- `yaml.safe_load` in the importer.
- `PUT /notes/{note_id}` checks `owner_id` and answers 404; `DELETE` scopes by `owner_id`.
- `subprocess.run(["git", "status", ...])` and `["git", "rev-parse", "HEAD"]`: argument lists, no shell, behind `require_admin`.
- `GET /notes` filters by the caller's id.
