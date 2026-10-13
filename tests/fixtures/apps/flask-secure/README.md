# flask-secure (test fixture for false-positive measurement)

> **INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy, do not install, do not run.**
> This directory is evaluation data for the dsh-security-plugin scanner. Nothing here is
> executed or installed by the test suite.

"Docvault": a Flask document locker written to be **mostly secure**. It exists to measure
false positives: a scanner should report exactly one issue here.

Security controls in place:

- `@login_required` on every route except sign-in and the token-based share download.
- Every per-document route goes through `owned_document_or_404()`, which filters by
  `owner_id=current_user.id` and answers 404 for other users' documents.
- SQLAlchemy ORM queries only; no raw SQL.
- Uploads are stored under a random `secrets.token_urlsafe` name; downloads use
  `send_from_directory` with the fixed upload directory and that stored name.
- CSRF protection through Flask-WTF `CSRFProtect` (forms and the logout/delete/share POSTs).
- Templates rely on Jinja2 autoescaping (`render_template`, no `|safe`, no `Markup`).
- Post-login `?next=` is restricted to same-site relative paths.
- Share links use `secrets.token_urlsafe(32)` and expire.
- `SECRET_KEY` comes from the environment; security headers are set on every response.

## Layout

| Path | Purpose |
| --- | --- |
| `wsgi.py` | Production entry point (`gunicorn wsgi:app`) |
| `app/__init__.py` | App factory, extensions, blueprints, security headers |
| `app/config.py` | Base, production and testing configuration |
| `app/models.py` | `User`, `Document`, `ShareLink` |
| `app/auth.py`, `app/documents.py`, `app/sharing.py` | Blueprints |
| `app/forms.py` | Flask-WTF forms |
| `app/templates/` | Jinja2 templates |

## The one real issue

- **FS-01** (low): `ProductionConfig.SESSION_COOKIE_SECURE = False` in `app/config.py`, so the
  session cookie may be sent over plain HTTP and intercepted. Fix: set it to `True`
  (and keep `PREFERRED_URL_SCHEME = "https"` with HSTS).

Everything else listed in [`expected.json`](./expected.json) under `negatives` is a control
that must not be reported. `TestingConfig.WTF_CSRF_ENABLED = False` is test-only configuration
(`APP_ENV=testing`) and is not a finding.
