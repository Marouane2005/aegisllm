# Contributing

Issues and pull requests are welcome. Bug reports that include a failing test are the easiest to land.

## Setup

Python 3.11 or 3.12, Postgres 16, Redis 7, Node 20.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
# Point POSTGRES_HOST and REDIS_URL at the services you just started.
alembic upgrade head
pytest
ruff check app tests
```

Frontend:

```bash
cd frontend
npm ci
npm run lint
npm run typecheck
npm run build
```

`scripts/check_env_example.py` must keep passing. If you add a setting, add it to `.env.example` with a comment that says how to generate the value. Do not commit a real secret. `.env` is gitignored.

## Tests

The suite talks to a real Postgres. The defaults in `tests/conftest.py` are user `test`, password `test`, database `test` on localhost. Set `REDIS_URL=redis://localhost:6379/0` if you want the limiter tests to hit Redis; otherwise they use in-memory storage.

Injection changes should keep `tests/test_injection_corpus.py` green and should not quietly delete benign controls to make the score look better. If a new pattern false-positives, fix the pattern or move that string into the attack list and say why in the pull request.

## Pull requests

- Keep the change focused. A bug fix and its regression test belong together.
- `ruff check app tests` and the mypy command in the README should pass.
- Migrations go in `alembic/versions` and move forward from the current head.
- Do not commit `.env`, provider keys, or a real `FERNET_MASTER_KEY`.

## Code style

Match the surrounding code. ruff's checked rules are in `ruff.toml` (`E4`, `E7`, `E9`, `F`, with `E712` ignored because SQLAlchemy filters use `== True`). New security checks belong next to the existing ones in `app/services`, with a test that fails on the previous behavior.
