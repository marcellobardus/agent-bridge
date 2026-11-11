# Contributing

Thanks for helping. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) first.

**Security problems:** do not open an issue. Follow [SECURITY.md](SECURITY.md) (GitHub private vulnerability
reporting).

## Development setup

Python 3.13+.

```sh
python -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock      # runtime deps, hash-pinned
.venv/bin/pip install -e '.[test]'                                # editable install + pytest, httpx
.venv/bin/python -m pytest -q
```

The suite (about 1,100 tests, including end-to-end tests that start a real server process) must pass.

## Changing things

- **Dependencies:** edit `requirements.in`, then run `scripts/lock.sh` (needs `uv`) to regenerate the hash-pinned,
  wheels-only `requirements.lock`.
- **API changes:** regenerate the contract and the schemas. The tests fail if they are stale:
  `python scripts/export_openapi.py` (writes `docs/openapi.json`), then `python scripts/gen_integration_schemas.py`
  (writes `integration-kit/openapi.json` and `integration-kit/schemas/*.json`). Update `docs/API.md` and
  `integration-kit/` text if behaviour changed.
- **Migrations are append-only and immutable.** Add a new numbered file under `bridge/db/migrations/`; never edit an
  applied one. Restore compares `sqlite_master` with the migrations, so editing one breaks existing databases and
  snapshots (even a comment).
- **Security-sensitive changes need a regression test** (authentication, authorisation, approvals, request limits,
  the client guard, restore). Look at `tests/test_security.py` for the style.
- **No real hostnames, personal names or secrets** in code, docs, fixtures or commit messages. Use placeholders such
  as `example.ngrok.app`, `alice`/`bob`, `agent-a`/`agent-b`. Test fixtures that look like keys are allowlisted
  explicitly in `.gitleaks.toml`; do not widen it casually.
- Keep behaviour changes, refactors and docs in separate commits where practical.

## Pull requests

Open a PR against `main` using the template. CI runs the tests and a secret scan (gitleaks). Sign-off (DCO) is
not required.

By contributing you agree that your contribution is licensed under the MIT license of this project.
