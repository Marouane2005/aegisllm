# Changelog

## 0.2.0 - 2026-11-09

### Fixed

- A blocked prompt injection returns 403 and writes an audit row. It used to raise `UnboundLocalError` and surface as 500, with no row.
- Metrics, audit time filters, and retention compared timezone-aware datetimes with a `timestamp without time zone` column, so metrics 500'd and cleanup deleted nothing.
- A client disconnect during a streamed response no longer drops the audit row. The write is scheduled off the cancelled task, and the upstream response is closed.
- Credit card numbers are matched with their own pattern and checked with Luhn and an issuer prefix. They were previously taken from the phone expression, which never saw a full 16-digit number.
- Register and login limits use the shared Redis limiter. They were an in-process limiter that reset when the process did, and the test suite tripped the register cap.
- The default provider is the oldest active row (`created_at`, then `id`). It used to be whichever row the database returned first.
- `asyncpg` is 0.30.0 so a local install on Python 3.13 can resolve a wheel.
- Streamed audit text is reassembled across chunk boundaries.
- A 3xx from upstream is rejected instead of being parsed as a completion or treated as a successful stream.
- The pinned request's `Host` header is the hostname, not userinfo plus host.

### Added

- DNS resolution and a non-global IP block before the upstream connection, with the socket pinned to the address that was checked. Decimal, hex, octal, and shortened IP literals are interpreted in-process. NAT64, 6to4, and Teredo embeddings of a private address are blocked.
- PII masking at write time. Raw bodies are stored only when `STORE_RAW_PAYLOADS=true`. `include_raw=true` requires an email in `ADMIN_EMAILS` and is recorded in `payload_access_logs`.
- Per-API-key limiting on `/v1` (`RATE_LIMIT_PER_MINUTE`, 429, `Retry-After`).
- Retention of `audit_logs` rows older than `AUDIT_LOG_RETENTION_DAYS` (default 90), in batches.
- Phone, IBAN, UK NINO, and Spanish DNI detectors next to the existing email, SSN, card, AWS key, and IPv4 detectors.
- A broader injection pass: normalization, a few languages, and encoded payloads. The checked-in corpus reports precision and recall.
- `/v1/chat/completions` returns 501 for an Anthropic provider instead of forwarding an OpenAI-shaped body.
- GitHub Actions for ruff, mypy on the service layer, pytest with Postgres and Redis, the frontend build, and `docker compose build`.
- `.env.example` and a check that every setting the app or Compose reads is listed there.

### Notes

- `audit_logs.timestamp` is still `timestamp without time zone` holding UTC. Aware query parameters are converted before they are bound.
- Anthropic is stored as a provider and is not implemented on `/v1/chat/completions`.

## 0.1.0 - 2026-10-26

Initial import. Dashboard, project API keys, Fernet-encrypted provider keys, a Postgres audit log, and a first cut of the proxy.
