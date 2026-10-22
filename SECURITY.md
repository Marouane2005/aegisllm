# Security Policy

## Supported Versions

Only the latest release is supported with security updates.

## Threat Model

| Threat | Mitigation |
|---|---|
| Upstream API key theft | Fernet-encrypted at rest. Master key in env var only. Never returned via API. |
| Aegis API key leakage | Stored as SHA-256 hashes. Plaintext shown once at creation, never again. |
| Prompt injection | Multi-signal heuristic (jailbreak phrases, invisible chars, base64 payloads, homoglyphs). |
| PII leakage to LLM providers | Regex + Luhn-validated detectors. Masked before forwarding. |
| SSRF via proxy | Strict upstream host allowlist. Redirect following disabled. Internal IPs blocked. |
| Denial of service | Per-IP rate limiting via Redis. Request body cap (2MB). Stream buffer cap (4MB). |
| Credential brute force | Argon2 password hashing. Rate-limited login (10/min) and register (5/min). |
| Session hijacking | Short-lived JWTs. Strict CORS allowlist. |
| SQL injection | SQLAlchemy ORM with parameterized queries. No raw SQL. |
| XSS | React's default escaping. CSP-ready headers via Caddy. |
| Disk exhaustion | Scheduled cleanup deletes payloads older than `retention_days`. |
| Memory exhaustion | Async streaming with bounded buffers. Connection pool limits. Redis LRU eviction. |

## Known Limitations

- Zero-day jailbreaks cannot be caught by heuristics.
- Upstream provider compromise is out of scope.
- `FERNET_MASTER_KEY` theft + DB access = upstream key decryption. Protect your env vars.
- Dashboard JWT in localStorage — use HTTPS-only and short expiry.

## Reporting a Vulnerability

Email security@yourdomain.com or open a private GitHub security advisory. Do NOT open a public issue.

Acknowledgement within 48 hours. Fix timeline within 7 days.
