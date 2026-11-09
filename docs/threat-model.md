# Threat model

This describes the system as it is in 0.2.0. It is the model the tests are written against, not a promise that every attack in the wild is caught.

## Assets

- Upstream provider API keys. Encrypted at rest with `FERNET_MASTER_KEY`. Returned to the dashboard only as a prefix, never in full.
- Project API keys. Stored as SHA-256 hashes. The plaintext is shown once, at creation.
- Dashboard passwords. Argon2.
- Dashboard JWTs. Signed with `JWT_SECRET_KEY`.
- Prompt and completion text. May contain personal data, credentials, or instructions aimed at the model.
- The audit log. It is the record of what was blocked, masked, or forwarded.

## Actors

- A developer or service holding a project API key. Trusted to call the proxy, not trusted to send clean prompts.
- A person with a dashboard account. Trusted for the projects they own. Not trusted to read someone else's raw payloads.
- An admin whose email is in `ADMIN_EMAILS`. Allowed to read raw payloads. Every such read is written to `payload_access_logs`.
- The upstream provider. Trusted with whatever we forward. Not trusted to be free of bugs, and not a place we want internal network calls to land.
- Someone without a key. Should get 401 or, on the auth routes, a rate limit.

## What the proxy tries to stop

| Threat | What we do | Residual risk |
|---|---|---|
| Personal data in a prompt | Regex detectors with checksums where a checksum exists. The outbound message is masked. The stored copy is masked again at write time from the original text, so a caller cannot pass a "masked" string that still contains the value. | Unknown formats are not detected. The caller still receives the raw completion. |
| Prompt injection | Normalized phrase match: case, zero-width characters, a small homoglyph map, leetspeak, spaced letters, base64, rot13, URL encoding, and hex escapes. A handful of languages have their own phrases. On the checked-in corpus of 40 attacks and 45 benign controls, precision is 1.00 and recall is 1.00. | A request that quotes an attack phrase is blocked. That is the right call for a gateway and a false positive for someone discussing the phrase. Jailbreaks that do not look like these patterns pass. |
| SSRF through the upstream URL | Scheme is http or https. Host must be on an exact allowlist. The host is resolved once; any non-global answer (loopback, RFC1918, link-local, CGNAT, multicast, reserved, documentation space, IPv4-mapped IPv6, NAT64, 6to4, Teredo) rejects the call. Decimal, hex, octal, and shortened IP literals are parsed in-process so this does not depend on libc. The connection uses the pinned address, with the original hostname kept for `Host` and TLS SNI. Redirects are refused. | An allowlisted host that is itself malicious can still answer. An operator who adds a private CIDR to `UPSTREAM_PRIVATE_IP_ALLOWLIST` is opting into that network. |
| Credential stuffing on the dashboard | Argon2 passwords. Register is 5/minute and login is 10/minute per IP, stored in Redis. | Distributed attempts from many addresses are not correlated. |
| A noisy or looping client | `/v1` is limited per API key (`RATE_LIMIT_PER_MINUTE`, default 60). Body size is capped at 2 MB. A stream buffer is capped at 4 MB. | The limiter is a fixed window and the Redis calls are synchronous. A stolen project key can spend that key's budget. |
| Audit log growing without bound | A daily job deletes payload bodies past the project's `retention_days`, then deletes audit rows past `AUDIT_LOG_RETENTION_DAYS` (default 90, `0` keeps them), in committed batches. | Rows inside the window are kept in full. There is no separate tamper-evident seal; integrity here means the row matches the call and retention does not delete fresh rows. |
| A dashboard user reading raw prompts | Raw bodies are not stored unless `STORE_RAW_PAYLOADS=true`. `include_raw=true` requires the caller's email in `ADMIN_EMAILS` and writes an access row. | An admin can read raw data when storage is on. The masked column can still contain data the detectors missed. |
| A client disconnect hiding a stream | The audit write is scheduled on the event loop and shielded, then the upstream response is closed. | A process crash still loses the in-flight row. |

## Out of scope

- A hostile person who can read the environment or the database volume. `FERNET_MASTER_KEY` plus the database decrypts provider keys. That is a host compromise, not a proxy bug.
- The upstream provider being compromised, logging what we send, or ignoring the masked text and somehow seeing the original. We never send the original message content when a detector fired.
- Jailbreaks that a model would follow but that do not match the heuristic.
- Users pasting secrets into the dashboard UI outside of a proxied request.
- DDoS against the host itself. Redis limits help; they are not a network filter. Caddy is a reverse proxy, not a scrubbing center.
- Availability of OpenAI or Anthropic.

## Reporting

See [SECURITY.md](../SECURITY.md). Please use a private GitHub security advisory rather than a public issue when the report describes a bypass.
