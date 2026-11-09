# Security policy

## Supported versions

| Version | Status |
|---|---|
| 0.2.x | Supported |
| 0.1.0 | No longer updated |

0.1.0 is the initial import. 0.2.0 is the first release that includes the SSRF pin, write-time masking, per-key limits, and retention of audit rows.

## Reporting a vulnerability

Open a [private security advisory](https://github.com/Marouane2005/aegisllm/security/advisories/new) on this repository. Please do not file a public issue for a bypass, a credential leak, or anything that is exploitable on a default deploy.

Include the version, the request you sent (with secrets redacted), and what you expected to happen. A report that describes impact without a step-by-step exploit is still useful.

## What "supported" means

Fixes for issues that match [docs/threat-model.md](docs/threat-model.md): injection bypasses against the documented heuristic, PII that a listed detector should have caught, SSRF to a non-global address, authentication and rate-limit bypasses, and audit rows that are missing or that retain raw text when `STORE_RAW_PAYLOADS` is off.

Out of scope, same as the threat model: host compromise, a stolen `FERNET_MASTER_KEY`, jailbreaks the heuristic does not claim to catch, and availability of the upstream provider.

## Hardening defaults

- `STORE_RAW_PAYLOADS` defaults to off.
- `ADMIN_EMAILS` defaults to empty, so `include_raw=true` is denied.
- `UPSTREAM_PRIVATE_IP_ALLOWLIST` defaults to empty.
- `ALLOW_REGISTRATION` defaults to on so the first account can be created. Turn it off after that.
- Debug docs are off unless `DEBUG=true`.
