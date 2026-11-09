---
name: Bug report
about: Something the proxy, the API, or the dashboard does wrong
title: ""
labels: bug
---

### What happened

### What you expected

### Version

Output of `git rev-parse --short HEAD`, or the image tag.

### How to reproduce

Config that matters (redact secrets): `STORE_RAW_PAYLOADS`, `RATE_LIMIT_PER_MINUTE`, the provider type. A failing pytest is ideal.

### Logs

The response status and, if you have one, the audit row's `action_taken` and `request_id`. Do not paste raw prompts that contain personal data.
