# AegisLLM

**Open-source LLM security gateway and audit proxy.**

AegisLLM sits between your applications and LLM providers (OpenAI, Anthropic), inspecting every request for PII leakage and prompt injection — then forwarding, masking, or blocking as appropriate. Every interaction is audited with full request/response payloads.

## Why?

- **Shadow AI risk**: Developers paste PII into ChatGPT. AegisLLM catches it before it leaves your network.
- **Prompt injection**: Jailbreak attempts are detected and blocked using a multi-signal heuristic engine.
- **Audit & compliance**: Every LLM call is logged with masked payloads, latency, token usage, and threat signals.
- **Self-hosted**: Runs on a single $0 Oracle Cloud VM. Your data never touches a third-party SaaS.

## Features

- 🔐 Transparent reverse proxy — drop-in replacement for `api.openai.com`
- 🛡️ PII detection — email, credit cards (Luhn-validated), SSN, AWS keys, API keys, IPs
- 🚫 Prompt injection guard — jailbreak phrases, invisible Unicode, base64-encoded payloads, homoglyphs
- 📊 Audit dashboard — cursor-paginated logs, filters, threat summaries, raw/masked payload viewer
- 📈 Metrics — request counts, latency percentiles, token usage, breakdowns by action/provider
- 🔑 Per-project API keys — hashed storage, plaintext shown once at creation
- 🔒 Encrypted upstream credentials — Fernet-encrypted at rest, never returned to the dashboard
- 🧹 Automatic retention — scheduled cleanup keeps disk usage bounded forever
- ⚡ Streaming support — full SSE streaming with audit, bounded memory, client-disconnect safe
- 🐳 One-command deploy — Docker Compose with Postgres, Redis, Caddy (HTTPS auto)

## Quick Start (Oracle Cloud Always Free)

### 1. Provision the VM

Oracle Cloud Console → Compute → Create Instance:
- **Image**: Ubuntu 22.04 or 24.04
- **Shape**: `VM.Standard.A1.Flex` — **2 OCPUs, 12 GB RAM** (Always Free)
- **Boot volume**: 50 GB

### 2. Open firewall ports

**Oracle Cloud Security List** (VCN → Security Lists → Default → Ingress Rules):
- TCP 22 (SSH) — your IP only
- TCP 80 (HTTP) — 0.0.0.0/0
- TCP 443 (HTTPS) — 0.0.0.0/0
- UDP 443 (HTTP/3) — 0.0.0.0/0

**On the VM itself**:
```bash
sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -I INPUT -p udp --dport 443 -j ACCEPT


## Rate limiting

`/v1/*` proxy routes are limited **per API key** to `RATE_LIMIT_PER_MINUTE` requests per minute (default **60**; `0` disables).
Counters live in Redis (`REDIS_URL`), so they are shared across workers and restarts. Over the limit the proxy returns
`429` with a `Retry-After` header (seconds until the window resets). Auth routes keep their own per-IP limits
(register 5/min, login 10/min).
