# Security Policy

## Threat Model

Secret Squirrel is a **credential scanner** — it processes files that may contain secrets.
This creates a unique security posture:

### What we protect against

| Threat | Mitigation |
|--------|-----------|
| Secret exposure in output | `RedactedString` shows ≤40% of any secret in all outputs |
| Secret exposure in logs | Secrets are never passed to `tracing` spans or log events |
| Memory disclosure after scan | `zeroize` zeroes secret memory on Drop |
| Credential oracle (MCP) | `validate_finding` accepts opaque IDs only, never raw secret strings |
| Path traversal (MCP scan_file) | All paths sandboxed to workspace root; absolute paths and `..` rejected |
| SSRF via validation engine | Validation URLs are hardcoded per provider; never constructed from input |
| Zip bomb / tarball bomb | 100:1 decompression ratio limit; 10 MB per-file limit in archives |
| ReDoS via custom rules | Rule compiler measures regex complexity; rejects pathological patterns |
| GPU side-channel | GPU buffers zeroed at the end of each scan session |

### What we do NOT protect against

- **The tool itself being used maliciously**: Secret Squirrel is a security tool. Like any tool, it can be misused. We are not responsible for unauthorized use.
- **Network exfiltration**: We have no network egress outside of explicit validation calls (opt-in only) and model downloads.
- **False negatives**: No scanner has 100% recall. Always combine Secret Squirrel with other controls (code review, runtime secret management).

---

## Data Handling

### Secrets in memory

- Secrets discovered during scanning are stored as `RedactedString` — a wrapper around `secrecy::Secret<String>`.
- The `zeroize` crate zeroes secret memory when the wrapper is dropped.
- Secrets are **never** written to disk except as redacted representations in output files.
- Each scan session generates a random HMAC nonce for secret hashing; nonces are discarded after the session.

### Communication sources (Slack, Jira)

- These sources require explicit authorization acknowledgement via `.confirmed(true)`.
- You **must** have appropriate authorization from your workspace administrator before scanning communication tools.
- Secret Squirrel does not store, transmit, or retain message content beyond the duration of a scan session.

### Validation engine

- Live validation is **opt-in** only (`--validate` flag or `validate = true` in config).
- Validation calls are made directly from your machine to the provider API — no proxy, no telemetry.
- Secret Squirrel never sends your secrets to any third-party service. Validation is performed by making the exact API call the provider documents (e.g., `sts:GetCallerIdentity` for AWS).

### MCP server

- The MCP server binds to `127.0.0.1` only when using HTTP transport.
- All file scan paths are sandboxed to the configured workspace root.
- `validate_finding` accepts only opaque 16-byte hex IDs — it is not possible to extract secrets via this endpoint.

---

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Report security issues via:

1. **GitHub Security Advisories** (preferred): [https://github.com/Chrysalisms/Secret-Squirrel/security/advisories/new](https://github.com/Chrysalisms/Secret-Squirrel/security/advisories/new)

2. **Email**: security@chrysalisms.dev

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within **72 hours** and aim to release a patch within **7 days** for critical issues.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (current) | ✅ |
| < 0.1.0 | ❌ |

---

## Security Hardening Checklist

If you are deploying Secret Squirrel in a CI/CD pipeline or production environment:

- [ ] Run as a **non-root** user (the Docker image already does this)
- [ ] Set `SQUIRREL_ALLOW_SHOW_SECRETS` only if absolutely necessary — never in CI logs
- [ ] Use `--validate` only from isolated environments with minimal blast radius
- [ ] Restrict MCP HTTP server to `127.0.0.1` (default) — never expose to the network
- [ ] Store `.squirrel-state.json` (baseline file) in a location not accessible by untrusted code
- [ ] Pin the GitHub Action to a specific commit SHA for supply-chain security

---

## Acknowledgements

We gratefully acknowledge the security research community for responsible disclosure.
Contributors who report valid security issues will be credited in our release notes (with your permission).
