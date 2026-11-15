# Security Policy

TraceLayer is a portfolio project, not a supported product. If you find a vulnerability, please open a
GitHub issue that contains **no exploit details** and asks for a private contact channel, or use GitHub's
private vulnerability reporting if it is enabled on the repository.

Please do not test against deployments you do not own. The public demo is a static, browser-only build
with no backend.

How TraceLayer is secured, what was audited, and what is known to be missing:

- [docs/SECURITY.md](docs/SECURITY.md): threat model, controls, secret rotation
- [docs/V2_SECURITY_AUDIT.md](docs/V2_SECURITY_AUDIT.md): findings by severity and their status
- [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md): accounts, sessions, CSRF, RBAC
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md): known limitations
