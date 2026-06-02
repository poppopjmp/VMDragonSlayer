# Security Policy

## Supported Versions

VMDragonSlayer is under active development. Security fixes are applied to the
latest released minor version and the active development branch.

| Version | Supported          |
| ------- | ------------------ |
| 0.9.x   | :white_check_mark: |
| < 0.9   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not open a public
issue**. Instead, report it privately so it can be triaged and fixed before
disclosure.

- **Preferred:** Use GitHub's
  [private vulnerability reporting](https://github.com/poppopjmp/vmdragonslayer/security/advisories/new)
  ("Report a vulnerability" under the *Security* tab).
- **Email:** `contact@vmdragonslayer.com`

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (proof-of-concept, affected module, sample if relevant).
- The version / commit you tested against.

You can expect an initial acknowledgement within **5 business days** and a
status update within **30 days**. Coordinated disclosure is appreciated.

## Scope & Threat Model

VMDragonSlayer analyses **untrusted, potentially malicious binaries**. Treat
all analysis input as hostile:

- Run analysis in an isolated environment (VM/container) without network access
  to anything you care about.
- The framework parses and (optionally) emulates attacker-controlled bytes via
  LIEF, Capstone, Unicorn, Triton, angr, and Qiling. Parser/emulator crashes on
  crafted input are expected and should be contained by your sandbox, not relied
  upon as a security boundary.
- ML model artifacts are loaded via `joblib`/`pickle`. **Only load model files
  from sources you trust** — unpickling untrusted data can execute arbitrary
  code.
- The REST API server (`dragonslayer.api.server`) is intended for trusted,
  local or network-isolated deployments. Set `VMDS_API_KEY` to enable
  authentication before exposing it.

## Security Tooling

CI runs `bandit` (SAST) and `pip-audit` (dependency scanning) on every change.
Static-analysis findings that are intentional (e.g. non-cryptographic hashing
for content addressing, `pickle` for trusted model artifacts) are annotated at
the call site with justification.
