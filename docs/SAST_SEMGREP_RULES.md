# SAST Semgrep Rules — Sources and Configuration

This document describes the Semgrep rule sources used by Navigator SAST (OWASP, SANS, MITRE CWE, ported tools, and how to add more).

## Built-in baseline (always included)

Every SAST scan includes these registry rulesets:

| Ruleset ID | Description |
|------------|-------------|
| `p/default` | Default Semgrep ruleset (curated) |
| `p/security-audit` | Security audit rules (potential issues for review) |
| `p/owasp-top-ten` | **OWASP Top 10** — industry-standard web app risks |
| `p/cwe-top-25` | **CWE Top 25** (MITRE) — aligns with **SANS Top 25** style focus |
| `p/secrets` | Secret detection (tokens, keys, credentials) |

## Standards coverage

- **OWASP Top 10**: Covered by `p/owasp-top-ten` (in baseline).
- **OWASP ASVS** (Application Security Verification Standard): No official pack in the main Semgrep registry. Community rules: [semgrep-old/rules-owasp-asvs](https://github.com/semgrep-old/rules-owasp-asvs). To use: clone the repo and pass the rules directory as custom rules, or add rule files to your org’s custom rules in Navigator.
- **SANS Top 25**: Same conceptual set as **CWE Top 25** (MITRE). Use `p/cwe-top-25` (in baseline).
- **MITRE CWE**: Many rules in the registry have CWE metadata; `p/cwe-top-25` targets the Top 25. For broader CWE coverage, use language/framework packs and ported tools below.

## Optional rulesets (add via scan config `rule_sets`)

You can enable extra packs in the SAST scan config (e.g. when creating/editing a scan or policy) by setting `rule_sets` to include any of the keys below. You can also pass raw registry IDs like `p/secure-defaults` or `p/r2c-security-audit`.

### Standards / audit

| Key | Registry ID | Description |
|-----|-------------|-------------|
| `secure-defaults` | `p/secure-defaults` | Secure defaults (e.g. CSRF, framework defaults) |
| `r2c-security-audit` | `p/r2c-security-audit` | R2C security audit pack (extra coverage) |

### Languages (auto-included when language is detected)

Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C, C++, C#, Rust, Kotlin, Swift, Scala, Bash, Solidity, Apex, Elixir, Clojure, Terraform, Dockerfile, YAML, HTML, JSON — see `LANGUAGE_RULE_MAP` in `backend/app/services/sast/semgrep_runner.py`.

### Ported security tools

| Key | Registry ID | Source tool |
|-----|-------------|-------------|
| `bandit` | `p/bandit` | Bandit (Python) |
| `eslint` | `p/eslint` | ESLint (JS/TS) |
| `gosec` | `p/gosec` | Gosec (Go) |
| `findsecbugs` | `p/findsecbugs` | FindSecBugs (Java) |
| `nodejsscan` | `p/nodejsscan` | NodeJsScan |
| `brakeman` | `p/brakeman` | Brakeman (Ruby) |
| `flawfinder` | `p/flawfinder` | Flawfinder (C/C++) |
| `gitleaks` | `p/gitleaks` | Gitleaks (secrets) |
| `phpcs-security-audit` | `p/phpcs-security-audit` | phpcs-security-audit (PHP) |
| `security-code-scan` | `p/security-code-scan` | Security Code Scan (.NET) |

### Vulnerability categories

| Key | Registry ID |
|-----|-------------|
| `xss` | `p/xss` |
| `sql-injection` | `p/sql-injection` |
| `command-injection` | `p/command-injection` |
| `insecure-transport` | `p/insecure-transport` |
| `jwt` | `p/jwt` |

### Config / infra

| Key | Registry ID |
|-----|-------------|
| `docker-compose` | `p/docker-compose` |
| `nginx` | `p/nginx` |
| `terraform` | `p/terraform` |
| `kubernetes` | `p/kubernetes` |
| `dockerfile` | `p/dockerfile` |

## Pro / paid rules (Semgrep AppSec Platform)

Semgrep **Pro rules** (cross-file, deep dataflow, extra languages) are available with a **Semgrep AppSec Platform** (cloud) subscription, not via the public registry alone.

- To use Pro rules: run Semgrep via Semgrep Cloud (e.g. CI integration with `semgrep scan --config=auto` and cloud) or use the platform’s rule board.
- Navigator uses the **Semgrep CLI** with the **public registry** only; it does not include Pro rules unless you configure Semgrep Cloud and sync policies.

References:

- [Semgrep Pro rules](https://semgrep.dev/docs/semgrep-code/pro-rules)
- [Semgrep Registry](https://semgrep.dev/explore)
- [Semgrep rules repo (GitHub)](https://github.com/semgrep/semgrep-rules)

## Adding OWASP ASVS rules

1. Clone [semgrep-old/rules-owasp-asvs](https://github.com/semgrep-old/rules-owasp-asvs) (or use a fork with updates).
2. Either:
   - Add the repo’s rule YAML files as **custom rules** in Navigator (per-org custom rules), or
   - Place the rules on disk and pass the directory as the **custom rules path** for the scan (if your deployment supports that).

Rules are standard Semgrep YAML; ensure they’re compatible with your Semgrep CLI version.

## Adding custom rules (Navigator)

Use **Settings → SAST → Custom rules** (or org-level SAST policies) to add your own Semgrep YAML rules. They are run in addition to the baseline and any optional `rule_sets` you enable.

## SAST tools and installation

| Tool | Purpose | Install |
|------|---------|--------|
| **Semgrep** | Primary SAST (code + rules); required | `pip install semgrep` (in backend venv) or `./scripts/install-sast-tools.sh` |
| **TruffleHog** | Deep secret scan (800+ detectors, optional verification) | `./scripts/install-dast-tools.sh` or Go: `go install github.com/trufflesecurity/trufflehog/v3@latest`; binary expected at `/usr/local/bin/trufflehog` |
| **Gitleaks** | Fast secret scan (150+ rules); optional, used when `gitleaks_enabled` or `exhaustive` | `./scripts/install-sast-tools.sh` or `go install github.com/gitleaks/gitleaks/v8@latest`; binary at `/usr/local/bin/gitleaks` or `/usr/bin/gitleaks` |
| **Trivy** | Container/image vulnerability scan (optional in container_scanner) | `INSTALL_TRIVY=1 ./scripts/install-sast-tools.sh` or [Trivy install](https://aquasecurity.github.io/trivy/latest/docs/installation/) |

- **One-line SAST setup (recommended):**  
  `./scripts/install-sast-tools.sh`  
  This installs Semgrep in the backend venv and, by default, Gitleaks. TruffleHog is installed by `install-dast-tools.sh`.
- **Exhaustive / max-coverage scan:** Set scan config `exhaustive: true` or `max_coverage: true` to add rulesets `secure-defaults`, `r2c-security-audit` and to run Gitleaks in addition to regex + TruffleHog.

## Implementation reference

- Rule packs and language mapping: `backend/app/services/sast/semgrep_runner.py`  
  - `RULE_PACKS`, `LANGUAGE_RULE_MAP`, `UNSUPPORTED_RULE_PACKS`
- Scan config (e.g. `rule_sets`, languages, `exhaustive`, `gitleaks_enabled`): `backend/app/services/sast/scanner.py` (calls `run_semgrep` with `rule_sets`; runs Gitleaks when enabled or exhaustive).
