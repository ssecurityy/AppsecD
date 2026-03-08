# SAST Enhancement Roadmap (2026+)

This document summarizes SAST coverage, enhancements done, and optional next steps for world-class coverage.

## Current pipeline (what runs every scan)

1. **Language detection** — By file extension (30+ languages including solidity, groovy, dart, vb, apex, clojure, ocaml, vue, svelte).
2. **Semgrep** — OWASP Top 10, CWE Top 25, secrets, language/framework packs, ported tools (Bandit, ESLint, Gosec, FindSecBugs, Brakeman, etc.).
3. **IaC** — Terraform, Kubernetes, Dockerfile, CloudFormation, Helm, Ansible.
4. **Container** — Dockerfile/compose rules + optional Trivy image scan.
5. **JS/TS deep** — Custom patterns (prototype pollution, XSS, unsafe eval, etc.).
6. **Secrets** — Regex + optional TruffleHog + optional Gitleaks (when enabled or exhaustive).
7. **Git history secrets** — Optional (`scan_git_history: true`).
8. **SCA** — OSV for npm, PyPI, Go, Maven, RubyGems, Cargo, Packagist.
9. **License** — Blocked-license and risk checks.
10. **Claude review** / **AI analysis** — Optional.
11. **CVE enrichment** — SCA + KEV/EPSS.
12. **Policy** — Severity, fail-on-secrets, blocked licenses.
13. **SBOM** — CycloneDX/SPDX from SCA.

## Enhancements completed


| Item                        | Description                                                                                                                        |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| **Semgrep in requirements** | `semgrep>=1.95.0` in `backend/requirements.txt`.                                                                                   |
| **SAST install script**     | `scripts/install-sast-tools.sh` — Semgrep (venv), Gitleaks, optional Trivy.                                                        |
| **Language extensions**     | Added solidity, groovy, dart, vb, apex, clojure, ocaml, vue, svelte, scala `.sc`.                                                  |
| **Gitleaks**                | Optional secret scanner; runs when `gitleaks_enabled`, `exhaustive`, or `max_coverage`.                                            |
| **Exhaustive mode**         | Scan config `exhaustive: true` or `max_coverage: true` adds rulesets `secure-defaults`, `r2c-security-audit` and enables Gitleaks. |
| **Compliance/SARIF**        | `gitleaks` and `trufflehog` rule_source mapped in compliance_reporter and sarif_export.                                            |
| **Docs**                    | `docs/SAST_SEMGREP_RULES.md` — rules, tools, installation; `docs/SAST_ENHANCEMENT_ROADMAP.md` (this file).                         |


## Scan config options (API / UI)

- **languages** — Override detected languages for Semgrep.
- **rule_sets** — Extra Semgrep packs (e.g. `["secure-defaults", "r2c-security-audit", "brakeman"]`).
- **exhaustive** / **max_coverage** — Enable extra rulesets + Gitleaks.
- **gitleaks_enabled** — Run Gitleaks even when not exhaustive.
- **exclude_patterns** — Exclude paths from Semgrep.
- **iac_scanning_enabled** — Toggle IaC.
- **sca_enabled** — Toggle SCA.
- **scan_git_history** — Scan git history for secrets.
- **claude_review_enabled** — Toggle Claude review.

## Optional next steps (backlog)


| Area            | Idea                                                                                        |
| --------------- | ------------------------------------------------------------------------------------------- |
| **SCA**         | Add NuGet (packages.config, .csproj) if OSV supports; document all ecosystems.              |
| **Semgrep**     | OWASP ASVS custom rules (clone semgrep-old/rules-owasp-asvs, add as custom rules).          |
| **Tools**       | Bandit standalone run (in addition to p/bandit) for Python; CodeQL only via GitHub Actions. |
| **Performance** | Parallelize independent phases (e.g. secrets + SCA); tune timeouts/memory.                  |
| **Frontend**    | Expose `exhaustive`, `gitleaks_enabled` in scan config UI.                                  |


## References

- Semgrep rules: `docs/SAST_SEMGREP_RULES.md`
- Install: `./scripts/install-sast-tools.sh` (SAST), `./scripts/install-dast-tools.sh` (TruffleHog + DAST)

