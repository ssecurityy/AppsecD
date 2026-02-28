# Payload & Test Case Sync Guide

This document describes how to populate PostgreSQL with payloads, wordlists, and test cases from GitHub repositories.

## Quick Start

```bash
cd /opt/navigator/backend && source venv/bin/activate

# Option A: Run all at once
python scripts/setup_payloads.py

# Option B: Run individually
python scripts/import_payloads_seclists.py   # PAT + SecLists
python scripts/sync_all_payloads.py          # FuzzDB, XSS, SQLi, Nuclei, WSTG, Intruder
python scripts/import_wstg_test_cases.py     # OWASP WSTG test cases
```

## One-Command Setup

For fresh installs or re-sync:

```bash
cd /opt/navigator/backend && source venv/bin/activate && python scripts/setup_payloads.py
```

## Data Sources

| Source | Script | Contents |
|--------|-------|----------|
| PayloadsAllTheThings | `import_payloads_seclists.py` | 65 categories, READMEs, payload docs |
| SecLists | `import_payloads_seclists.py` | 9 categories, 6,000+ wordlist files |
| FuzzDB | `sync_all_payloads.py` | 295 files |
| Big List of Naughty Strings | `sync_all_payloads.py` | 8 files |
| XSS Payloads (7000+) | `sync_all_payloads.py` | 8 files |
| SQL Injection Payloads | `sync_all_payloads.py` | 11 files |
| Advanced SQL Injection Cheatsheet | `sync_all_payloads.py` | 16 files |
| Nuclei Templates | `sync_all_payloads.py` | 13,005 files |
| Intruder Payload Packs (1N3) | `sync_all_payloads.py` | 108 files |
| OWASP Web Security Testing Guide | `sync_all_payloads.py` | 175 markdown files |
| OWASP WSTG Test Cases | `import_wstg_test_cases.py` | 126 test cases in `test_cases` table |

## Prerequisites

- `PayloadsAllTheThings` and `SecLists` folders in `/opt/navigator/data/` (or paths from config)
- Git installed for cloning repos
- PostgreSQL running with Navigator schema

## File Size Limits

- **200MB** per file (no files skipped under this size)
- Null bytes stripped before insert (PostgreSQL UTF8 compatibility)

## Repo URLs (sync_all_payloads.py)

| Repo | URL |
|------|-----|
| FuzzDB | https://github.com/fuzzdb-project/fuzzdb |
| BLNS | https://github.com/minimaxir/big-list-of-naughty-strings |
| XSS Payloads | https://github.com/fxrhan/all-XSS-Payloads |
| SQL Injection | https://github.com/manishravtole/SQL-injection-payloads |
| Advanced SQLi | https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet |
| Nuclei Templates | https://github.com/projectdiscovery/nuclei-templates |
| Intruder Payloads | https://github.com/1N3/IntruderPayloads |
| OWASP WSTG | https://github.com/OWASP/wstg |

## Troubleshooting

- **OOM during SecLists import**: The import streams category-by-category; if you still hit OOM, reduce SecLists to a subset.
- **"Repository not found"**: Some original repos (IbrahimHisham/XSS-Payloads, m4ll0k/SQLi-Payload-List, etc.) were removed; we use working alternatives.
- **Null byte error**: Fixed in both scripts; content is sanitized before insert.
