"""JavaScript/TypeScript deep security analyzer — custom pattern detection beyond Semgrep."""
import hashlib
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# File extensions to scan and directories/patterns to skip
# ---------------------------------------------------------------------------
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SKIP_DIRS = {"node_modules", "dist", "build", ".git", ".next", "__pycache__", "vendor", "coverage", ".cache"}
SKIP_SUFFIXES = {".min.js", ".min.mjs", ".min.cjs"}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB per file
MAX_FILES = 80000

# ---------------------------------------------------------------------------
# Context-line window for snippet extraction
# ---------------------------------------------------------------------------
CONTEXT_LINES = 3

# ---------------------------------------------------------------------------
# Sanitization / safe-pattern hints — presence near a match lowers confidence
# ---------------------------------------------------------------------------
_SANITIZATION_HINTS = re.compile(
    r"(?:sanitize|escape|encode|purify|DOMPurify|xss|createTextNode|textContent"
    r"|validator|whitelist|allowlist|safelist|encodeURI|encodeURIComponent"
    r"|parameterize|prepared|placeholder|\bif\s*\(\s*typeof\b)",
    re.IGNORECASE,
)

# Patterns that indicate user/external input nearby
_USER_INPUT_PATTERN = re.compile(
    r"(?:req\.(?:body|query|params|headers|cookies)|request\."
    r"(?:body|query|params|headers|cookies)|ctx\.(?:request|query|params)"
    r"|event\.(?:data|target\.value)|userinput|user_input|userInput"
    r"|formData|searchParams|URLSearchParams|location\.(?:search|hash)"
    r"|window\.location|document\.(?:URL|referrer|cookie)"
    r"|process\.argv|args\[|argv\[)",
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════════
# CHECK DEFINITIONS
# Each check is a dict with:
#   rule_id, severity, confidence, title, description, cwe_id, owasp_category,
#   patterns (list of compiled regexes — any match triggers the check),
#   negative_patterns (optional — if any match, the finding is suppressed),
#   context_required (optional — if set, surrounding lines must match this),
#   references (list of URLs)
# ═══════════════════════════════════════════════════════════════════════════

_CHECKS: list[dict] = []


def _register(check: dict) -> None:
    """Validate and store a check definition."""
    check.setdefault("negative_patterns", [])
    check.setdefault("context_required", None)
    check.setdefault("references", [])
    _CHECKS.append(check)


# ── 1. Prototype Pollution ────────────────────────────────────────────────
_register({
    "rule_id": "js_deep.prototype-pollution",
    "severity": "high",
    "confidence": "medium",
    "title": "Potential Prototype Pollution",
    "description": (
        "Object.assign, _.merge, _.defaultsDeep, or $.extend is called with "
        "external input, which may allow an attacker to inject properties into "
        "Object.prototype, leading to denial of service or privilege escalation."
    ),
    "cwe_id": "CWE-1321",
    "owasp_category": "A03:2021",
    "patterns": [
        re.compile(r"Object\.assign\s*\("),
        re.compile(r"_\.merge\s*\("),
        re.compile(r"_\.defaultsDeep\s*\("),
        re.compile(r"\$\.extend\s*\(\s*true\s*,"),
        re.compile(r"deepmerge\s*\("),
        re.compile(r"lodash\.merge\s*\("),
    ],
    "context_required": _USER_INPUT_PATTERN,
    "references": [
        "https://cwe.mitre.org/data/definitions/1321.html",
        "https://portswigger.net/daily-swig/prototype-pollution-the-dangerous-and-underrated-vulnerability-impacting-javascript-applications",
    ],
})

# ── 2. DOM XSS Sinks ─────────────────────────────────────────────────────
_register({
    "rule_id": "js_deep.dom-xss-sink",
    "severity": "high",
    "confidence": "high",
    "title": "DOM XSS Sink Detected",
    "description": (
        "Direct assignment to innerHTML/outerHTML, use of document.write, eval, "
        "Function(), setTimeout/setInterval with string argument, "
        "insertAdjacentHTML, or unsafe location manipulation can lead to "
        "cross-site scripting (XSS) when the value originates from user input."
    ),
    "cwe_id": "CWE-79",
    "owasp_category": "A03:2021",
    "patterns": [
        re.compile(r"\.innerHTML\s*="),
        re.compile(r"\.outerHTML\s*="),
        re.compile(r"document\.write\s*\("),
        re.compile(r"document\.writeln\s*\("),
        re.compile(r"\beval\s*\("),
        re.compile(r"\bFunction\s*\("),
        re.compile(r"setTimeout\s*\(\s*['\"`]"),
        re.compile(r"setInterval\s*\(\s*['\"`]"),
        re.compile(r"\.insertAdjacentHTML\s*\("),
        re.compile(r"location\.href\s*="),
        re.compile(r"location\.assign\s*\("),
        re.compile(r"location\.replace\s*\("),
        re.compile(r"window\.open\s*\("),
    ],
    "negative_patterns": [
        re.compile(r"DOMPurify\.sanitize", re.IGNORECASE),
        re.compile(r"createTextNode"),
        re.compile(r"textContent\s*="),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/79.html",
        "https://owasp.org/www-community/attacks/DOM_Based_XSS",
    ],
})

# ── 3. Insecure Deserialization ───────────────────────────────────────────
_register({
    "rule_id": "js_deep.insecure-deserialization",
    "severity": "critical",
    "confidence": "high",
    "title": "Insecure Deserialization",
    "description": (
        "Usage of node-serialize, funcster, or js-yaml.load without "
        "SAFE_SCHEMA / safeLoad can lead to arbitrary code execution when "
        "processing untrusted input."
    ),
    "cwe_id": "CWE-502",
    "owasp_category": "A08:2021",
    "patterns": [
        re.compile(r"require\s*\(\s*['\"]node-serialize['\"]\s*\)"),
        re.compile(r"require\s*\(\s*['\"]funcster['\"]\s*\)"),
        re.compile(r"from\s+['\"]node-serialize['\"]"),
        re.compile(r"from\s+['\"]funcster['\"]"),
        re.compile(r"serialize\s*\.\s*unserialize\s*\("),
        re.compile(r"yaml\.load\s*\("),
        re.compile(r"(?:msgpack|notepack)\.decode\s*\("),
    ],
    "negative_patterns": [
        re.compile(r"SAFE_SCHEMA"),
        re.compile(r"safeLoad"),
        re.compile(r"JSON_SCHEMA"),
        re.compile(r"schema:\s*yaml\."),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/502.html",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests",
    ],
})

# ── 4. Client-Side Secret Exposure ────────────────────────────────────────
_register({
    "rule_id": "js_deep.client-secret-exposure",
    "severity": "high",
    "confidence": "high",
    "title": "Client-Side Secret Exposure",
    "description": (
        "API keys, tokens, or credentials are embedded directly in client-side "
        "JavaScript/TypeScript code. Environment variables prefixed with "
        "REACT_APP_, NEXT_PUBLIC_, or VITE_ are shipped to the browser."
    ),
    "cwe_id": "CWE-798",
    "owasp_category": "A07:2021",
    "patterns": [
        # Env vars with actual values (not just references to process.env)
        re.compile(
            r"""(?:REACT_APP_|NEXT_PUBLIC_|VITE_)[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\s*"""
            r"""[=:]\s*['"][A-Za-z0-9\-_/+=]{8,}['"]"""
        ),
        # Firebase config blocks
        re.compile(r"apiKey\s*:\s*['\"]AIza[0-9A-Za-z\-_]{35}['\"]"),
        # Google Maps hardcoded
        re.compile(r"(?:google|maps).*(?:key|api)\s*[=:]\s*['\"]AIza[0-9A-Za-z\-_]{35}['\"]", re.IGNORECASE),
        # Generic hardcoded tokens
        re.compile(
            r"""(?:api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|secret[_-]?key)\s*"""
            r"""[=:]\s*['"][A-Za-z0-9\-_/+=]{16,}['"]""",
            re.IGNORECASE,
        ),
        # Stripe publishable key in source (not in env)
        re.compile(r"""['\"]pk_(?:test|live)_[A-Za-z0-9]{20,}['\"]"""),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/798.html",
    ],
})

# ── 5. Unsafe Regex (ReDoS) ──────────────────────────────────────────────
_register({
    "rule_id": "js_deep.redos",
    "severity": "medium",
    "confidence": "medium",
    "title": "Potential Regular Expression Denial of Service (ReDoS)",
    "description": (
        "A regular expression contains nested quantifiers (e.g. (a+)+, (a*)*) "
        "or overlapping alternation with repetition, which can cause catastrophic "
        "backtracking and denial of service."
    ),
    "cwe_id": "CWE-1333",
    "owasp_category": None,
    "patterns": [
        # Nested quantifiers: (a+)+, (a*)+, (a+)*, (a*)*, (.+)+, etc.
        re.compile(r"/[^/]*\([^)]*[+*][^)]*\)[+*][^/]*/"),
        # Also detect in RegExp constructor
        re.compile(r"""new\s+RegExp\s*\(\s*['"][^'"]*\([^)]*[+*][^)]*\)[+*][^'"]*['"]\s*\)"""),
        # Overlapping alternation: (a|a)+
        re.compile(r"/[^/]*\(([^|)]+)\|\1\)[+*][^/]*/"),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/1333.html",
        "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
    ],
})

# ── 6. postMessage Abuse ─────────────────────────────────────────────────
_register({
    "rule_id": "js_deep.postmessage-no-origin-check",
    "severity": "high",
    "confidence": "medium",
    "title": "postMessage Handler Without Origin Verification",
    "description": (
        "An event listener for 'message' events is registered without verifying "
        "event.origin, allowing any origin to send messages to this handler. "
        "This can lead to DOM XSS or data theft."
    ),
    "cwe_id": "CWE-346",
    "owasp_category": "A07:2021",
    "patterns": [
        re.compile(r"""addEventListener\s*\(\s*['"]message['"]"""),
        re.compile(r"""\.on\s*\(\s*['"]message['"]"""),
    ],
    "negative_patterns": [
        re.compile(r"event\.origin"),
        re.compile(r"e\.origin"),
        re.compile(r"msg\.origin"),
        re.compile(r"message\.origin"),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/346.html",
        "https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns",
    ],
})

# ── 7. NoSQL Injection ────────────────────────────────────────────────────
_register({
    "rule_id": "js_deep.nosql-injection",
    "severity": "high",
    "confidence": "medium",
    "title": "Potential NoSQL Injection",
    "description": (
        "MongoDB query operators ($gt, $ne, $regex, $where) or unsanitized user "
        "input is passed directly to database query methods (find, findOne, "
        "updateOne, deleteOne), enabling NoSQL injection attacks."
    ),
    "cwe_id": "CWE-943",
    "owasp_category": "A03:2021",
    "patterns": [
        # Direct use of MongoDB operators from input
        re.compile(r"""\.find\s*\(\s*\{[^}]*req\.(?:body|query|params)"""),
        re.compile(r"""\.findOne\s*\(\s*\{[^}]*req\.(?:body|query|params)"""),
        re.compile(r"""\.updateOne\s*\(\s*\{[^}]*req\.(?:body|query|params)"""),
        re.compile(r"""\.deleteOne\s*\(\s*\{[^}]*req\.(?:body|query|params)"""),
        re.compile(r"""\.findOneAndUpdate\s*\(\s*\{[^}]*req\.(?:body|query|params)"""),
        # $where with user input
        re.compile(r"""\$where\s*:\s*.*req\.(?:body|query|params)"""),
        # Dangerous query operators near user input
        re.compile(r"""(?:\$gt|\$ne|\$regex|\$where|\$exists)\s*:\s*.*(?:req\.|input|user|param)""", re.IGNORECASE),
    ],
    "negative_patterns": [
        re.compile(r"(?:mongo-sanitize|express-mongo-sanitize|sanitize)", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/943.html",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
    ],
})

# ── 8. Path Traversal ────────────────────────────────────────────────────
_register({
    "rule_id": "js_deep.path-traversal",
    "severity": "high",
    "confidence": "medium",
    "title": "Path Traversal via User Input",
    "description": (
        "File system operations (fs.readFile, fs.readFileSync, res.sendFile, "
        "path.join with user input) are performed using unsanitized user input, "
        "allowing directory traversal attacks to read arbitrary files."
    ),
    "cwe_id": "CWE-22",
    "owasp_category": "A01:2021",
    "patterns": [
        re.compile(r"fs\.readFile(?:Sync)?\s*\([^)]*req\.(?:params|query|body)"),
        re.compile(r"fs\.createReadStream\s*\([^)]*req\.(?:params|query|body)"),
        re.compile(r"fs\.writeFile(?:Sync)?\s*\([^)]*req\.(?:params|query|body)"),
        re.compile(r"res\.sendFile\s*\([^)]*req\.(?:params|query|body)"),
        re.compile(r"res\.download\s*\([^)]*req\.(?:params|query|body)"),
        re.compile(r"path\.join\s*\([^)]*req\.(?:params|query|body)"),
        re.compile(r"path\.resolve\s*\([^)]*req\.(?:params|query|body)"),
        # Template literal version
        re.compile(r"fs\.readFile(?:Sync)?\s*\(\s*`[^`]*\$\{.*req\."),
        re.compile(r"res\.sendFile\s*\(\s*`[^`]*\$\{.*req\."),
    ],
    "negative_patterns": [
        re.compile(r"path\.normalize"),
        re.compile(r"\.replace\s*\(\s*/\\\.\\\."),
        re.compile(r"\.includes\s*\(\s*['\"]\\.\\."),
        re.compile(r"startsWith\s*\("),
        re.compile(r"realpath"),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/22.html",
        "https://owasp.org/www-community/attacks/Path_Traversal",
    ],
})

# ── 9. Command Injection ─────────────────────────────────────────────────
_register({
    "rule_id": "js_deep.command-injection",
    "severity": "critical",
    "confidence": "high",
    "title": "Command Injection via child_process",
    "description": (
        "User input is passed to child_process.exec, execSync, or similar "
        "functions via string concatenation or template literals, allowing "
        "arbitrary command execution on the server."
    ),
    "cwe_id": "CWE-78",
    "owasp_category": "A03:2021",
    "patterns": [
        # exec with concatenation from user input
        re.compile(r"(?:child_process\.)?exec\s*\([^)]*req\.(?:body|query|params)"),
        re.compile(r"(?:child_process\.)?execSync\s*\([^)]*req\.(?:body|query|params)"),
        # Template literal usage
        re.compile(r"(?:child_process\.)?exec\s*\(\s*`[^`]*\$\{"),
        re.compile(r"(?:child_process\.)?execSync\s*\(\s*`[^`]*\$\{"),
        # String concatenation with exec
        re.compile(r"""(?:child_process\.)?exec\s*\(\s*['"][^'"]*['"]\s*\+"""),
        re.compile(r"""(?:child_process\.)?execSync\s*\(\s*['"][^'"]*['"]\s*\+"""),
        # Shell: true with user input
        re.compile(r"spawn\s*\([^)]*\{[^}]*shell\s*:\s*true[^}]*\}"),
    ],
    "negative_patterns": [
        re.compile(r"execFile\s*\("),
        re.compile(r"spawn\s*\(\s*['\"]"),  # spawn with literal command (safer)
        re.compile(r"shellescape|shell-escape|shell-quote", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://owasp.org/www-community/attacks/Command_Injection",
    ],
})

# ── 10. Insecure Randomness ──────────────────────────────────────────────
_register({
    "rule_id": "js_deep.insecure-randomness",
    "severity": "medium",
    "confidence": "medium",
    "title": "Insecure Randomness (Math.random) for Security-Sensitive Value",
    "description": (
        "Math.random() is used near a security-sensitive context (token, secret, "
        "password, session, key, UUID generation). Math.random() is not "
        "cryptographically secure; use crypto.randomBytes() or "
        "crypto.getRandomValues() instead."
    ),
    "cwe_id": "CWE-338",
    "owasp_category": "A02:2021",
    "patterns": [
        re.compile(r"Math\.random\s*\(\s*\)"),
    ],
    # Only flag when near security-sensitive variable names (checked via context)
    "context_required": re.compile(
        r"(?:token|secret|password|passwd|session|key|uuid|nonce|salt|csrf|otp"
        r"|auth|credential|api.?key|random.?id|unique.?id|request.?id|verify)",
        re.IGNORECASE,
    ),
    "references": [
        "https://cwe.mitre.org/data/definitions/338.html",
    ],
})

# ── 11. React dangerouslySetInnerHTML ────────────────────────────────────
_register({
    "rule_id": "js_deep.react-dangerously-set-innerhtml",
    "severity": "high",
    "confidence": "high",
    "title": "React dangerouslySetInnerHTML Without Sanitization",
    "description": (
        "dangerouslySetInnerHTML is used without DOMPurify.sanitize() or similar "
        "sanitization, which can lead to cross-site scripting (XSS) if the HTML "
        "content originates from user input or external sources."
    ),
    "cwe_id": "CWE-79",
    "owasp_category": "A03:2021",
    "patterns": [
        re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:"),
    ],
    "negative_patterns": [
        re.compile(r"DOMPurify\.sanitize", re.IGNORECASE),
        re.compile(r"purify\.sanitize", re.IGNORECASE),
        re.compile(r"sanitize\s*\(", re.IGNORECASE),
        re.compile(r"dompurify", re.IGNORECASE),
        re.compile(r"xss\s*\(", re.IGNORECASE),
        re.compile(r"sanitizeHtml\s*\(", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/79.html",
        "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html",
    ],
})

# ── 12. Next.js API Route Missing Auth ──────────────────────────────────
_register({
    "rule_id": "js_deep.nextjs-api-no-auth",
    "severity": "high",
    "confidence": "medium",
    "title": "Next.js API Route Without Authentication Check",
    "description": (
        "A Next.js API route handler (pages/api/ or app/api/) does not appear to "
        "verify authentication via session, token, or middleware. Unauthenticated "
        "API endpoints may allow unauthorized access to server-side functionality."
    ),
    "cwe_id": "CWE-306",
    "owasp_category": "A07:2021",
    "patterns": [
        # pages/api handler pattern
        re.compile(r"export\s+default\s+(?:async\s+)?function\s+handler\s*\("),
        # app/api route pattern
        re.compile(r"export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\s*\("),
    ],
    "negative_patterns": [
        re.compile(r"getSession|getServerSession|getToken|auth\(|withAuth|requireAuth", re.IGNORECASE),
        re.compile(r"verifyToken|validateToken|checkAuth|isAuthenticated|session\?\.user", re.IGNORECASE),
        re.compile(r"authorization|bearer|jwt\.verify|middleware|authMiddleware", re.IGNORECASE),
        re.compile(r"NextAuth|clerk|supabase\.auth|lucia|iron-session", re.IGNORECASE),
        re.compile(r"cookies\(\)\.get|headers\(\)\.get\(['\"]authorization", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/306.html",
        "https://nextjs.org/docs/app/building-your-application/routing/route-handlers",
    ],
})

# ── 13. Express Middleware Ordering ─────────────────────────────────────
_register({
    "rule_id": "js_deep.express-middleware-ordering",
    "severity": "high",
    "confidence": "medium",
    "title": "Express Route Handler Before Auth Middleware",
    "description": (
        "A route handler (app.get, app.post, etc.) is defined before auth middleware "
        "is registered with app.use(). This means the route handler will execute "
        "without authentication, potentially exposing sensitive endpoints."
    ),
    "cwe_id": "CWE-862",
    "owasp_category": "A01:2021",
    "patterns": [
        re.compile(r"app\.(?:get|post|put|patch|delete)\s*\(\s*['\"/]"),
        re.compile(r"router\.(?:get|post|put|patch|delete)\s*\(\s*['\"/]"),
    ],
    "negative_patterns": [
        re.compile(r"app\.use\s*\([^)]*(?:auth|session|passport|jwt|protect|guard)", re.IGNORECASE),
        re.compile(r"(?:auth|session|passport|jwt|protect|guard)Middleware", re.IGNORECASE),
        re.compile(r"requireAuth|isAuthenticated|ensureAuth|checkAuth|verifyToken", re.IGNORECASE),
    ],
    "context_required": re.compile(
        r"(?:app\.use|router\.use)\s*\([^)]*(?:auth|session|passport|jwt|protect|guard)",
        re.IGNORECASE,
    ),
    "references": [
        "https://cwe.mitre.org/data/definitions/862.html",
        "https://expressjs.com/en/guide/using-middleware.html",
    ],
})

# ── 14. localStorage/sessionStorage for Tokens ─────────────────────────
_register({
    "rule_id": "js_deep.storage-sensitive-token",
    "severity": "medium",
    "confidence": "high",
    "title": "Sensitive Token Stored in localStorage/sessionStorage",
    "description": (
        "Authentication tokens, JWTs, or credentials are stored in "
        "localStorage or sessionStorage, which are accessible to any JavaScript "
        "running on the page. XSS attacks can steal these tokens. Use httpOnly "
        "cookies for sensitive authentication data instead."
    ),
    "cwe_id": "CWE-922",
    "owasp_category": "A07:2021",
    "patterns": [
        re.compile(r"localStorage\.setItem\s*\(\s*['\"](?:token|jwt|access_token|auth_token|refresh_token|id_token|session|bearer)", re.IGNORECASE),
        re.compile(r"sessionStorage\.setItem\s*\(\s*['\"](?:token|jwt|access_token|auth_token|refresh_token|id_token|session|bearer)", re.IGNORECASE),
        re.compile(r"localStorage\s*\[\s*['\"](?:token|jwt|access_token|auth_token|refresh_token|id_token|session|bearer)", re.IGNORECASE),
        re.compile(r"sessionStorage\s*\[\s*['\"](?:token|jwt|access_token|auth_token|refresh_token|id_token|session|bearer)", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/922.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage",
    ],
})

# ── 15. CORS Wildcard ──────────────────────────────────────────────────
_register({
    "rule_id": "js_deep.cors-wildcard",
    "severity": "high",
    "confidence": "high",
    "title": "CORS Wildcard or Unconfigured Origin",
    "description": (
        "CORS is configured with origin: '*' or cors() is called without origin "
        "configuration, allowing any website to make cross-origin requests. "
        "Combined with credentials, this can lead to data theft."
    ),
    "cwe_id": "CWE-942",
    "owasp_category": "A05:2021",
    "patterns": [
        re.compile(r"""cors\s*\(\s*\{\s*origin\s*:\s*['\"]?\*['\"]?"""),
        re.compile(r"""cors\s*\(\s*\)"""),
        re.compile(r"""['"]Access-Control-Allow-Origin['"]\s*,\s*['\"]\*['\"]"""),
        re.compile(r"""res\.(?:header|setHeader|set)\s*\(\s*['\"]Access-Control-Allow-Origin['\"],\s*['\"]\*['\"]"""),
    ],
    "negative_patterns": [
        re.compile(r"origin\s*:\s*\[", re.IGNORECASE),
        re.compile(r"origin\s*:\s*(?:process\.env|config|options|settings)", re.IGNORECASE),
        re.compile(r"corsOptions|corsConfig|allowedOrigins", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/942.html",
        "https://portswigger.net/web-security/cors",
    ],
})

# ── 16. JWT Secret Hardcoding ──────────────────────────────────────────
_register({
    "rule_id": "js_deep.jwt-hardcoded-secret",
    "severity": "critical",
    "confidence": "high",
    "title": "Hardcoded JWT Signing Secret",
    "description": (
        "A JWT is signed or verified using a hardcoded string secret. "
        "If the secret is leaked, attackers can forge arbitrary tokens. "
        "Use environment variables or a key management service for JWT secrets."
    ),
    "cwe_id": "CWE-798",
    "owasp_category": "A02:2021",
    "patterns": [
        re.compile(r"""jwt\.sign\s*\(\s*[^,]+,\s*['"][^'"]{2,}['"]"""),
        re.compile(r"""jwt\.verify\s*\(\s*[^,]+,\s*['"][^'"]{2,}['"]"""),
        re.compile(r"""jsonwebtoken.*\.sign\s*\(\s*[^,]+,\s*['"][^'"]{2,}['"]"""),
        re.compile(r"""jsonwebtoken.*\.verify\s*\(\s*[^,]+,\s*['"][^'"]{2,}['"]"""),
    ],
    "negative_patterns": [
        re.compile(r"process\.env"),
        re.compile(r"config\.", re.IGNORECASE),
        re.compile(r"(?:secret|key)\s*[=:]\s*process\.env", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    ],
})

# ── 17. GraphQL Resolver Missing Auth ──────────────────────────────────
_register({
    "rule_id": "js_deep.graphql-resolver-no-auth",
    "severity": "high",
    "confidence": "medium",
    "title": "GraphQL Resolver Without Authentication Check",
    "description": (
        "A GraphQL resolver function does not check for authentication via "
        "context, session, or user objects. Unauthenticated resolvers can expose "
        "sensitive data or mutations to any client."
    ),
    "cwe_id": "CWE-306",
    "owasp_category": "A07:2021",
    "patterns": [
        # Typical resolver patterns: Mutation/Query resolver objects
        re.compile(r"(?:Mutation|Query)\s*:\s*\{"),
        # Resolver function patterns
        re.compile(r"(?:resolve|fieldResolver)\s*[:(]\s*(?:async\s+)?(?:function\s*)?\((?:parent|root|_|obj)\s*,\s*(?:args|input)\s*,\s*(?:context|ctx)"),
    ],
    "negative_patterns": [
        re.compile(r"context\.user|ctx\.user|context\.auth|ctx\.auth", re.IGNORECASE),
        re.compile(r"isAuthenticated|requireAuth|checkAuth|verifyAuth", re.IGNORECASE),
        re.compile(r"authGuard|AuthGuard|@Authorized|@UseGuards", re.IGNORECASE),
        re.compile(r"if\s*\(\s*!\s*(?:context|ctx)\.(?:user|auth|session)", re.IGNORECASE),
        re.compile(r"throw.*(?:Unauthorized|AuthenticationError|ForbiddenError)", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/306.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
    ],
})

# ── 18. Open Redirect ──────────────────────────────────────────────────
_register({
    "rule_id": "js_deep.open-redirect",
    "severity": "medium",
    "confidence": "high",
    "title": "Open Redirect via User Input",
    "description": (
        "User-controlled input (e.g., req.query.url, req.body.redirect) is passed "
        "directly to res.redirect() without validation. Attackers can use this to "
        "redirect users to phishing or malicious sites."
    ),
    "cwe_id": "CWE-601",
    "owasp_category": "A01:2021",
    "patterns": [
        re.compile(r"res\.redirect\s*\(\s*req\.(?:query|params|body)\.\w+"),
        re.compile(r"res\.redirect\s*\(\s*req\.(?:query|params|body)\["),
        re.compile(r"res\.redirect\s*\(\s*`[^`]*\$\{req\.(?:query|params|body)"),
        re.compile(r"res\.redirect\s*\(\s*(?:url|redirect|returnUrl|next|callback|goto|dest|target|redir)", re.IGNORECASE),
        re.compile(r"location\.href\s*=\s*(?:searchParams|params|query)", re.IGNORECASE),
    ],
    "negative_patterns": [
        re.compile(r"(?:startsWith|indexOf|match|test)\s*\(\s*['\"](?:https?:)?//", re.IGNORECASE),
        re.compile(r"whitelist|allowlist|safelist|allowedUrls|validRedirects", re.IGNORECASE),
        re.compile(r"url\.parse|new\s+URL\(", re.IGNORECASE),
        re.compile(r"\.hostname\s*===|\.host\s*===", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/601.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    ],
})

# ── 19. SSRF via fetch/axios ───────────────────────────────────────────
_register({
    "rule_id": "js_deep.ssrf-fetch-axios",
    "severity": "high",
    "confidence": "high",
    "title": "Server-Side Request Forgery (SSRF) via User Input",
    "description": (
        "User-controlled input is passed directly to fetch(), axios, or http.get() "
        "as a URL, allowing attackers to make the server issue requests to internal "
        "services, cloud metadata endpoints, or other infrastructure."
    ),
    "cwe_id": "CWE-918",
    "owasp_category": "A10:2021",
    "patterns": [
        re.compile(r"fetch\s*\(\s*req\.(?:query|body|params)\.\w+"),
        re.compile(r"fetch\s*\(\s*`[^`]*\$\{req\.(?:query|body|params)"),
        re.compile(r"axios\.(?:get|post|put|delete|patch|request)\s*\(\s*req\.(?:query|body|params)\.\w+"),
        re.compile(r"axios\.(?:get|post|put|delete|patch|request)\s*\(\s*`[^`]*\$\{req\.(?:query|body|params)"),
        re.compile(r"http\.(?:get|request)\s*\(\s*req\.(?:query|body|params)\.\w+"),
        re.compile(r"https\.(?:get|request)\s*\(\s*req\.(?:query|body|params)\.\w+"),
        re.compile(r"got\s*\(\s*req\.(?:query|body|params)\.\w+"),
        re.compile(r"needle\s*\(\s*['\"](?:get|post)['\"],\s*req\.(?:query|body|params)\.\w+"),
    ],
    "negative_patterns": [
        re.compile(r"(?:allowlist|whitelist|validUrls|allowedHosts|safelist)", re.IGNORECASE),
        re.compile(r"(?:ssrf-req-filter|ssrf-agent|ssrf-protect)", re.IGNORECASE),
        re.compile(r"new\s+URL\([^)]+\)\.hostname", re.IGNORECASE),
        re.compile(r"\.includes\s*\(\s*['\"](?:localhost|127\.0\.0\.1|169\.254)", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/918.html",
        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    ],
})

# ── 20. XXE in xml2js ──────────────────────────────────────────────────
_register({
    "rule_id": "js_deep.xxe-xml2js",
    "severity": "high",
    "confidence": "medium",
    "title": "XXE Risk in XML Parser Configuration",
    "description": (
        "xml2js, libxmljs, or fast-xml-parser is used without explicitly disabling "
        "external entity processing. Insecure XML parsing can allow attackers to "
        "read files, perform SSRF, or cause denial of service."
    ),
    "cwe_id": "CWE-611",
    "owasp_category": "A05:2021",
    "patterns": [
        re.compile(r"xml2js\.parseString\s*\("),
        re.compile(r"new\s+xml2js\.Parser\s*\("),
        re.compile(r"libxmljs\.parseXml\s*\("),
        re.compile(r"(?:require|from)\s*\(?['\"]fast-xml-parser['\"]"),
        re.compile(r"new\s+(?:XMLParser|DOMParser)\s*\("),
    ],
    "negative_patterns": [
        re.compile(r"explicitArray\s*:\s*false", re.IGNORECASE),
        re.compile(r"noent\s*:\s*false", re.IGNORECASE),
        re.compile(r"dtdload\s*:\s*false", re.IGNORECASE),
        re.compile(r"externalEntities\s*:\s*false", re.IGNORECASE),
        re.compile(r"processEntities\s*:\s*false", re.IGNORECASE),
        re.compile(r"entityExpansion", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/611.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    ],
})

# ── 21. Electron nodeIntegration ────────────────────────────────────────
_register({
    "rule_id": "js_deep.electron-node-integration",
    "severity": "critical",
    "confidence": "high",
    "title": "Electron nodeIntegration Enabled",
    "description": (
        "Electron BrowserWindow is configured with nodeIntegration: true, which "
        "gives renderer processes full Node.js access. If the renderer loads any "
        "remote or untrusted content, attackers can execute arbitrary commands. "
        "Use contextBridge and preload scripts instead."
    ),
    "cwe_id": "CWE-829",
    "owasp_category": "A05:2021",
    "patterns": [
        re.compile(r"nodeIntegration\s*:\s*true"),
        re.compile(r"contextIsolation\s*:\s*false"),
        re.compile(r"webSecurity\s*:\s*false"),
    ],
    "negative_patterns": [
        re.compile(r"nodeIntegration\s*:\s*false"),
        re.compile(r"contextIsolation\s*:\s*true"),
        re.compile(r"sandbox\s*:\s*true"),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/829.html",
        "https://www.electronjs.org/docs/latest/tutorial/security",
    ],
})

# ── 22. WebSocket Without Origin Validation ─────────────────────────────
_register({
    "rule_id": "js_deep.websocket-no-origin-check",
    "severity": "medium",
    "confidence": "medium",
    "title": "WebSocket Server Without Origin Validation",
    "description": (
        "A WebSocket server (ws, socket.io) is created without verifyClient, "
        "handleUpgrade, or origin validation, allowing cross-site WebSocket "
        "hijacking from any origin."
    ),
    "cwe_id": "CWE-346",
    "owasp_category": "A07:2021",
    "patterns": [
        re.compile(r"new\s+WebSocket\.Server\s*\("),
        re.compile(r"new\s+WebSocketServer\s*\("),
        re.compile(r"new\s+(?:ws\.)?Server\s*\(\s*\{[^}]*port\s*:"),
    ],
    "negative_patterns": [
        re.compile(r"verifyClient"),
        re.compile(r"handleUpgrade"),
        re.compile(r"origin", re.IGNORECASE),
        re.compile(r"allowedOrigins|corsOrigin|originIsAllowed", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/346.html",
        "https://christian-schneider.net/CrossSiteWebSocketHijacking.html",
    ],
})

# ── 23. Timing-Safe Comparison Missing ──────────────────────────────────
_register({
    "rule_id": "js_deep.timing-unsafe-comparison",
    "severity": "medium",
    "confidence": "medium",
    "title": "Timing-Unsafe Secret Comparison",
    "description": (
        "A secret value (token, API key, password hash, HMAC) is compared using "
        "=== or == instead of crypto.timingSafeEqual(). Timing side-channel "
        "attacks can leak the secret byte-by-byte."
    ),
    "cwe_id": "CWE-208",
    "owasp_category": "A02:2021",
    "patterns": [
        re.compile(r"(?:token|secret|apiKey|api_key|hmac|hash|signature|digest|password)\s*===\s*", re.IGNORECASE),
        re.compile(r"===\s*(?:token|secret|apiKey|api_key|hmac|hash|signature|digest|password)\b", re.IGNORECASE),
        re.compile(r"(?:token|secret|apiKey|api_key|hmac|hash|signature|digest|password)\s*==\s*", re.IGNORECASE),
        re.compile(r"==\s*(?:token|secret|apiKey|api_key|hmac|hash|signature|digest|password)\b", re.IGNORECASE),
    ],
    "negative_patterns": [
        re.compile(r"timingSafeEqual"),
        re.compile(r"crypto\.subtle\.verify"),
        re.compile(r"constantTimeEqual|safeCompare|secureCompare", re.IGNORECASE),
        re.compile(r"bcrypt\.compare|argon2\.verify|scrypt\.verify", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/208.html",
        "https://codahale.com/a-lesson-in-timing-attacks/",
    ],
})

# ── 24. Mass Assignment ────────────────────────────────────────────────
_register({
    "rule_id": "js_deep.mass-assignment",
    "severity": "high",
    "confidence": "medium",
    "title": "Mass Assignment via Unsanitized Request Body",
    "description": (
        "ORM create/update methods (Sequelize, TypeORM, Prisma, Mongoose) are "
        "called directly with req.body without selecting allowed fields. Attackers "
        "can set admin flags, roles, or other privileged fields."
    ),
    "cwe_id": "CWE-915",
    "owasp_category": "A08:2021",
    "patterns": [
        re.compile(r"\.create\s*\(\s*req\.body\s*\)"),
        re.compile(r"\.update\s*\(\s*req\.body\s*\)"),
        re.compile(r"\.bulkCreate\s*\(\s*req\.body\s*\)"),
        re.compile(r"\.findOneAndUpdate\s*\([^,]*,\s*req\.body\s*\)"),
        re.compile(r"\.updateOne\s*\([^,]*,\s*req\.body\s*\)"),
        re.compile(r"\.updateMany\s*\([^,]*,\s*req\.body\s*\)"),
        re.compile(r"\.insertMany\s*\(\s*req\.body\s*\)"),
        re.compile(r"\.save\s*\(\s*req\.body\s*\)"),
        re.compile(r"Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)"),
        re.compile(r"\{\s*\.\.\.req\.body\s*\}"),
    ],
    "negative_patterns": [
        re.compile(r"pick\s*\(|omit\s*\(|allowedFields|sanitize", re.IGNORECASE),
        re.compile(r"Joi\.validate|yup\.validate|zod\.parse|validator", re.IGNORECASE),
        re.compile(r"\bonly\s*\(|\bexclude\s*\(|\bselect\s*\(", re.IGNORECASE),
        re.compile(r"class-validator|class-transformer", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/915.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
    ],
})

# ── 25. Unvalidated File Upload ────────────────────────────────────────
_register({
    "rule_id": "js_deep.unvalidated-file-upload",
    "severity": "high",
    "confidence": "medium",
    "title": "File Upload Without Type Validation",
    "description": (
        "File upload handling (multer, formidable, busboy) does not validate "
        "file type, extension, or MIME type. Attackers can upload executable "
        "files, web shells, or malicious content."
    ),
    "cwe_id": "CWE-434",
    "owasp_category": "A04:2021",
    "patterns": [
        re.compile(r"multer\s*\(\s*\{[^}]*dest\s*:", re.DOTALL),
        re.compile(r"multer\s*\(\s*\{[^}]*storage\s*:", re.DOTALL),
        re.compile(r"multer\s*\(\s*\)"),
        re.compile(r"new\s+formidable\s*\(", re.IGNORECASE),
        re.compile(r"formidable\s*\(\s*\{", re.IGNORECASE),
        re.compile(r"busboy\s*\(\s*\{", re.IGNORECASE),
    ],
    "negative_patterns": [
        re.compile(r"fileFilter|mimetype|mimeType|allowedTypes|fileTypes", re.IGNORECASE),
        re.compile(r"\.(?:endsWith|includes)\s*\(\s*['\"]\.(?:jpg|png|pdf|gif)", re.IGNORECASE),
        re.compile(r"file-type|magic-bytes|file-extension|mime-types", re.IGNORECASE),
        re.compile(r"limits\s*:\s*\{[^}]*fileSize", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/434.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
    ],
})

# ── 26. eval with Template Literal ─────────────────────────────────────
_register({
    "rule_id": "js_deep.eval-template-literal",
    "severity": "critical",
    "confidence": "high",
    "title": "eval() with Template Literal or Dynamic String",
    "description": (
        "eval() is called with a template literal containing variable interpolation "
        "or with dynamic string concatenation. This allows arbitrary code execution "
        "if any interpolated variable is user-controlled."
    ),
    "cwe_id": "CWE-95",
    "owasp_category": "A03:2021",
    "patterns": [
        re.compile(r"eval\s*\(\s*`[^`]*\$\{"),
        re.compile(r"eval\s*\(\s*['\"][^'\"]*['\"]\s*\+"),
        re.compile(r"eval\s*\(\s*\w+\s*\+"),
        re.compile(r"new\s+Function\s*\(\s*`[^`]*\$\{"),
        re.compile(r"new\s+Function\s*\(\s*['\"][^'\"]*['\"]\s*\+"),
        re.compile(r"new\s+Function\s*\(\s*\w+\s*\+"),
    ],
    "negative_patterns": [
        re.compile(r"//\s*eslint-disable"),
        re.compile(r"//\s*nosec"),
        re.compile(r"//\s*safe:"),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/95.html",
        "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!",
    ],
})

# ── 27. Insecure Cookie Missing Flags ──────────────────────────────────
_register({
    "rule_id": "js_deep.insecure-cookie",
    "severity": "medium",
    "confidence": "medium",
    "title": "Cookie Set Without Security Flags",
    "description": (
        "res.cookie() or Set-Cookie header is used without httpOnly, secure, or "
        "sameSite flags. Cookies without httpOnly are accessible to JavaScript "
        "(XSS risk), without secure they are sent over HTTP, and without sameSite "
        "they are vulnerable to CSRF attacks."
    ),
    "cwe_id": "CWE-614",
    "owasp_category": "A05:2021",
    "patterns": [
        re.compile(r"res\.cookie\s*\(\s*['\"]"),
        re.compile(r"(?:set|setHeader|writeHead)\s*\(\s*['\"]Set-Cookie['\"]"),
        re.compile(r"document\.cookie\s*="),
    ],
    "negative_patterns": [
        re.compile(r"httpOnly\s*:\s*true", re.IGNORECASE),
        re.compile(r"secure\s*:\s*true", re.IGNORECASE),
        re.compile(r"sameSite\s*:\s*['\"](?:strict|lax|none)['\"]", re.IGNORECASE),
        re.compile(r"HttpOnly", re.IGNORECASE),
        re.compile(r"Secure;", re.IGNORECASE),
        re.compile(r"SameSite=", re.IGNORECASE),
        re.compile(r"cookie-session|express-session|csurf", re.IGNORECASE),
    ],
    "references": [
        "https://cwe.mitre.org/data/definitions/614.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies",
    ],
})


# ═══════════════════════════════════════════════════════════════════════════
# SCANNING ENGINE
# ═══════════════════════════════════════════════════════════════════════════

def scan_javascript(source_path: str) -> list[dict]:
    """Deep JS/TS security analysis. Returns list of finding dicts.

    Walks the source tree, reads JS/TS files line-by-line, and applies
    regex-based pattern checks with context awareness.

    Args:
        source_path: Root directory of the source code to scan.

    Returns:
        Deduplicated list of finding dicts compatible with SastFinding schema,
        each with ``rule_source="js_deep"``.
    """
    findings: list[dict] = []
    files_scanned = 0

    if not os.path.isdir(source_path):
        logger.warning("js_analyzer: source_path is not a directory: %s", source_path)
        return findings

    for root, dirs, filenames in os.walk(source_path):
        if files_scanned >= MAX_FILES:
            logger.info("js_analyzer: file limit (%d) reached, stopping walk", MAX_FILES)
            break

        # Prune skippable directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in filenames:
            if files_scanned >= MAX_FILES:
                break

            # Extension check
            ext = os.path.splitext(fname)[1].lower()
            if ext not in JS_EXTENSIONS:
                continue

            # Skip minified files
            lower_fname = fname.lower()
            if any(lower_fname.endswith(s) for s in SKIP_SUFFIXES):
                continue

            fpath = os.path.join(root, fname)

            # Size check
            try:
                if os.path.getsize(fpath) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            try:
                rel_path = os.path.relpath(fpath, source_path)
                file_findings = _scan_file(fpath, rel_path)
                findings.extend(file_findings)
                files_scanned += 1
            except Exception as exc:
                logger.debug("js_analyzer: skipped %s: %s", fname, exc)

    # Deduplicate by fingerprint
    seen: set[str] = set()
    deduped: list[dict] = []
    for f in findings:
        fp = f.get("fingerprint", "")
        if fp and fp not in seen:
            seen.add(fp)
            deduped.append(f)
        elif not fp:
            deduped.append(f)

    logger.info(
        "js_analyzer: scanned %d files, found %d issues (%d after dedup)",
        files_scanned, len(findings), len(deduped),
    )
    return deduped


def _scan_file(file_path: str, rel_path: str) -> list[dict]:
    """Run all checks against a single file."""
    try:
        with open(file_path, "r", errors="ignore") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[dict] = []

    for check in _CHECKS:
        check_findings = _run_check(check, lines, rel_path)
        findings.extend(check_findings)

    return findings


def _run_check(check: dict, lines: list[str], rel_path: str) -> list[dict]:
    """Run a single check definition against the file lines."""
    findings: list[dict] = []
    patterns: list[re.Pattern] = check["patterns"]
    negative_patterns: list[re.Pattern] = check.get("negative_patterns", [])
    context_required: re.Pattern | None = check.get("context_required")

    for line_num_0, line in enumerate(lines):
        line_num = line_num_0 + 1  # 1-based

        # Skip comment-only lines to reduce false positives
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        for pattern in patterns:
            if not pattern.search(line):
                continue

            # ── Negative-pattern suppression ──────────────────────
            # Check the current line and surrounding context for negative patterns
            context_window = _get_context_window(lines, line_num_0, window=8)
            context_text = "\n".join(context_window)

            if any(neg.search(context_text) for neg in negative_patterns):
                continue

            # ── Context-required check ────────────────────────────
            # If the check requires a certain pattern in surrounding context,
            # verify it is present.
            if context_required is not None:
                wide_context = _get_context_window(lines, line_num_0, window=10)
                wide_text = "\n".join(wide_context)
                if not context_required.search(wide_text) and not context_required.search(line):
                    continue

            # ── Confidence adjustment ─────────────────────────────
            confidence = check["confidence"]
            if _SANITIZATION_HINTS.search(context_text):
                # Downgrade confidence if sanitization is nearby
                if confidence == "high":
                    confidence = "medium"
                elif confidence == "medium":
                    confidence = "low"

            # ── Build snippet ─────────────────────────────────────
            snippet_lines = _get_context_window(lines, line_num_0, window=CONTEXT_LINES)
            snippet = "".join(snippet_lines)

            # ── Fingerprint ───────────────────────────────────────
            fp_raw = f"{check['rule_id']}|{rel_path}|{line_num}"
            fingerprint = hashlib.sha256(fp_raw.encode()).hexdigest()[:32]

            findings.append({
                "rule_id": check["rule_id"],
                "rule_source": "js_deep",
                "severity": check["severity"],
                "confidence": confidence,
                "title": check["title"],
                "description": check["description"],
                "message": f"{check['title']} at {rel_path}:{line_num}",
                "file_path": rel_path,
                "line_start": line_num,
                "line_end": line_num,
                "column_start": None,
                "column_end": None,
                "code_snippet": snippet[:3000],
                "cwe_id": check.get("cwe_id"),
                "owasp_category": check.get("owasp_category"),
                "references": check.get("references", []),
                "fingerprint": fingerprint,
            })
            # Only report the first matching pattern per line per check
            break

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _get_context_window(lines: list[str], center_idx: int, window: int = 3) -> list[str]:
    """Return lines surrounding *center_idx* (0-based), clamped to file bounds."""
    start = max(0, center_idx - window)
    end = min(len(lines), center_idx + window + 1)
    return lines[start:end]
