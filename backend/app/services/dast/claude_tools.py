"""Claude DAST tool definitions — JSON schemas for Claude API tool_use."""


def build_all_tools(available_checks: list[str]) -> list[dict]:
    """Build complete tool list for Claude DAST agent.

    Args:
        available_checks: List of check names from ALL_CHECKS registry.

    Returns:
        List of tool dicts compatible with Anthropic messages API.
    """
    checks_desc = ", ".join(available_checks) if available_checks else "none"

    return [
        # ── CRAWLING & DISCOVERY ──────────────────────────────────────
        {
            "name": "browse_url",
            "description": (
                "Browse a URL using a headless browser (Playwright). Returns full HTML, "
                "all links, forms, scripts, network requests (XHR/fetch), cookies, and console logs. "
                "Use this for SPAs, JavaScript-rendered content, and understanding page structure. "
                "Optionally perform actions like scrolling, clicking, or typing."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to browse"},
                    "actions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string", "enum": ["click", "scroll", "type", "wait", "screenshot"]},
                                "selector": {"type": "string", "description": "CSS selector for click/type"},
                                "value": {"type": "string", "description": "Text to type (for type action)"},
                                "duration_ms": {"type": "integer", "description": "Wait duration in ms"},
                            },
                            "required": ["type"],
                        },
                        "description": "Browser actions to perform in sequence",
                    },
                    "auth_headers": {"type": "object", "description": "Auth headers to set"},
                    "wait_for_network_idle": {"type": "boolean", "default": True},
                },
                "required": ["url"],
            },
        },
        {
            "name": "crawl_sitemap",
            "description": (
                "Parse sitemap.xml and robots.txt from the target. Returns all URLs from sitemap, "
                "disallowed paths from robots.txt, and interesting paths that may contain sensitive content."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Base URL of the target"},
                },
                "required": ["target_url"],
            },
        },
        {
            "name": "discover_endpoints",
            "description": (
                "Discover hidden paths and endpoints using wordlist-based fuzzing. "
                "Use technology-specific wordlists for better results. Returns found paths with status codes."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string", "description": "Base URL to fuzz (e.g., https://target.com/api/)"},
                    "wordlist_type": {
                        "type": "string",
                        "enum": ["common", "api", "admin", "backup", "config", "node", "php", "java", "python", "dotnet"],
                        "description": "Type of wordlist to use based on target technology",
                    },
                    "custom_words": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional custom words to try (e.g., app-specific paths)",
                    },
                    "extensions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "File extensions to append (e.g., ['.php', '.bak', '.old'])",
                    },
                    "auth_headers": {"type": "object", "description": "Auth headers for authenticated fuzzing"},
                },
                "required": ["base_url"],
            },
        },
        {
            "name": "enumerate_subdomains",
            "description": (
                "Enumerate subdomains for a domain using certificate transparency logs (crt.sh), "
                "DNS brute force, and common subdomain wordlists. Returns discovered subdomains with IPs and status."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Root domain (e.g., example.com)"},
                    "methods": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["crt_transparency", "dns_bruteforce", "common_subdomains"]},
                        "description": "Discovery methods to use",
                        "default": ["crt_transparency", "common_subdomains"],
                    },
                },
                "required": ["domain"],
            },
        },
        {
            "name": "analyze_javascript",
            "description": (
                "Analyze a JavaScript file for security-relevant content: hidden API endpoints, "
                "hardcoded secrets (API keys, tokens, passwords), library versions (for SCA), "
                "configuration objects, and developer comments with TODOs/FIXMEs."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "js_url": {"type": "string", "description": "URL of the JavaScript file to analyze"},
                    "js_content": {"type": "string", "description": "Raw JS content (if already fetched). Max 50KB."},
                },
            },
        },
        {
            "name": "discover_api_schema",
            "description": (
                "Discover API schemas: OpenAPI/Swagger for REST, introspection for GraphQL, "
                "reflection for gRPC, WSDL for SOAP. Returns endpoints, types, and auth requirements."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string", "description": "Base URL of the API"},
                    "api_type": {
                        "type": "string",
                        "enum": ["rest", "graphql", "grpc", "soap", "auto"],
                        "default": "auto",
                        "description": "API type to probe for. 'auto' tries all.",
                    },
                },
                "required": ["base_url"],
            },
        },
        {
            "name": "interact_form",
            "description": (
                "Interact with an HTML form: fill fields and optionally submit. "
                "Use for testing login forms, search forms, registration, and other form-based functionality. "
                "Captures full request/response including redirects and cookies."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "form_url": {"type": "string", "description": "URL of the page containing the form"},
                    "form_action": {"type": "string", "description": "Form action URL (submit target)"},
                    "form_method": {"type": "string", "enum": ["GET", "POST"], "default": "POST"},
                    "fields": {
                        "type": "object",
                        "description": "Form field name→value pairs to fill",
                    },
                    "submit": {"type": "boolean", "default": True, "description": "Whether to submit the form"},
                    "auth_headers": {"type": "object", "description": "Auth headers to include"},
                },
                "required": ["form_url", "fields"],
            },
        },
        # ── TESTING & ATTACK ──────────────────────────────────────────
        {
            "name": "http_request",
            "description": (
                "Send a custom HTTP request to the target. Use for testing specific vulnerabilities, "
                "verifying findings, and dynamic payload testing. Supports concurrent requests for "
                "race condition testing and raw bodies for HTTP smuggling. "
                "ALWAYS check the response for vulnerability indicators."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]},
                    "url": {"type": "string", "description": "Full URL to request"},
                    "headers": {"type": "object", "description": "Custom request headers"},
                    "body": {"type": "string", "description": "Request body (for POST/PUT/PATCH)"},
                    "content_type": {"type": "string", "description": "Content-Type header shorthand (json, form, xml, text)"},
                    "follow_redirects": {"type": "boolean", "default": False},
                    "timeout_seconds": {"type": "number", "default": 15},
                    "concurrent_count": {
                        "type": "integer",
                        "description": "Send N identical requests simultaneously for race condition testing (max 50)",
                        "default": 1,
                    },
                    "raw_body": {
                        "type": "string",
                        "description": "Raw HTTP body bytes (for smuggling tests). Overrides body if set.",
                    },
                    "auth_headers": {"type": "object", "description": "Auth headers to include"},
                },
                "required": ["method", "url"],
            },
        },
        {
            "name": "run_dast_check",
            "description": (
                f"Run a predefined DAST security check. Available checks: {checks_desc}. "
                "Each check returns a structured result with status (passed/failed/error), "
                "severity, evidence, request/response, CWE/OWASP mapping, and remediation."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "check_name": {"type": "string", "description": "Name of the check to run"},
                    "target_url": {"type": "string", "description": "URL to test (defaults to scan target)"},
                },
                "required": ["check_name"],
            },
        },
        {
            "name": "test_injection",
            "description": (
                "Test a parameter for injection vulnerabilities with intelligent payload escalation. "
                "Supports SQLi (error/blind/time-based/union), XSS (reflected/DOM), command injection, "
                "SSTI, LDAP, NoSQL, XPath, and XXE. Automatically escalates to obfuscated/WAF-bypass "
                "payloads if basic payloads are blocked."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL containing the parameter"},
                    "parameter": {"type": "string", "description": "Parameter name to test"},
                    "param_location": {"type": "string", "enum": ["query", "body", "header", "cookie", "path"], "default": "query"},
                    "injection_type": {
                        "type": "string",
                        "enum": ["sqli", "xss", "cmdi", "ssti", "ldap", "nosql", "xpath", "xxe", "auto"],
                        "description": "Type of injection to test. 'auto' tests all relevant types.",
                    },
                    "payload_level": {
                        "type": "string",
                        "enum": ["basic", "obfuscated", "waf_bypass", "all"],
                        "default": "basic",
                        "description": "Payload sophistication level. Use 'waf_bypass' when WAF blocks basic payloads.",
                    },
                    "custom_payloads": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Custom payloads to try in addition to built-in ones",
                    },
                    "auth_headers": {"type": "object"},
                    "base_method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                },
                "required": ["url", "parameter"],
            },
        },
        {
            "name": "test_authentication",
            "description": (
                "Test authentication security: brute force with context-aware wordlists, "
                "default credential testing, session management analysis, JWT attacks "
                "(alg:none, weak secret, kid injection), OAuth flow abuse, MFA bypass. "
                "Selects appropriate wordlists based on application type."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "login_url": {"type": "string", "description": "URL of the login endpoint"},
                    "username_field": {"type": "string", "default": "username"},
                    "password_field": {"type": "string", "default": "password"},
                    "test_type": {
                        "type": "string",
                        "enum": ["default_creds", "bruteforce", "session", "jwt", "oauth", "mfa", "all"],
                    },
                    "app_context": {
                        "type": "object",
                        "description": "Context for smart wordlist selection: {app_type, technology, discovered_usernames[]}",
                    },
                    "auth_headers": {"type": "object"},
                },
                "required": ["login_url", "test_type"],
            },
        },
        {
            "name": "test_race_condition",
            "description": (
                "Send multiple HTTP requests simultaneously to test for race conditions. "
                "Uses HTTP/2 single-packet technique for maximum timing precision. "
                "Targets: coupon redemption, money transfer, vote manipulation, inventory purchase, "
                "like/follow duplication, account creation, privilege changes."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to test"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"], "default": "POST"},
                    "headers": {"type": "object"},
                    "body": {"type": "string"},
                    "concurrent_count": {"type": "integer", "default": 20, "description": "Number of concurrent requests (max 50)"},
                    "repeat_rounds": {"type": "integer", "default": 3, "description": "Number of rounds to repeat"},
                    "auth_headers": {"type": "object"},
                },
                "required": ["url"],
            },
        },
        {
            "name": "test_websocket",
            "description": (
                "Connect to a WebSocket endpoint and test for security issues: "
                "missing origin validation, cross-site WebSocket hijacking (CSWSH), "
                "message injection, binary message fuzzing, auth bypass."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "ws_url": {"type": "string", "description": "WebSocket URL (ws:// or wss://)"},
                    "initial_messages": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Messages to send on connection (e.g., auth handshake)",
                    },
                    "test_messages": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Malicious test messages to send",
                    },
                    "test_origins": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Origins to test for CSWSH (e.g., ['https://evil.com', 'null'])",
                    },
                    "auth_headers": {"type": "object"},
                },
                "required": ["ws_url"],
            },
        },
        {
            "name": "test_graphql",
            "description": (
                "Test GraphQL endpoint security: introspection exposure, nested query DoS, "
                "batch brute force, alias enumeration, field duplication, mutation testing, "
                "subscription abuse."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "graphql_url": {"type": "string", "description": "GraphQL endpoint URL"},
                    "test_type": {
                        "type": "string",
                        "enum": ["introspection", "dos_depth", "dos_complexity", "batching", "alias_enum", "mutations", "all"],
                    },
                    "auth_headers": {"type": "object"},
                    "max_depth": {"type": "integer", "default": 10, "description": "Max nesting depth for DoS test"},
                },
                "required": ["graphql_url", "test_type"],
            },
        },
        {
            "name": "test_llm_chatbot",
            "description": (
                "Test an LLM/AI chatbot for OWASP LLM Top 10 vulnerabilities: "
                "prompt injection (direct/indirect), sensitive data leakage, system prompt extraction, "
                "XSS via chatbot output, excessive agency testing, unbounded consumption (DoS). "
                "Use this when you detect chatbot or AI features on the target."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "chatbot_url": {"type": "string", "description": "Chatbot API endpoint or page URL"},
                    "chatbot_type": {"type": "string", "enum": ["api", "widget", "page"], "default": "api"},
                    "test_type": {
                        "type": "string",
                        "enum": ["prompt_injection", "data_leakage", "system_prompt", "xss_output", "excessive_agency", "dos", "all"],
                    },
                    "message_field": {"type": "string", "default": "message", "description": "Field name for chat message"},
                    "auth_headers": {"type": "object"},
                },
                "required": ["chatbot_url", "test_type"],
            },
        },
        # ── WORDLIST & PAYLOAD DATABASE ──────────────────────────────
        {
            "name": "get_wordlists",
            "description": (
                "Get available wordlists and payloads from the internal database. "
                "Returns wordlist names and their line counts. Use 'load_wordlist' to get the actual payloads. "
                "Categories: directory (for dir brute force), sqli, xss, lfi, auth_bypass, command_exec, traversal, passwords, usernames, fuzzing. "
                "Auto-select the best wordlist based on the detected technology and what you're testing."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": ["directory", "sqli", "xss", "lfi", "auth_bypass", "command_exec", "traversal", "passwords", "usernames", "fuzzing", "all"],
                        "description": "Category of wordlists to retrieve",
                    },
                },
                "required": ["category"],
            },
        },
        {
            "name": "load_wordlist",
            "description": (
                "Load the contents of a specific wordlist file for use in testing. "
                "Returns the payloads/words as a list. Use this after get_wordlists to load specific lists for brute forcing, fuzzing, or payload injection."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "wordlist_name": {"type": "string", "description": "Name of the wordlist file (e.g., 'dirbuster-top1000.txt', 'sqli-error-based.txt')"},
                    "max_lines": {"type": "integer", "default": 500, "description": "Maximum number of lines to return (default 500)"},
                },
                "required": ["wordlist_name"],
            },
        },
        # ── RAG & LEARNING ────────────────────────────────────────────
        {
            "name": "retrieve_past_learnings",
            "description": (
                "Retrieve past test results and learnings for a domain or technology stack. "
                "Returns known vulnerabilities, WAF bypass techniques, and previous scan intelligence. "
                "Use this to inform your testing strategy — known-working payloads should be tried first, "
                "and areas confirmed as not vulnerable can be deprioritized."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain to query learnings for"},
                    "categories": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by vulnerability categories (sqli, xss, auth, ssrf, waf_bypass, etc.)",
                    },
                    "technology": {"type": "string", "description": "Filter by technology (e.g., 'nginx', 'laravel', 'cloudflare')"},
                    "include_similar": {"type": "boolean", "default": False, "description": "Also include learnings from similar tech stacks on other domains"},
                },
                "required": ["domain"],
            },
        },
        # ── ANALYSIS & REPORTING ──────────────────────────────────────
        {
            "name": "create_finding",
            "description": (
                "Record a CONFIRMED security finding with full evidence. "
                "Only use this after verifying the vulnerability is real. "
                "Include the exact request/response that demonstrates the vulnerability."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Clear, specific title (e.g., 'Reflected XSS via SVG/onload WAF Bypass in /search')"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "description": {"type": "string", "description": "Detailed description of the vulnerability and its context"},
                    "evidence": {"type": "string", "description": "Proof of vulnerability — what in the response confirms it"},
                    "reproduction_steps": {"type": "string", "description": "Step-by-step reproduction guide"},
                    "impact": {"type": "string", "description": "Specific business impact of this vulnerability"},
                    "remediation": {"type": "string", "description": "Specific fix recommendations (not generic)"},
                    "cwe_id": {"type": "string", "description": "CWE identifier (e.g., CWE-79)"},
                    "owasp_ref": {"type": "string", "description": "OWASP reference (e.g., A03:2025)"},
                    "request_raw": {"type": "string", "description": "Full HTTP request that triggers the vulnerability"},
                    "response_raw": {"type": "string", "description": "HTTP response showing vulnerability evidence (first 5000 chars)"},
                    "affected_url": {"type": "string", "description": "Specific URL affected"},
                    "affected_parameter": {"type": "string", "description": "Specific parameter affected"},
                    "cvss_score": {"type": "string", "description": "CVSS 3.1 score if calculable"},
                },
                "required": ["title", "severity", "description", "evidence", "reproduction_steps", "remediation", "request_raw", "response_raw"],
            },
        },
        {
            "name": "save_crawl_result",
            "description": (
                "Save a crawled page/endpoint to the AI Crawled results. "
                "Call this for EVERY page, API endpoint, and resource you discover during crawling. "
                "This populates the AI Crawled tab in the frontend."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "default": "GET"},
                    "status_code": {"type": "integer"},
                    "content_type": {"type": "string"},
                    "request_raw": {"type": "string", "description": "Full HTTP request"},
                    "response_headers": {"type": "object", "description": "Response headers dict"},
                    "response_body_preview": {"type": "string", "description": "First 2000 chars of response body"},
                    "category": {
                        "type": "string",
                        "enum": ["page", "api", "form", "js_file", "static", "hidden_path", "admin", "auth", "config", "backup", "other"],
                    },
                    "forms": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Forms found on this page [{action, method, fields[]}]",
                    },
                    "links": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Links found on this page",
                    },
                    "technologies_detected": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Technologies detected on this page",
                    },
                    "secrets_found": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Secrets found [{type, value_preview, line}]",
                    },
                    "interesting_notes": {"type": "string", "description": "Any interesting security-relevant observations"},
                },
                "required": ["url", "status_code"],
            },
        },
        {
            "name": "save_test_case",
            "description": (
                "Save a new security test case to the platform's test case library. "
                "Use this when you discover a novel attack vector that should be reused in future scans."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "category": {"type": "string", "description": "OWASP category (e.g., WSTG-INPV, A03:2025)"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "payloads": {"type": "array", "items": {"type": "string"}, "description": "Test payloads"},
                    "how_to_test": {"type": "string", "description": "Step-by-step testing procedure"},
                    "pass_indicators": {"type": "string", "description": "What indicates the app is NOT vulnerable"},
                    "fail_indicators": {"type": "string", "description": "What indicates the app IS vulnerable"},
                    "remediation": {"type": "string"},
                    "cwe_id": {"type": "string"},
                    "owasp_ref": {"type": "string"},
                },
                "required": ["title", "description", "how_to_test"],
            },
        },
        {
            "name": "get_project_context",
            "description": (
                "Retrieve project context: scope, technology stack, existing findings, "
                "crawl history, test case results. Use this to understand what has already been tested."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "data_type": {
                        "type": "string",
                        "enum": ["scope", "technology", "findings", "crawl_data", "test_results", "all"],
                        "default": "all",
                    },
                },
            },
        },
        {
            "name": "offer_pentest_option",
            "description": (
                "Present deeper penetration testing options to the user for a confirmed vulnerability. "
                "The user will see these options in the UI and can choose to proceed or skip. "
                "Use this for findings where further exploitation could reveal more information "
                "(e.g., SQLi found → offer to enumerate databases, XSS found → offer to test for stored XSS)."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "finding_title": {"type": "string", "description": "Title of the related finding"},
                    "options": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "label": {"type": "string", "description": "Short label (e.g., 'Extract DB version')"},
                                "description": {"type": "string", "description": "What this option does"},
                                "risk_level": {"type": "string", "enum": ["low", "medium", "high"]},
                            },
                            "required": ["label", "description", "risk_level"],
                        },
                        "description": "Exploitation options to present to the user (max 5)",
                    },
                },
                "required": ["finding_title", "options"],
            },
        },
        {
            "name": "update_progress",
            "description": (
                "Update the scan progress displayed to the user. Call this when changing phases "
                "or at significant milestones to keep the user informed."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "phase": {
                        "type": "string",
                        "enum": ["crawling", "recon", "automated_checks", "dynamic_testing", "llm_testing", "business_logic", "verification", "test_generation", "done"],
                    },
                    "message": {"type": "string", "description": "Human-readable status message"},
                    "detail": {"type": "string", "description": "Additional detail (e.g., current URL being tested)"},
                },
                "required": ["phase", "message"],
            },
        },
    ]
