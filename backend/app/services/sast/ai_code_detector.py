"""AI-generated code detection — identify and flag AI-generated code for enhanced scrutiny.

AI-generated code is 2.74x more likely to contain XSS vulnerabilities and tends
to have patterns that can be detected heuristically:
- Repetitive structure and naming conventions
- Generic/boilerplate comment styles
- Consistent formatting regardless of project style
- Known AI model output patterns

This module flags AI-generated files for stricter confidence thresholds during scanning.
"""
import logging
import os
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Patterns that suggest AI-generated code
_AI_COMMENT_PATTERNS = [
    re.compile(r"#\s*(?:Generated|Created|Written)\s+(?:by|with|using)\s+(?:AI|GPT|Claude|Copilot|ChatGPT|Gemini|Codex|Amazon Q|Tabnine)", re.IGNORECASE),
    re.compile(r"//\s*(?:Generated|Created|Written)\s+(?:by|with|using)\s+(?:AI|GPT|Claude|Copilot|ChatGPT|Gemini|Codex)", re.IGNORECASE),
    re.compile(r"/\*\*?\s*(?:Generated|Created|Written)\s+(?:by|with|using)\s+(?:AI|GPT|Claude|Copilot|ChatGPT|Gemini|Codex)", re.IGNORECASE),
    re.compile(r"@(?:generated|auto-generated|ai-generated)", re.IGNORECASE),
    re.compile(r"This (?:code|file|module|function|class) was (?:generated|created|written) (?:by|with|using)", re.IGNORECASE),
]

# Function naming patterns common in AI output
_AI_NAMING_PATTERNS = [
    # Very descriptive camelCase/snake_case names typical of AI
    re.compile(r"def\s+(?:handle|process|validate|calculate|generate|create|update|delete|get|set|check|parse|convert|transform|format|sanitize)_[a-z]+(?:_[a-z]+){3,}\("),
    re.compile(r"function\s+(?:handle|process|validate|calculate|generate|create|update|delete|get|set|check|parse|convert|transform|format|sanitize)[A-Z][a-zA-Z]+(?:[A-Z][a-zA-Z]+){3,}\("),
]

# Documentation patterns typical of AI output
_AI_DOC_PATTERNS = [
    # Overly detailed parameter documentation
    re.compile(r'"""[^"]*\n\s+Args:\n(?:\s+\w+[^:]*:[^\n]+\n){5,}', re.MULTILINE),
    # "This function" or "This method" opening pattern
    re.compile(r'(?:"""|\'\'\'|/\*\*)\s*This (?:function|method|class|module|utility) (?:is responsible for|handles|processes|takes|accepts|returns|provides|implements)', re.IGNORECASE),
    # Numbered step comments
    re.compile(r"#\s*Step\s+\d+:", re.IGNORECASE),
    re.compile(r"//\s*Step\s+\d+:", re.IGNORECASE),
]

# Structural patterns
_AI_STRUCTURE_PATTERNS = [
    # Try-except with generic error message pattern
    re.compile(r"except\s+(?:Exception|Error)\s+as\s+e:\s*\n\s+(?:print|logger?\.\w+|raise)\s*\(\s*f?['\"](?:Error|Failed|An error occurred)", re.MULTILINE),
    # TODO/FIXME with AI-style descriptions
    re.compile(r"#\s*TODO:\s*(?:Implement|Add|Handle|Consider|Replace with)\s+", re.IGNORECASE),
    # Placeholder/stub patterns
    re.compile(r"(?:pass|raise NotImplementedError)\s*#\s*(?:TODO|FIXME|placeholder|stub)", re.IGNORECASE),
]

# Minimum lines for meaningful analysis
MIN_LINES_FOR_ANALYSIS = 20

# Thresholds
AI_SCORE_THRESHOLD = 0.6  # Above this = likely AI-generated
AI_SCORE_HIGH_CONFIDENCE = 0.8  # Above this = almost certainly AI-generated


class AICodeDetector:
    """Detect AI-generated code patterns in source files."""

    def __init__(self, strict_mode: bool = False):
        """Initialize detector.

        Args:
            strict_mode: If True, use lower thresholds for flagging
        """
        self.strict_mode = strict_mode
        self.threshold = AI_SCORE_THRESHOLD * (0.8 if strict_mode else 1.0)

    def scan_directory(self, source_path: str) -> dict:
        """Scan an entire directory for AI-generated code.

        Returns:
            {
                "total_files": int,
                "ai_generated_files": int,
                "ai_percentage": float,
                "files": [{"path": str, "score": float, "indicators": list, "lines": int}],
                "summary": str,
            }
        """
        results = []
        total_files = 0
        extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
                      ".php", ".cs", ".rs", ".kt", ".swift", ".cpp", ".c", ".h"}

        for root, dirs, files in os.walk(source_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in {
                "node_modules", ".git", "vendor", "dist", "build", "__pycache__",
                ".venv", "venv", "env", ".tox", ".mypy_cache",
            }]

            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in extensions:
                    continue

                file_path = os.path.join(root, filename)
                total_files += 1

                try:
                    result = self.analyze_file(file_path, source_path)
                    if result["score"] >= self.threshold:
                        results.append(result)
                except Exception as e:
                    logger.debug("AI detection failed for %s: %s", file_path, e)

        ai_count = len(results)
        ai_pct = (ai_count / total_files * 100) if total_files > 0 else 0

        return {
            "total_files": total_files,
            "ai_generated_files": ai_count,
            "ai_percentage": round(ai_pct, 1),
            "files": sorted(results, key=lambda x: -x["score"]),
            "summary": (
                f"{ai_count}/{total_files} files ({ai_pct:.1f}%) detected as likely AI-generated"
                if total_files > 0 else "No files analyzed"
            ),
        }

    def analyze_file(self, file_path: str, base_path: str = "") -> dict:
        """Analyze a single file for AI-generated code patterns.

        Returns:
            {"path": str, "score": float, "indicators": list, "lines": int, "is_ai_generated": bool}
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except (IOError, OSError):
            return {"path": file_path, "score": 0, "indicators": [], "lines": 0, "is_ai_generated": False}

        lines = content.split("\n")
        if len(lines) < MIN_LINES_FOR_ANALYSIS:
            return {
                "path": os.path.relpath(file_path, base_path) if base_path else file_path,
                "score": 0,
                "indicators": [],
                "lines": len(lines),
                "is_ai_generated": False,
            }

        indicators = []
        score = 0.0

        # Check for explicit AI generation comments (strongest signal)
        for pattern in _AI_COMMENT_PATTERNS:
            if pattern.search(content):
                indicators.append("explicit_ai_comment")
                score += 0.5  # Very strong signal
                break

        # Check for AI-style naming patterns
        ai_names = 0
        for pattern in _AI_NAMING_PATTERNS:
            ai_names += len(pattern.findall(content))
        if ai_names >= 3:
            indicators.append(f"ai_naming_patterns ({ai_names} matches)")
            score += min(0.2, ai_names * 0.05)

        # Check for AI-style documentation
        doc_matches = 0
        for pattern in _AI_DOC_PATTERNS:
            doc_matches += len(pattern.findall(content))
        if doc_matches >= 2:
            indicators.append(f"ai_documentation_style ({doc_matches} matches)")
            score += min(0.15, doc_matches * 0.05)

        # Check for structural patterns
        struct_matches = 0
        for pattern in _AI_STRUCTURE_PATTERNS:
            struct_matches += len(pattern.findall(content))
        if struct_matches >= 3:
            indicators.append(f"ai_structural_patterns ({struct_matches} matches)")
            score += min(0.15, struct_matches * 0.04)

        # Check comment-to-code ratio (AI tends to over-comment)
        comment_lines = sum(1 for line in lines if line.strip().startswith(("#", "//", "*", "/*")))
        code_lines = sum(1 for line in lines if line.strip() and not line.strip().startswith(("#", "//", "*", "/*")))
        if code_lines > 0:
            comment_ratio = comment_lines / code_lines
            if comment_ratio > 0.4:
                indicators.append(f"high_comment_ratio ({comment_ratio:.2f})")
                score += 0.1

        # Check for uniform line lengths (AI tends to be consistent)
        non_empty = [len(line) for line in lines if line.strip()]
        if len(non_empty) > 20:
            avg_len = sum(non_empty) / len(non_empty)
            variance = sum((l - avg_len) ** 2 for l in non_empty) / len(non_empty)
            std_dev = variance ** 0.5
            cv = std_dev / avg_len if avg_len > 0 else 1
            if cv < 0.35:  # Very uniform line lengths
                indicators.append(f"uniform_line_length (cv={cv:.2f})")
                score += 0.1

        # Check for repetitive function signatures
        func_pattern = re.compile(r"(?:def|function|func|fn)\s+\w+\s*\(")
        functions = func_pattern.findall(content)
        if len(functions) >= 5:
            # Check if function parameter counts are very similar
            param_pattern = re.compile(r"(?:def|function|func|fn)\s+\w+\s*\(([^)]*)\)")
            params = param_pattern.findall(content)
            param_counts = [len(p.split(",")) if p.strip() else 0 for p in params]
            if param_counts:
                avg_params = sum(param_counts) / len(param_counts)
                if all(abs(p - avg_params) <= 1 for p in param_counts) and len(param_counts) >= 5:
                    indicators.append("uniform_function_signatures")
                    score += 0.1

        rel_path = os.path.relpath(file_path, base_path) if base_path else file_path
        return {
            "path": rel_path,
            "score": min(1.0, round(score, 2)),
            "indicators": indicators,
            "lines": len(lines),
            "is_ai_generated": score >= self.threshold,
        }

    @staticmethod
    def adjust_confidence_for_ai_code(
        findings: list[dict],
        ai_files: set[str],
        stricter_threshold: float = 0.85,
    ) -> list[dict]:
        """Apply stricter confidence thresholds to findings in AI-generated files.

        AI-generated code is 2.74x more likely to have XSS and other vulnerabilities,
        so we apply stricter scrutiny: only raise confidence threshold for findings
        in AI-generated files (not lower it).

        Args:
            findings: List of finding dicts
            ai_files: Set of file paths identified as AI-generated
            stricter_threshold: Higher confidence threshold for AI-generated code

        Returns:
            Modified findings list with adjusted confidence metadata
        """
        for f in findings:
            file_path = f.get("file_path", "")
            if file_path in ai_files or any(file_path.endswith(af) for af in ai_files):
                ai_info = f.get("ai_analysis", {})
                if not isinstance(ai_info, dict):
                    ai_info = {}
                ai_info["in_ai_generated_file"] = True
                ai_info["enhanced_scrutiny"] = True
                f["ai_analysis"] = ai_info

                # Don't filter these out — they need MORE attention, not less
                # Just add metadata for the UI to highlight

        return findings
