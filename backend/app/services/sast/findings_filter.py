"""Multi-stage false positive filtering for security findings.

Stage 1: Hard exclusion rules — pattern-based immediate filtering.
Stage 2: Comment-based suppression detection (@navigator-ignore, # nosec, // NOSONAR).
Stage 3: Org-level custom exclusion patterns.
Stage 4: Fingerprint-based auto-suppression (previously-marked false positives).
Stage 5: Smart confidence scoring — Claude re-evaluation per finding.
"""
import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# ── Inline Suppression Patterns ──────────────────────────────────────
# Comment-based suppression markers recognized across languages
SUPPRESSION_MARKERS = [
    # Navigator native
    re.compile(r"@navigator-ignore(?:\s+(?P<cwe>CWE-\d+))?(?:\s+(?P<reason>.+))?", re.IGNORECASE),
    re.compile(r"#\s*navigator-ignore(?:\s+(?P<cwe>CWE-\d+))?(?:\s+(?P<reason>.+))?", re.IGNORECASE),
    re.compile(r"//\s*navigator-ignore(?:\s+(?P<cwe>CWE-\d+))?(?:\s+(?P<reason>.+))?", re.IGNORECASE),
    # Bandit / safety
    re.compile(r"#\s*nosec(?:\s+(?P<cwe>B\d+))?(?:\s+(?P<reason>.+))?", re.IGNORECASE),
    # SonarQube
    re.compile(r"//\s*NOSONAR(?:\s+(?P<reason>.+))?", re.IGNORECASE),
    # Semgrep
    re.compile(r"#\s*nosemgrep(?::(?P<cwe>[a-zA-Z0-9._-]+))?(?:\s+(?P<reason>.+))?", re.IGNORECASE),
    re.compile(r"//\s*nosemgrep(?::(?P<cwe>[a-zA-Z0-9._-]+))?(?:\s+(?P<reason>.+))?", re.IGNORECASE),
    # ESLint
    re.compile(r"//\s*eslint-disable(?:-next)?-line(?:\s+(?P<cwe>[a-zA-Z0-9/_-]+))?", re.IGNORECASE),
    # Checkmarx
    re.compile(r"//\s*checkmarx-ignore", re.IGNORECASE),
    # Snyk
    re.compile(r"#\s*snyk-ignore", re.IGNORECASE),
]


@dataclass
class FilterStats:
    """Track filtering statistics for transparency."""
    total_input: int = 0
    hard_excluded: int = 0
    comment_suppressed: int = 0
    org_pattern_excluded: int = 0
    fingerprint_suppressed: int = 0
    smart_filtered: int = 0
    passed: int = 0
    exclusion_reasons: dict = field(default_factory=dict)
    suppression_details: list = field(default_factory=list)


# Patterns that almost always produce false positives in code review
_HARD_EXCLUSION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("dos_generic", re.compile(
        r"(?:denial.of.service|rate.limit|timeout|resource.exhaustion)",
        re.IGNORECASE,
    )),
    ("unclosed_resource", re.compile(
        r"unclosed\s+(?:file|stream|connection|socket|cursor|handle)",
        re.IGNORECASE,
    )),
    ("missing_logging_generic", re.compile(
        r"(?:missing|no|absent)\s+(?:logging|audit.trail|log.entry).*(?:generic|informational)",
        re.IGNORECASE,
    )),
    ("test_file", re.compile(
        r"(?:test_|_test\.|\.test\.|\.spec\.|__tests__|/tests?/|/fixtures?/|mock|stub)",
        re.IGNORECASE,
    )),
    ("documentation_file", re.compile(
        r"(?:\.md$|\.rst$|\.txt$|README|CHANGELOG|LICENSE|CONTRIBUTING)",
        re.IGNORECASE,
    )),
    ("example_sample", re.compile(
        r"(?:/examples?/|/samples?/|/demo/|/tutorial/)",
        re.IGNORECASE,
    )),
    ("vendor_dependency", re.compile(
        r"(?:/node_modules/|/vendor/|/dist/|/build/|\.min\.js$)",
        re.IGNORECASE,
    )),
]

# Severity-based title patterns for hard exclusion
_LOW_VALUE_TITLES: list[re.Pattern] = [
    re.compile(r"(?:TODO|FIXME|HACK)\s+in\s+code", re.IGNORECASE),
    re.compile(r"unused\s+(?:import|variable|parameter|function)", re.IGNORECASE),
    re.compile(r"inconsistent\s+(?:naming|indentation|style)", re.IGNORECASE),
    re.compile(r"missing\s+(?:docstring|type.hint|annotation)", re.IGNORECASE),
]


class HardExclusionRules:
    """Stage 1: Pattern-based immediate filtering."""

    @staticmethod
    def should_exclude(finding: dict) -> tuple[bool, str]:
        """Check if a finding should be excluded by hard rules.

        Returns (should_exclude, reason).
        """
        file_path = finding.get("file_path", "")
        title = finding.get("title", "")
        description = finding.get("description", "")
        severity = finding.get("severity", "medium")
        confidence_val = finding.get("confidence", "medium")

        combined_text = f"{title} {description} {file_path}"

        for reason_key, pattern in _HARD_EXCLUSION_PATTERNS:
            target = file_path if reason_key in ("test_file", "documentation_file",
                                                   "example_sample", "vendor_dependency") else combined_text
            if pattern.search(target):
                return True, reason_key

        for pattern in _LOW_VALUE_TITLES:
            if pattern.search(title):
                return True, "low_value_title"

        if severity == "info" and confidence_val == "low":
            return True, "info_low_confidence"

        return False, ""


class SmartFilter:
    """Stage 2: Confidence-based re-evaluation.

    Uses Claude to re-evaluate findings that pass hard exclusion,
    filtering those below the confidence threshold.
    """

    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold

    def filter_by_confidence(self, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        """Split findings into passed and filtered based on AI confidence.

        Returns (passed, filtered).
        """
        passed = []
        filtered = []

        for f in findings:
            ai = f.get("ai_analysis", {})
            if isinstance(ai, dict):
                conf = ai.get("confidence", 0.7)
                if isinstance(conf, str):
                    conf = {"high": 0.9, "medium": 0.7, "low": 0.4}.get(conf, 0.7)
                if ai.get("is_false_positive", False):
                    filtered.append(f)
                    continue
                if conf < self.threshold:
                    filtered.append(f)
                    continue
            passed.append(f)

        return passed, filtered


class CommentSuppressionDetector:
    """Stage 2: Detect inline comment-based suppressions in source code.

    Scans code around finding locations for suppression markers like
    @navigator-ignore, # nosec, // NOSONAR, etc.
    """

    @staticmethod
    def check_suppression(finding: dict, source_lines: list[str] | None = None) -> tuple[bool, dict]:
        """Check if a finding is suppressed by an inline comment.

        Args:
            finding: The finding dict
            source_lines: Optional pre-loaded source lines (for batch processing)

        Returns:
            (is_suppressed, suppression_info)
        """
        file_path = finding.get("file_path", "")
        line_start = finding.get("line_start", 0)
        code_snippet = finding.get("code_snippet", "")
        cwe_id = finding.get("cwe_id", "")

        # Try to load source lines if not provided
        lines_to_check = []
        if source_lines and 0 < line_start <= len(source_lines):
            # Check the line itself, line above, and line below
            start = max(0, line_start - 2)
            end = min(len(source_lines), line_start + 1)
            lines_to_check = source_lines[start:end]
        elif code_snippet:
            lines_to_check = code_snippet.split("\n")

        for line in lines_to_check:
            for marker in SUPPRESSION_MARKERS:
                match = marker.search(line)
                if match:
                    groups = match.groupdict()
                    marker_cwe = groups.get("cwe", "")
                    reason = groups.get("reason", "").strip() if groups.get("reason") else ""

                    # If the marker specifies a CWE, only suppress if it matches
                    if marker_cwe and cwe_id:
                        if marker_cwe.upper() != cwe_id.upper() and marker_cwe not in finding.get("rule_id", ""):
                            continue

                    return True, {
                        "marker": marker.pattern,
                        "matched_line": line.strip(),
                        "cwe_filter": marker_cwe,
                        "reason": reason,
                        "file_path": file_path,
                        "line": line_start,
                    }

        return False, {}

    @staticmethod
    def scan_file_suppressions(file_path: str) -> list[dict]:
        """Scan an entire file for suppression comments and return their locations."""
        suppressions = []
        try:
            with open(file_path, "r", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    for marker in SUPPRESSION_MARKERS:
                        match = marker.search(line)
                        if match:
                            groups = match.groupdict()
                            suppressions.append({
                                "line": line_num,
                                "marker": match.group(0).strip(),
                                "cwe_filter": groups.get("cwe", ""),
                                "reason": (groups.get("reason", "") or "").strip(),
                            })
        except (IOError, OSError):
            pass
        return suppressions


class OrgPatternExcluder:
    """Stage 3: Org-level custom exclusion patterns.

    Applies organization-specific exclusion rules stored in the org settings.
    Patterns can match on: file_path, rule_id, title, description, severity.
    """

    def __init__(self, exclusion_patterns: list[dict] | None = None):
        """Initialize with org exclusion patterns.

        Each pattern dict can have:
        - file_pattern: regex for file_path matching
        - rule_pattern: regex for rule_id matching
        - title_pattern: regex for title matching
        - severity_below: exclude findings below this severity
        - category: specific category to exclude
        """
        self.patterns = exclusion_patterns or []
        self._compiled = []
        for p in self.patterns:
            compiled = {}
            for key in ("file_pattern", "rule_pattern", "title_pattern"):
                if p.get(key):
                    try:
                        compiled[key] = re.compile(p[key], re.IGNORECASE)
                    except re.error:
                        logger.warning("Invalid org exclusion pattern: %s = %s", key, p[key])
            compiled["severity_below"] = p.get("severity_below")
            compiled["category"] = p.get("category")
            compiled["reason"] = p.get("reason", "org_custom_exclusion")
            self._compiled.append(compiled)

    def should_exclude(self, finding: dict) -> tuple[bool, str]:
        """Check if a finding matches any org exclusion pattern."""
        severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

        for pattern in self._compiled:
            match = True

            if "file_pattern" in pattern:
                if not pattern["file_pattern"].search(finding.get("file_path", "")):
                    match = False
            if "rule_pattern" in pattern and match:
                if not pattern["rule_pattern"].search(finding.get("rule_id", "")):
                    match = False
            if "title_pattern" in pattern and match:
                if not pattern["title_pattern"].search(finding.get("title", "")):
                    match = False
            if pattern.get("severity_below") and match:
                threshold = severity_order.get(pattern["severity_below"], 3)
                finding_sev = severity_order.get(finding.get("severity", "medium"), 3)
                if finding_sev >= threshold:
                    match = False
            if pattern.get("category") and match:
                if pattern["category"].lower() not in finding.get("rule_id", "").lower():
                    match = False

            if match and any(k in pattern for k in ("file_pattern", "rule_pattern", "title_pattern",
                                                       "severity_below", "category")):
                return True, pattern.get("reason", "org_custom_exclusion")

        return False, ""


class FingerprintAutoSuppressor:
    """Stage 4: Auto-suppress findings matching previously-confirmed false positives.

    Uses finding fingerprints to automatically suppress findings that have been
    previously marked as false_positive by users.
    """

    def __init__(self, known_fp_fingerprints: set[str] | None = None):
        """Initialize with known false positive fingerprints.

        Args:
            known_fp_fingerprints: Set of fingerprint hashes from previously
                                   marked false positive findings.
        """
        self.known_fps = known_fp_fingerprints or set()

    def is_auto_suppressed(self, finding: dict) -> bool:
        """Check if a finding matches a known false positive fingerprint."""
        fp = finding.get("fingerprint", "")
        if fp and fp in self.known_fps:
            return True

        # Also check semantic fingerprint (file + line range + rule category)
        semantic_fp = self._compute_semantic_fingerprint(finding)
        return semantic_fp in self.known_fps

    @staticmethod
    def _compute_semantic_fingerprint(finding: dict) -> str:
        """Compute a semantic fingerprint for fuzzy matching.

        Based on: file_path + rule_category + severity (ignoring exact line).
        This catches the same issue even if lines shifted slightly.
        """
        parts = finding.get("rule_id", "").split(".")
        category = parts[2] if len(parts) > 2 else parts[0] if parts else "unknown"
        raw = f"{finding.get('file_path', '')}:{category}:{finding.get('severity', '')}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    async def load_known_fps(project_id: str) -> set[str]:
        """Load known false positive fingerprints from database.

        Queries SastFinding for findings marked as false_positive/wont_fix
        and returns their fingerprints.
        """
        fps = set()
        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastFinding
            from sqlalchemy import select
            import uuid as _uuid

            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(SastFinding.fingerprint).where(
                        SastFinding.project_id == _uuid.UUID(project_id),
                        SastFinding.status.in_(["false_positive", "wont_fix", "ignored"]),
                        SastFinding.fingerprint.isnot(None),
                    )
                )
                for row in result:
                    if row[0]:
                        fps.add(row[0])
        except Exception as e:
            logger.debug("Failed to load known FPs: %s", e)
        return fps


class SuppressionAuditTrail:
    """Tracks suppression decisions for audit and compliance purposes."""

    @staticmethod
    async def record_suppression(
        finding_id: str,
        suppression_type: str,
        reason: str,
        suppressed_by: str | None = None,
        expires_at: datetime | None = None,
    ) -> dict:
        """Record a suppression decision in the audit trail.

        Args:
            finding_id: UUID of the finding being suppressed
            suppression_type: One of: comment_based, org_pattern, fingerprint_auto, manual
            reason: Human-readable reason for suppression
            suppressed_by: User ID who suppressed (None for automatic)
            expires_at: Optional expiry date for the suppression
        """
        record = {
            "finding_id": finding_id,
            "suppression_type": suppression_type,
            "reason": reason,
            "suppressed_by": suppressed_by,
            "suppressed_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at.isoformat() if expires_at else None,
        }

        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastFinding
            from sqlalchemy import select
            import uuid as _uuid

            async with AsyncSessionLocal() as db:
                finding = (await db.execute(
                    select(SastFinding).where(SastFinding.id == _uuid.UUID(finding_id))
                )).scalar_one_or_none()
                if finding:
                    # Store suppression info in ai_analysis field
                    ai = finding.ai_analysis or {}
                    if not isinstance(ai, dict):
                        ai = {}
                    suppression_history = ai.get("suppression_history", [])
                    suppression_history.append(record)
                    ai["suppression_history"] = suppression_history
                    ai["is_suppressed"] = True
                    ai["suppression_type"] = suppression_type
                    finding.ai_analysis = ai
                    await db.commit()
        except Exception as e:
            logger.debug("Failed to record suppression: %s", e)

        return record


def apply_filters(
    findings: list[dict],
    confidence_threshold: float = 0.7,
    skip_hard_exclusion: bool = False,
    org_exclusion_patterns: list[dict] | None = None,
    known_fp_fingerprints: set[str] | None = None,
    source_lines_cache: dict[str, list[str]] | None = None,
) -> tuple[list[dict], FilterStats]:
    """Apply all filtering stages to a list of findings.

    Stages:
    1. Hard exclusion rules (pattern-based)
    2. Comment-based suppression detection
    3. Org-level custom exclusion patterns
    4. Fingerprint-based auto-suppression
    5. Smart confidence scoring

    Returns (filtered_findings, stats).
    """
    stats = FilterStats(total_input=len(findings))
    source_cache = source_lines_cache or {}

    # Stage 1: Hard exclusion
    stage1_passed = []
    if skip_hard_exclusion:
        stage1_passed = findings
    else:
        for f in findings:
            excluded, reason = HardExclusionRules.should_exclude(f)
            if excluded:
                stats.hard_excluded += 1
                stats.exclusion_reasons[reason] = stats.exclusion_reasons.get(reason, 0) + 1
            else:
                stage1_passed.append(f)

    # Stage 2: Comment-based suppression
    stage2_passed = []
    detector = CommentSuppressionDetector()
    for f in stage1_passed:
        file_path = f.get("file_path", "")
        src_lines = source_cache.get(file_path)
        suppressed, info = detector.check_suppression(f, src_lines)
        if suppressed:
            stats.comment_suppressed += 1
            stats.suppression_details.append({
                "type": "comment",
                "finding_title": f.get("title", ""),
                **info,
            })
            f["_suppressed"] = True
            f["_suppression_type"] = "comment_based"
            f["_suppression_reason"] = info.get("reason", "inline comment suppression")
        else:
            stage2_passed.append(f)

    # Stage 3: Org-level custom exclusion patterns
    stage3_passed = []
    if org_exclusion_patterns:
        org_excluder = OrgPatternExcluder(org_exclusion_patterns)
        for f in stage2_passed:
            excluded, reason = org_excluder.should_exclude(f)
            if excluded:
                stats.org_pattern_excluded += 1
                stats.exclusion_reasons[f"org:{reason}"] = stats.exclusion_reasons.get(f"org:{reason}", 0) + 1
            else:
                stage3_passed.append(f)
    else:
        stage3_passed = stage2_passed

    # Stage 4: Fingerprint auto-suppression
    stage4_passed = []
    if known_fp_fingerprints:
        fp_suppressor = FingerprintAutoSuppressor(known_fp_fingerprints)
        for f in stage3_passed:
            if fp_suppressor.is_auto_suppressed(f):
                stats.fingerprint_suppressed += 1
                f["_suppressed"] = True
                f["_suppression_type"] = "fingerprint_auto"
                f["_suppression_reason"] = "Matches previously-confirmed false positive"
            else:
                stage4_passed.append(f)
    else:
        stage4_passed = stage3_passed

    # Stage 5: Smart confidence scoring
    smart = SmartFilter(threshold=confidence_threshold)
    passed, smart_filtered = smart.filter_by_confidence(stage4_passed)
    stats.smart_filtered = len(smart_filtered)
    stats.passed = len(passed)

    logger.info(
        "Finding filter: %d input → %d hard-excluded, %d comment-suppressed, "
        "%d org-excluded, %d fp-auto-suppressed, %d smart-filtered → %d passed",
        stats.total_input, stats.hard_excluded, stats.comment_suppressed,
        stats.org_pattern_excluded, stats.fingerprint_suppressed,
        stats.smart_filtered, stats.passed,
    )
    return passed, stats
