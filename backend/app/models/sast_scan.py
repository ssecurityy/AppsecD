"""SAST (Static Application Security Testing) models."""
from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer, Float, ForeignKey, Numeric
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
import uuid
from app.core.database import Base


class SastScanSession(Base):
    """Tracks a SAST scan session — ZIP upload, repo scan, or CI/CD trigger."""
    __tablename__ = "sast_scan_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)

    # Source type: zip_upload, github, gitlab, bitbucket, cicd_webhook
    scan_type = Column(String(30), nullable=False, default="zip_upload")
    # queued, extracting, scanning, ai_analyzing, completed, failed, cancelled
    status = Column(String(30), nullable=False, default="queued", index=True)

    # Source metadata
    source_info = Column(JSONB, nullable=True)  # {repo_url, branch, commit_sha, zip_filename, file_size_bytes}

    # Scan results summary
    language_stats = Column(JSONB, nullable=True)  # {python: 1200, javascript: 3400, ...}
    total_files = Column(Integer, default=0)
    files_scanned = Column(Integer, default=0)
    total_issues = Column(Integer, default=0)
    issues_by_severity = Column(JSONB, nullable=True)  # {critical: 2, high: 5, ...}
    issues_by_category = Column(JSONB, nullable=True)  # {injection: 3, xss: 2, ...}

    # AI analysis
    ai_analysis_enabled = Column(Boolean, default=False)
    ai_cost_usd = Column(Numeric(10, 2), default=0)
    ai_model_used = Column(String(50), nullable=True)

    # Scan engine stats
    semgrep_rules_used = Column(Integer, default=0)
    custom_rules_used = Column(Integer, default=0)
    secrets_found = Column(Integer, default=0)
    dependency_issues = Column(Integer, default=0)

    # Code Security Platform — extended tracking (028 migration)
    claude_review_enabled = Column(Boolean, server_default="false")
    claude_review_cost_usd = Column(Numeric(10, 2), server_default="0")
    claude_review_findings_count = Column(Integer, server_default="0")
    sca_issues = Column(Integer, server_default="0")
    iac_issues = Column(Integer, server_default="0")
    container_issues = Column(Integer, server_default="0")
    js_deep_issues = Column(Integer, server_default="0")
    license_issues = Column(Integer, server_default="0")

    # Timing
    scan_duration_seconds = Column(Float, nullable=True)

    # Configuration used
    scan_config = Column(JSONB, nullable=True)  # {languages, severity_filter, rule_sets, exclude_patterns}

    # Error info
    error_message = Column(Text, nullable=True)

    # Full SARIF output for export
    sarif_output = Column(JSONB, nullable=True)

    # Policy evaluation result
    policy_result = Column(JSONB, nullable=True)  # {passed: bool, policy_name, violations[]}

    created_by = Column(UUID(as_uuid=True), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)


class SastFinding(Base):
    """Individual code vulnerability found during SAST scan."""
    __tablename__ = "sast_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_session_id = Column(UUID(as_uuid=True), ForeignKey("sast_scan_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    # Rule info
    rule_id = Column(String(255), nullable=False)  # e.g. "python.security.injection.sql-injection"
    rule_source = Column(String(30), default="semgrep")  # semgrep, custom, ai, secret_scan

    # Severity & confidence
    severity = Column(String(20), nullable=False, default="medium", index=True)
    confidence = Column(String(20), default="medium")  # high, medium, low

    # Finding details
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    message = Column(Text, nullable=True)  # Semgrep message

    # Code location
    file_path = Column(String(1000), nullable=False)
    line_start = Column(Integer, nullable=False)
    line_end = Column(Integer, nullable=True)
    column_start = Column(Integer, nullable=True)
    column_end = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)  # ~5 lines context

    # Fix suggestions
    fix_suggestion = Column(Text, nullable=True)  # Semgrep autofix or AI suggestion
    fixed_code = Column(Text, nullable=True)  # AI-generated fixed code

    # AI analysis results
    ai_analysis = Column(JSONB, nullable=True)  # {is_false_positive, confidence, explanation, remediation}

    # Standards mapping
    cwe_id = Column(String(20), nullable=True)
    owasp_category = Column(String(255), nullable=True)
    references = Column(JSONB, nullable=True)  # [urls]

    # Dedup
    fingerprint = Column(String(64), nullable=True, index=True)

    # Status: open, confirmed, false_positive, fixed, ignored, wont_fix, in_progress
    status = Column(String(30), default="open", index=True)

    # Lifecycle management (029 migration)
    assigned_to = Column(UUID(as_uuid=True), nullable=True, index=True)
    sla_deadline = Column(DateTime, nullable=True, index=True)
    exception_approved_by = Column(UUID(as_uuid=True), nullable=True)
    exception_expires_at = Column(DateTime, nullable=True)
    status_history = Column(JSONB, nullable=True)  # [{status, changed_by, changed_at, reason}]

    # Reachability & suppression (029 migration)
    is_reachable = Column(Boolean, server_default="true", nullable=True)
    is_suppressed = Column(Boolean, server_default="false", nullable=True)
    suppression_reason = Column(Text, nullable=True)
    suppression_type = Column(String(30), nullable=True)  # comment_based, org_pattern, fingerprint_auto, manual

    created_at = Column(DateTime, default=datetime.utcnow)


class SastCustomRule(Base):
    """Organization-defined custom Semgrep rules."""
    __tablename__ = "sast_custom_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    rule_yaml = Column(Text, nullable=False)
    is_active = Column(Boolean, server_default="true", nullable=False)
    created_by = Column(UUID(as_uuid=True), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SastTrendSnapshot(Base):
    """Historical scan metrics for trend analysis."""
    __tablename__ = "sast_trend_snapshots"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_session_id = Column(UUID(as_uuid=True), ForeignKey("sast_scan_sessions.id", ondelete="CASCADE"), nullable=True)
    total_issues = Column(Integer, server_default="0")
    new_issues = Column(Integer, server_default="0")
    fixed_issues = Column(Integer, server_default="0")
    issues_by_severity = Column(JSONB, nullable=True)
    issues_by_scanner = Column(JSONB, nullable=True)
    mttr_hours = Column(Float, nullable=True)
    fix_rate_pct = Column(Float, nullable=True)
    issues_per_kloc = Column(Float, nullable=True)
    metrics = Column(JSONB, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class SastSupplyChainAlert(Base):
    """Supply chain security alert (typosquatting, malicious package, dependency confusion)."""
    __tablename__ = "sast_supply_chain_alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_session_id = Column(UUID(as_uuid=True), ForeignKey("sast_scan_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_type = Column(String(50), nullable=False)  # typosquatting, malicious, dependency_confusion
    package_name = Column(String(500), nullable=False)
    package_version = Column(String(100), nullable=True)
    ecosystem = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text, nullable=True)
    similar_to = Column(String(500), nullable=True)  # For typosquatting: the legitimate package
    evidence = Column(JSONB, nullable=True)
    status = Column(String(30), server_default="open")
    created_at = Column(DateTime, default=datetime.utcnow)


class SastRepository(Base):
    """Connected source code repository for SAST scanning."""
    __tablename__ = "sast_repositories"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)

    # Provider: github, gitlab, bitbucket
    provider = Column(String(30), nullable=False, default="github")
    repo_url = Column(String(500), nullable=False)
    repo_name = Column(String(255), nullable=False)
    repo_owner = Column(String(255), nullable=True)
    default_branch = Column(String(100), default="main")

    # Auth (encrypted PAT)
    access_token_encrypted = Column(Text, nullable=True)

    # Webhook
    webhook_id = Column(String(100), nullable=True)
    webhook_secret = Column(String(64), nullable=True)

    # Scanning config
    last_scan_at = Column(DateTime, nullable=True)
    auto_scan_enabled = Column(Boolean, default=False)
    auto_scan_branches = Column(JSONB, nullable=True, server_default='["main"]')
    scan_config = Column(JSONB, nullable=True)  # {languages, severity_filter, exclude_patterns}

    created_by = Column(UUID(as_uuid=True), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class SastPolicy(Base):
    """Scanning policy for build gating and compliance."""
    __tablename__ = "sast_policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)

    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    is_default = Column(Boolean, default=False)

    # Thresholds
    severity_threshold = Column(String(20), default="critical")  # Block build if this severity found
    max_issues_allowed = Column(Integer, default=-1)  # -1 = unlimited
    fail_on_secrets = Column(Boolean, default=True)

    # Category enforcement
    required_fix_categories = Column(JSONB, nullable=True)  # ["injection", "auth"]
    exclude_rules = Column(JSONB, nullable=True)  # Rule IDs to ignore

    # Compliance
    compliance_standards = Column(JSONB, nullable=True)  # ["owasp-top-10", "pci-dss", "soc2"]

    # Code Security Platform — extended policy fields (028 migration)
    fail_on_sca_critical = Column(Boolean, server_default="true")
    fail_on_kev = Column(Boolean, server_default="true")
    max_dependency_issues = Column(Integer, server_default="-1")
    blocked_licenses = Column(JSONB, nullable=True)
    fail_on_iac_critical = Column(Boolean, server_default="true")
    fail_on_container_critical = Column(Boolean, server_default="true")

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SastDependency(Base):
    """Dependency record from SCA scanning."""
    __tablename__ = "sast_dependencies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_session_id = Column(UUID(as_uuid=True), ForeignKey("sast_scan_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    name = Column(String(500), nullable=False)
    version = Column(String(100), nullable=True)
    ecosystem = Column(String(50), nullable=False)
    manifest_file = Column(String(500), nullable=True)
    latest_version = Column(String(100), nullable=True)
    is_outdated = Column(Boolean, server_default="false")
    is_direct = Column(Boolean, server_default="true")
    license_id = Column(String(100), nullable=True)
    license_risk = Column(String(20), nullable=True)
    vulnerabilities = Column(JSONB, nullable=True)
    epss_score = Column(Float, nullable=True)
    in_kev = Column(Boolean, server_default="false")
    cvss_score = Column(Float, nullable=True)
    fingerprint = Column(String(64), nullable=True, index=True)
    status = Column(String(30), server_default="open")
    created_at = Column(DateTime, default=datetime.utcnow)


class SastSuppressionRule(Base):
    """Org or project-level suppression rule (fingerprint, rule_id, file_pattern, cwe)."""
    __tablename__ = "sast_suppression_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True)
    rule_type = Column(String(30), nullable=False)
    pattern = Column(String(500), nullable=False)
    reason = Column(String(500), nullable=True)
    justification = Column(Text, nullable=True)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, server_default="true", nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class SastDataflowPath(Base):
    """Taint/dataflow path from source to sink for a finding (Claude AI–powered)."""
    __tablename__ = "sast_dataflow_paths"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_session_id = Column(UUID(as_uuid=True), ForeignKey("sast_scan_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("sast_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    source_file = Column(String(500), nullable=True)
    source_line = Column(Integer, nullable=True)
    source_type = Column(String(100), nullable=True)
    sink_file = Column(String(500), nullable=True)
    sink_line = Column(Integer, nullable=True)
    sink_type = Column(String(100), nullable=True)
    path_nodes = Column(JSONB, nullable=True)
    confidence = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class SastSBOM(Base):
    """Stored SBOM from a scan session."""
    __tablename__ = "sast_sboms"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_session_id = Column(UUID(as_uuid=True), ForeignKey("sast_scan_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    format = Column(String(20), nullable=False)
    spec_version = Column(String(20), nullable=False)
    component_count = Column(Integer, server_default="0")
    total_dependencies = Column(Integer, server_default="0")
    sbom_data = Column(JSONB, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class DastSchedule(Base):
    """Recurring DAST scan schedule."""
    __tablename__ = "dast_schedules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, unique=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    cron_expression = Column(String(100), nullable=False)
    scan_config = Column(JSONB, nullable=True)
    is_active = Column(Boolean, server_default="true")
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    created_by = Column(UUID(as_uuid=True), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DastBaseline(Base):
    """Baseline snapshot for DAST trend analysis."""
    __tablename__ = "dast_baselines"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_session_id = Column(String(100), nullable=True)
    total_findings = Column(Integer, server_default="0")
    findings_by_severity = Column(JSONB, nullable=True)
    findings_snapshot = Column(JSONB, nullable=True)
    new_findings = Column(Integer, server_default="0")
    fixed_findings = Column(Integer, server_default="0")
    unchanged_findings = Column(Integer, server_default="0")
    created_at = Column(DateTime, default=datetime.utcnow)
