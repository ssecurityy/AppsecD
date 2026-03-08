"""SAST scan orchestrator — coordinates full scan pipeline."""
import json
import logging
import os
import time
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)


async def _get_org_flags(organization_id: str) -> dict:
    """Load org-level feature flags for conditional phase execution."""
    from app.core.database import AsyncSessionLocal
    from app.models.organization import Organization
    from sqlalchemy import select
    flags = {}
    try:
        async with AsyncSessionLocal() as db:
            org = (await db.execute(
                select(Organization).where(Organization.id == uuid.UUID(organization_id))
            )).scalar_one_or_none()
            if org:
                flags = {
                    "sast_sca_enabled": getattr(org, "sast_sca_enabled", True),
                    "sast_iac_scanning_enabled": getattr(org, "sast_iac_scanning_enabled", True),
                    "sast_claude_review_enabled": getattr(org, "sast_claude_review_enabled", True),
                    "sast_pr_review_enabled": getattr(org, "sast_pr_review_enabled", True),
                    "sast_blocked_licenses": getattr(org, "sast_blocked_licenses", None),
                    "sast_custom_instructions": getattr(org, "sast_custom_instructions", ""),
                }
    except Exception as e:
        logger.debug("Failed to load org flags: %s", e)
    return flags

# Redis key prefix for progress tracking
SAST_PROGRESS_PREFIX = "sast_progress_"


def _progress_set(scan_id: str, data: dict) -> None:
    """Store progress in Redis."""
    try:
        import redis
        from app.core.config import get_settings
        settings = get_settings()
        r = redis.from_url(settings.redis_url)
        r.setex(f"{SAST_PROGRESS_PREFIX}{scan_id}", 3600, json.dumps(data, default=str))
    except Exception as e:
        logger.debug("Redis progress set failed: %s", e)


def _progress_get(scan_id: str) -> dict | None:
    """Get progress from Redis."""
    try:
        import redis
        from app.core.config import get_settings
        settings = get_settings()
        r = redis.from_url(settings.redis_url)
        data = r.get(f"{SAST_PROGRESS_PREFIX}{scan_id}")
        return json.loads(data) if data else None
    except Exception:
        return None


def _progress_is_stopped(scan_id: str) -> bool:
    """Return True when a scan was marked as stopped/cancelled by the API."""
    data = _progress_get(scan_id) or {}
    return data.get("status") in {"stopped", "cancelled"}


async def run_sast_scan(
    scan_session_id: str,
    project_id: str,
    organization_id: str,
    source_path: str,
    scan_config: dict | None = None,
    ai_analysis_enabled: bool = False,
    api_key: str = "",
    user_id: str | None = None,
) -> dict:
    """Execute full SAST scan pipeline.

    Pipeline: language detect → semgrep scan → secret scan → AI analysis → store results

    Args:
        scan_session_id: UUID of SastScanSession
        project_id: UUID of Project
        organization_id: UUID of Organization
        source_path: Path to extracted source code
        scan_config: Optional config overrides
        ai_analysis_enabled: Whether to run AI analysis
        api_key: Anthropic API key for AI analysis
        user_id: User who initiated the scan
    """
    from app.core.database import AsyncSessionLocal
    from app.models.sast_scan import SastScanSession, SastFinding
    from sqlalchemy import select

    config = scan_config or {}
    start_time = time.time()
    scan_id = scan_session_id

    _progress_set(scan_id, {
        "status": "extracting",
        "phase": "language_detection",
        "message": "Detecting languages...",
        "files_scanned": 0,
        "total_files": 0,
        "issues_found": 0,
    })

    # ── Phase 1: Language Detection ────────────────────────────────
    from .code_extractor import detect_languages, list_scannable_files

    language_stats = detect_languages(source_path)
    scannable_files = list_scannable_files(source_path)
    total_files = len(scannable_files)
    detected_languages = list(language_stats.keys())

    logger.info("SAST scan %s: %d files, languages: %s", scan_id, total_files, detected_languages)

    # ── Load org-level feature flags ─────────────────────────────────
    org_flags = await _get_org_flags(organization_id)
    logger.debug("Org flags for %s: %s", organization_id, org_flags)

    if _progress_is_stopped(scan_id):
        return await _finalize_stopped_scan(
            scan_session_id=scan_session_id,
            scan_id=scan_id,
            source_path=source_path,
            total_files=total_files,
            detected_languages=detected_languages,
        )

    _progress_set(scan_id, {
        "status": "scanning",
        "phase": "semgrep_scan",
        "message": f"Running Semgrep on {total_files} files...",
        "files_scanned": 0,
        "total_files": total_files,
        "issues_found": 0,
        "languages": detected_languages,
    })

    # ── Phase 2: Semgrep Scan ──────────────────────────────────────
    from .semgrep_runner import run_semgrep, check_semgrep_installed

    semgrep_findings = []
    semgrep_rules_used = 0
    semgrep_errors = []

    # Exhaustive/max-coverage: add extra rulesets (secure-defaults, r2c-security-audit)
    rule_sets = list(config.get("rule_sets") or [])
    if config.get("exhaustive") or config.get("max_coverage"):
        for extra in ("secure-defaults", "r2c-security-audit"):
            if extra not in rule_sets:
                rule_sets.append(extra)

    if check_semgrep_installed():
        semgrep_result = run_semgrep(
            source_dir=source_path,
            languages=config.get("languages") or detected_languages,
            rule_sets=rule_sets if rule_sets else None,
            exclude_patterns=config.get("exclude_patterns"),
        )
        semgrep_findings = semgrep_result.get("findings", [])
        semgrep_rules_used = semgrep_result.get("rules_used", 0)
        semgrep_errors = semgrep_result.get("errors", [])
        logger.info("Semgrep: %d findings, %d rules, %d errors",
                     len(semgrep_findings), semgrep_rules_used, len(semgrep_errors))
    else:
        logger.warning("Semgrep not installed — skipping SAST rules")
        semgrep_errors.append("Semgrep not installed")

    if _progress_is_stopped(scan_id):
        return await _finalize_stopped_scan(
            scan_session_id=scan_session_id,
            scan_id=scan_id,
            source_path=source_path,
            total_files=total_files,
            detected_languages=detected_languages,
        )

    # ── Phase 2.5: IaC Scanning (if IaC files detected) ────────────
    iac_findings = []
    from .code_extractor import detect_iac_files
    iac_files = detect_iac_files(source_path)

    iac_org_enabled = org_flags.get("sast_iac_scanning_enabled", True)
    if iac_files and config.get("iac_scanning_enabled", True) and iac_org_enabled:
        _progress_set(scan_id, {
            "status": "scanning",
            "phase": "iac_scanning",
            "message": f"Scanning IaC files... ({sum(iac_files.values())} files)",
            "files_scanned": total_files,
            "total_files": total_files,
            "issues_found": len(semgrep_findings),
            "languages": detected_languages,
        })
        try:
            from .iac_scanner import scan_iac
            iac_findings = scan_iac(source_path)
            logger.info("IaC scan: %d findings from %s", len(iac_findings), iac_files)
        except Exception as e:
            logger.warning("IaC scan failed: %s", e)

    if _progress_is_stopped(scan_id):
        return await _finalize_stopped_scan(
            scan_session_id=scan_session_id, scan_id=scan_id, source_path=source_path,
            total_files=total_files, detected_languages=detected_languages,
        )

    # ── Phase 2.8: Container Analysis ──────────────────────────────
    container_findings = []
    if iac_files.get("dockerfile") or iac_files.get("docker_compose"):
        _progress_set(scan_id, {
            "status": "scanning",
            "phase": "container_scanning",
            "message": "Scanning container configurations...",
            "files_scanned": total_files,
            "total_files": total_files,
            "issues_found": len(semgrep_findings) + len(iac_findings),
            "languages": detected_languages,
        })
        try:
            from .container_scanner import scan_containers
            container_findings = scan_containers(source_path)
            logger.info("Container scan: %d findings", len(container_findings))
        except Exception as e:
            logger.warning("Container scan failed: %s", e)

    # ── Phase 2.9: JS Deep Analysis (if JS/TS detected) ───────────
    js_deep_findings = []
    if any(lang in detected_languages for lang in ("javascript", "typescript")):
        _progress_set(scan_id, {
            "status": "scanning",
            "phase": "js_analyzing",
            "message": "Deep JS/TS security analysis...",
            "files_scanned": total_files,
            "total_files": total_files,
            "issues_found": len(semgrep_findings) + len(iac_findings) + len(container_findings),
            "languages": detected_languages,
        })
        try:
            from .js_analyzer import scan_javascript
            js_deep_findings = scan_javascript(source_path)
            logger.info("JS deep analysis: %d findings", len(js_deep_findings))
        except Exception as e:
            logger.warning("JS deep analysis failed: %s", e)

    if _progress_is_stopped(scan_id):
        return await _finalize_stopped_scan(
            scan_session_id=scan_session_id, scan_id=scan_id, source_path=source_path,
            total_files=total_files, detected_languages=detected_languages,
        )

    _progress_set(scan_id, {
        "status": "scanning",
        "phase": "secret_scan",
        "message": f"Scanning for secrets... ({len(semgrep_findings)} code issues found)",
        "files_scanned": total_files,
        "total_files": total_files,
        "issues_found": len(semgrep_findings),
        "languages": detected_languages,
    })

    # ── Phase 3: Secret Scan (regex + TruffleHog) ───────────────────
    from .secret_scanner import scan_secrets

    secret_findings = scan_secrets(source_path)
    logger.info("Secret scan (regex): %d findings", len(secret_findings))

    # TruffleHog deep secret scanning
    trufflehog_findings = []
    _progress_set(scan_id, {
        "status": "scanning",
        "phase": "secret_scan",
        "message": f"Running TruffleHog deep secret scan... ({len(secret_findings)} regex hits)",
        "files_scanned": total_files,
        "total_files": total_files,
        "issues_found": len(semgrep_findings) + len(secret_findings),
        "languages": detected_languages,
    })
    try:
        from .secret_scanner import scan_secrets_trufflehog
        trufflehog_findings = scan_secrets_trufflehog(source_path)
        logger.info("TruffleHog scan: %d findings", len(trufflehog_findings))
    except Exception as e:
        logger.warning("TruffleHog scan failed: %s", e)

    # Optional: Gitleaks (fast, 150+ rules) when enabled or exhaustive mode
    gitleaks_findings = []
    if config.get("gitleaks_enabled") or config.get("exhaustive") or config.get("max_coverage"):
        try:
            from .secret_scanner import scan_secrets_gitleaks
            gitleaks_findings = scan_secrets_gitleaks(source_path)
            logger.info("Gitleaks scan: %d findings", len(gitleaks_findings))
        except Exception as e:
            logger.warning("Gitleaks scan failed: %s", e)

    # Merge and deduplicate secrets (TruffleHog > Gitleaks > regex by priority)
    trufflehog_fps = {f.get("fingerprint") for f in trufflehog_findings if f.get("fingerprint")}
    gitleaks_fps = {f.get("fingerprint") for f in gitleaks_findings if f.get("fingerprint")}
    deduped_regex = [f for f in secret_findings if f.get("fingerprint") not in (trufflehog_fps | gitleaks_fps)]
    secret_findings = trufflehog_findings + gitleaks_findings + deduped_regex
    logger.info("Total secret findings after dedup: %d", len(secret_findings))

    # Optional: scan git history for leaked secrets
    git_history_findings = []
    if config.get("scan_git_history", False):
        _progress_set(scan_id, {
            "status": "scanning",
            "phase": "secret_scan_history",
            "message": "Scanning git history for leaked secrets...",
            "files_scanned": total_files,
            "total_files": total_files,
            "issues_found": len(semgrep_findings) + len(secret_findings),
            "languages": detected_languages,
        })
        try:
            from .secret_scanner import scan_git_history
            git_history_findings = scan_git_history(source_path, max_commits=100)
            logger.info("Git history secret scan: %d findings", len(git_history_findings))
        except Exception as e:
            logger.warning("Git history scan failed: %s", e)

    if _progress_is_stopped(scan_id):
        return await _finalize_stopped_scan(
            scan_session_id=scan_session_id, scan_id=scan_id, source_path=source_path,
            total_files=total_files, detected_languages=detected_languages,
        )

    # ── Phase 3.5: SCA — Dependency Scanning ──────────────────────
    sca_findings = []
    sca_dependencies = []
    license_findings = []

    sca_org_enabled = org_flags.get("sast_sca_enabled", True)
    if config.get("sca_enabled", True) and sca_org_enabled:
        _progress_set(scan_id, {
            "status": "scanning",
            "phase": "sca_scanning",
            "message": "Scanning dependencies for vulnerabilities...",
            "files_scanned": total_files,
            "total_files": total_files,
            "issues_found": len(semgrep_findings) + len(secret_findings),
            "languages": detected_languages,
        })
        try:
            from .sca_scanner import scan_dependencies
            sca_result = await scan_dependencies(source_path)
            sca_findings = sca_result.get("findings", [])
            sca_dependencies = sca_result.get("dependencies", [])
            logger.info("SCA scan: %d findings, %d packages",
                        len(sca_findings), sca_result.get("total_packages", 0))

            # License compliance check
            try:
                from .license_checker import LicenseChecker
                blocked = config.get("blocked_licenses")
                checker = LicenseChecker(blocked_licenses=blocked)
                license_findings = checker.check_dependencies(sca_dependencies)
                logger.info("License check: %d findings", len(license_findings))
            except Exception as e:
                logger.warning("License check failed: %s", e)
        except Exception as e:
            logger.warning("SCA scan failed: %s", e)

    if _progress_is_stopped(scan_id):
        return await _finalize_stopped_scan(
            scan_session_id=scan_session_id, scan_id=scan_id, source_path=source_path,
            total_files=total_files, detected_languages=detected_languages,
        )

    # ── Phase 3.8: Claude Security Review ───────────────────────────
    claude_review_findings = []
    claude_review_cost = 0.0

    # Enable Claude review when AI analysis is on, or explicitly requested,
    # AND the org-level flag allows it.
    claude_org_enabled = org_flags.get("sast_claude_review_enabled", False)
    claude_review_enabled = config.get("claude_review_enabled", ai_analysis_enabled) and claude_org_enabled
    if claude_review_enabled and api_key:
        logger.info("Claude security review running for scan %s (org enabled=%s, api_key=set)", scan_id, claude_org_enabled)
        _progress_set(scan_id, {
            "status": "scanning",
            "phase": "claude_reviewing",
            "message": "Running Claude security review (3-phase analysis)...",
            "files_scanned": total_files,
            "total_files": total_files,
            "issues_found": len(semgrep_findings) + len(sca_findings),
            "languages": detected_languages,
        })
        try:
            from .claude_security_review import run_claude_review

            # Gather existing findings for dedup — Claude should not re-report
            # what Semgrep/other scanners already found.
            pre_claude_findings = (
                semgrep_findings + iac_findings + container_findings
                + js_deep_findings + secret_findings + git_history_findings
                + sca_findings + license_findings
            )

            # Pass org custom instructions so Claude prompts are org-aware
            custom_instructions = org_flags.get("sast_custom_instructions", "") or ""

            review_result = await run_claude_review(
                source_path=source_path,
                mode="scan",
                languages=detected_languages,
                api_key=api_key,
                organization_id=organization_id,
                scan_config=config,
                custom_instructions=custom_instructions,
                existing_findings=pre_claude_findings,
            )
            claude_review_findings = review_result.get("findings", [])
            claude_review_cost = review_result.get("cost_usd", 0.0)
            logger.info("Claude review: %d findings, cost $%.4f",
                        len(claude_review_findings), claude_review_cost)
        except Exception as e:
            logger.warning("Claude security review failed: %s", e)
    else:
        if not api_key:
            logger.info("Claude review skipped for scan %s: no API key (set ANTHROPIC_API_KEY or org claude_dast_api_key)", scan_id)
        elif not claude_org_enabled:
            logger.info("Claude review skipped for scan %s: org sast_claude_review_enabled is false (super_admin can enable in SAST admin)", scan_id)
        elif not config.get("claude_review_enabled", ai_analysis_enabled):
            logger.info("Claude review skipped for scan %s: not requested (enable AI analysis or claude_review in scan config)", scan_id)

    # ── Phase 4: AI Analysis (optional) ────────────────────────────
    all_findings = (
        semgrep_findings + iac_findings + container_findings + js_deep_findings
        + secret_findings + git_history_findings + sca_findings + license_findings
        + claude_review_findings
    )
    ai_cost = 0.0

    if ai_analysis_enabled and api_key and all_findings:
        logger.info("SAST AI analysis running for scan %s: %d findings", scan_id, len(all_findings))
        _progress_set(scan_id, {
            "status": "ai_analyzing",
            "phase": "ai_analysis",
            "message": f"AI analyzing {len(all_findings)} findings...",
            "files_scanned": total_files,
            "total_files": total_files,
            "issues_found": len(all_findings),
            "languages": detected_languages,
        })

        try:
            from .ai_analyzer import analyze_findings_with_ai
            all_findings = await analyze_findings_with_ai(
                all_findings, api_key,
                model="claude-haiku-4-5-20251001",
                organization_id=organization_id,
            )
            for f in all_findings:
                ai = f.get("ai_analysis", {})
                if isinstance(ai, dict) and "error" not in ai:
                    ai_cost += 0.01
        except Exception as e:
            logger.warning("AI analysis failed: %s", e)
    else:
        if ai_analysis_enabled and not api_key:
            logger.info("SAST AI analysis skipped for scan %s: no API key (set ANTHROPIC_API_KEY or org claude_dast_api_key)", scan_id)
        elif ai_analysis_enabled and not all_findings:
            logger.info("SAST AI analysis skipped for scan %s: no findings", scan_id)

    if _progress_is_stopped(scan_id):
        return await _finalize_stopped_scan(
            scan_session_id=scan_session_id, scan_id=scan_id, source_path=source_path,
            total_files=total_files, detected_languages=detected_languages,
            issues_found=len(all_findings),
        )

    # ── Phase 5: CVE Enrichment (for SCA findings) ─────────────────
    if sca_findings:
        _progress_set(scan_id, {
            "status": "scanning",
            "phase": "cve_enrichment",
            "message": "Enriching CVE intelligence (EPSS/KEV)...",
            "files_scanned": total_files,
            "total_files": total_files,
            "issues_found": len(all_findings),
            "languages": detected_languages,
        })
        try:
            from .cve_enrichment import enrich_findings
            enriched_sca = [f for f in all_findings if f.get("rule_source") == "sca"]
            await enrich_findings(enriched_sca)
            logger.info("CVE enrichment complete for %d SCA findings", len(enriched_sca))
        except Exception as e:
            logger.warning("CVE enrichment failed: %s", e)

    # Build CVE enrichment lookup from enriched SCA findings (for SastDependency epss/cvss/in_kev)
    cve_to_enrichment: dict[str, dict] = {}
    for f in all_findings:
        if f.get("rule_source") != "sca":
            continue
        for ref in f.get("references") or []:
            if not isinstance(ref, dict) or "cve_id" not in ref:
                continue
            cve_id = ref.get("cve_id")
            epss = ref.get("epss_score")
            cvss = ref.get("cvss_score")
            in_kev = ref.get("in_kev", False)
            if cve_id not in cve_to_enrichment:
                cve_to_enrichment[cve_id] = {"epss": 0.0, "cvss": None, "in_kev": False}
            cur = cve_to_enrichment[cve_id]
            if epss is not None:
                cur["epss"] = max(cur["epss"], float(epss))
            if cvss is not None:
                cur["cvss"] = max(cur["cvss"], float(cvss)) if cur["cvss"] is not None else float(cvss)
            cur["in_kev"] = cur["in_kev"] or bool(in_kev)

    # ── Phase 5: Store Results ─────────────────────────────────────
    _progress_set(scan_id, {
        "status": "completing",
        "phase": "storing_results",
        "message": "Saving results to database...",
        "files_scanned": total_files,
        "total_files": total_files,
        "issues_found": len(all_findings),
        "languages": detected_languages,
    })

    # Compute severity/category counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    category_counts = {}
    for f in all_findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        parts = f.get("rule_id", "").split(".")
        cat = parts[2] if len(parts) > 2 else "other"
        category_counts[cat] = category_counts.get(cat, 0) + 1

    # Policy evaluation (extended for all new scanner types)
    policy_result = None
    try:
        async with AsyncSessionLocal() as db:
            from app.models.sast_scan import SastPolicy
            policy_q = await db.execute(
                select(SastPolicy).where(
                    SastPolicy.organization_id == uuid.UUID(organization_id),
                    SastPolicy.is_default == True,
                    SastPolicy.is_active == True,
                )
            )
            default_policy = policy_q.scalar_one_or_none()
            if default_policy:
                from .policy_engine import evaluate_policy
                policy_dict = {
                    "name": default_policy.name,
                    "severity_threshold": default_policy.severity_threshold,
                    "max_issues_allowed": default_policy.max_issues_allowed,
                    "fail_on_secrets": default_policy.fail_on_secrets,
                    "required_fix_categories": default_policy.required_fix_categories or [],
                    "fail_on_sca_critical": getattr(default_policy, "fail_on_sca_critical", True),
                    "fail_on_kev": getattr(default_policy, "fail_on_kev", True),
                    "max_dependency_issues": getattr(default_policy, "max_dependency_issues", -1),
                    "blocked_licenses": getattr(default_policy, "blocked_licenses", None),
                    "fail_on_iac_critical": getattr(default_policy, "fail_on_iac_critical", True),
                    "fail_on_container_critical": getattr(default_policy, "fail_on_container_critical", True),
                }
                policy_result = evaluate_policy(policy_dict, all_findings, len(secret_findings))
    except Exception as e:
        logger.debug("Policy evaluation skipped: %s", e)

    duration = round(time.time() - start_time, 1)

    # ── Phase 6: SBOM Generation ──────────────────────────────────
    if sca_dependencies:
        _progress_set(scan_id, {
            "status": "scanning",
            "phase": "sbom_generation",
            "message": "Generating SBOM...",
            "files_scanned": total_files,
            "total_files": total_files,
            "issues_found": len(all_findings),
            "languages": detected_languages,
        })
        try:
            from .sbom_generator import SBOMGenerator
            cyclonedx_sbom = SBOMGenerator.generate_cyclonedx(
                scan_session_id=scan_session_id,
                project_name=config.get("project_name", "Unknown Project"),
                dependencies=sca_dependencies,
                language_stats=language_stats,
            )
            logger.info("SBOM generated: %d components", len(sca_dependencies))
        except Exception as e:
            logger.warning("SBOM generation failed: %s", e)
            cyclonedx_sbom = None
    else:
        cyclonedx_sbom = None

    # Save to database
    async with AsyncSessionLocal() as db:
        try:
            # Update scan session
            session_q = await db.execute(
                select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
            )
            session = session_q.scalar_one_or_none()
            if session:
                session.status = "completed"
                session.language_stats = language_stats
                session.total_files = total_files
                session.files_scanned = total_files
                session.total_issues = len(all_findings)
                session.issues_by_severity = severity_counts
                session.issues_by_category = category_counts
                session.ai_analysis_enabled = ai_analysis_enabled
                session.ai_cost_usd = ai_cost
                session.semgrep_rules_used = semgrep_rules_used
                session.secrets_found = len(secret_findings) + len(git_history_findings)
                session.dependency_issues = len(sca_findings)
                session.scan_duration_seconds = duration
                session.policy_result = policy_result
                session.completed_at = datetime.utcnow()
                # Only persist errors that are not registry/parser noise (404, invalid config, Semgrep rule parse quirks)
                def _is_meaningful_error(e: str) -> bool:
                    if not e:
                        return False
                    low = e.lower()
                    if "404" in e or "invalid configuration" in low or "failed to download configuration" in low:
                        return False
                    # Semgrep rule syntax errors when parsing GitHub Actions ${{ }} as Bash (metavariable-pattern)
                    if "syntax error" in low and "metavariable-pattern" in low:
                        return False
                    if "when parsing a snippet as bash" in low and "${{" in e:
                        return False
                    return True
                meaningful_errors = [e for e in semgrep_errors[:10] if _is_meaningful_error(e)]
                if meaningful_errors:
                    session.error_message = "; ".join(meaningful_errors[:5])

                # Extended tracking columns
                session.iac_issues = len(iac_findings)
                session.container_issues = len(container_findings)
                session.js_deep_issues = len(js_deep_findings)
                session.sca_issues = len(sca_findings)
                session.license_issues = len(license_findings)
                session.claude_review_enabled = bool(claude_review_enabled and api_key)
                session.claude_review_cost_usd = claude_review_cost
                session.claude_review_findings_count = len(claude_review_findings)

            # Create finding records (sanitize to avoid varchar truncation)
            from app.services.sast.finding_sanitizer import sanitize_finding_for_db
            for f in all_findings:
                s = sanitize_finding_for_db(f)
                code_snippet = s.get("code_snippet") or ""
                if len(code_snippet) > 5000:
                    code_snippet = code_snippet[:5000]
                finding = SastFinding(
                    scan_session_id=uuid.UUID(scan_session_id),
                    project_id=uuid.UUID(project_id),
                    rule_id=s.get("rule_id", "unknown"),
                    rule_source=s.get("rule_source", "semgrep"),
                    severity=s.get("severity", "medium"),
                    confidence=s.get("confidence", "medium"),
                    title=s.get("title", "Unknown Issue"),
                    description=s.get("description", ""),
                    message=s.get("message", ""),
                    file_path=s.get("file_path", ""),
                    line_start=s.get("line_start", 0),
                    line_end=s.get("line_end"),
                    column_start=s.get("column_start"),
                    column_end=s.get("column_end"),
                    code_snippet=code_snippet,
                    fix_suggestion=s.get("fix_suggestion"),
                    fixed_code=s.get("fixed_code"),
                    ai_analysis=s.get("ai_analysis"),
                    cwe_id=s.get("cwe_id"),
                    owasp_category=s.get("owasp_category"),
                    references=s.get("references"),
                    fingerprint=s.get("fingerprint"),
                    status="open",
                )
                db.add(finding)

            # Store dependency records (with EPSS/CVSS/KEV from enrichment lookup)
            if sca_dependencies:
                from app.models.sast_scan import SastDependency
                import hashlib as _hashlib
                for dep in sca_dependencies:
                    fp_raw = f"{dep.get('ecosystem')}:{dep.get('name')}:{dep.get('version')}"
                    dep_epss, dep_cvss, dep_in_kev = 0.0, None, False
                    for vuln in dep.get("vulnerabilities") or []:
                        aliases = vuln.get("aliases", []) if isinstance(vuln, dict) else []
                        for alias in aliases:
                            if isinstance(alias, str) and alias.startswith("CVE-"):
                                info = cve_to_enrichment.get(alias, {})
                                dep_epss = max(dep_epss, info.get("epss", 0.0) or 0.0)
                                v = info.get("cvss")
                                if v is not None:
                                    dep_cvss = max(dep_cvss, v) if dep_cvss is not None else v
                                dep_in_kev = dep_in_kev or info.get("in_kev", False)
                    if dep_cvss is None and dep.get("max_cvss") is not None:
                        dep_cvss = dep.get("max_cvss")
                    db.add(SastDependency(
                        scan_session_id=uuid.UUID(scan_session_id),
                        project_id=uuid.UUID(project_id),
                        name=dep.get("name", ""),
                        version=dep.get("version"),
                        ecosystem=dep.get("ecosystem", "unknown"),
                        manifest_file=dep.get("manifest_file"),
                        is_direct=dep.get("is_direct", True),
                        license_id=dep.get("license_id"),
                        license_risk=dep.get("license_risk"),
                        vulnerabilities=dep.get("vulnerabilities"),
                        fingerprint=_hashlib.sha256(fp_raw.encode()).hexdigest()[:32],
                        epss_score=dep_epss if dep_epss > 0 else None,
                        cvss_score=float(dep_cvss) if dep_cvss is not None else None,
                        in_kev=dep_in_kev,
                    ))

            # Store SBOM
            if cyclonedx_sbom:
                from app.models.sast_scan import SastSBOM
                db.add(SastSBOM(
                    scan_session_id=uuid.UUID(scan_session_id),
                    project_id=uuid.UUID(project_id),
                    organization_id=uuid.UUID(organization_id),
                    format="cyclonedx",
                    spec_version="1.5",
                    component_count=len(cyclonedx_sbom.get("components", [])),
                    total_dependencies=len(sca_dependencies),
                    sbom_data=cyclonedx_sbom,
                ))

            await db.commit()
            logger.info("SAST scan %s complete: %d findings in %.1fs", scan_id, len(all_findings), duration)

        except Exception as e:
            await db.rollback()
            logger.exception("Failed to save SAST results: %s", e)
            # Update session as failed
            try:
                session_q2 = await db.execute(
                    select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
                )
                session2 = session_q2.scalar_one_or_none()
                if session2:
                    session2.status = "failed"
                    session2.error_message = str(e)[:500]
                    await db.commit()
            except Exception:
                pass

    # Final progress update
    scanner_counts = {
        "semgrep": len(semgrep_findings),
        "iac": len(iac_findings),
        "container": len(container_findings),
        "js_deep": len(js_deep_findings),
        "secrets": len(secret_findings) + len(git_history_findings),
        "sca": len(sca_findings),
        "license": len(license_findings),
        "claude_review": len(claude_review_findings),
    }

    _progress_set(scan_id, {
        "status": "completed",
        "phase": "done",
        "message": f"Scan complete: {len(all_findings)} issues found in {duration}s",
        "files_scanned": total_files,
        "total_files": total_files,
        "issues_found": len(all_findings),
        "languages": detected_languages,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "duration_seconds": duration,
        "policy_result": policy_result,
        "scanner_counts": scanner_counts,
        "dependencies_scanned": len(sca_dependencies),
    })

    # Cleanup source — keep on failure for debugging, warn on success cleanup
    from .code_extractor import cleanup_source
    if source_path:
        logger.warning("Cleaning up source directory: %s (set breakpoint before this line to inspect)", source_path)
        cleanup_source(source_path)

    return {
        "scan_session_id": scan_session_id,
        "total_findings": len(all_findings),
        "severity_counts": severity_counts,
        "duration_seconds": duration,
        "policy_result": policy_result,
        "scanner_counts": scanner_counts,
        "dependencies_scanned": len(sca_dependencies),
    }


async def run_diff_scan(
    scan_session_id: str,
    project_id: str,
    organization_id: str,
    source_path: str,
    base_branch: str,
    head_branch: str = "HEAD",
    scan_config: dict | None = None,
    api_key: str = "",
) -> dict:
    """Execute a diff-aware SAST scan — only scans changed files.

    Much faster for CI/CD integration and PR review workflows.
    """
    from .code_extractor import get_changed_files

    config = scan_config or {}
    changed = get_changed_files(source_path, base_branch, head_branch)

    if not changed:
        logger.info("Diff scan %s: no changed files between %s and %s",
                     scan_session_id, base_branch, head_branch)
        return {
            "scan_session_id": scan_session_id,
            "total_findings": 0,
            "severity_counts": {},
            "changed_files": 0,
        }

    logger.info("Diff scan %s: %d changed files", scan_session_id, len(changed))

    config["changed_files_only"] = changed
    return await run_sast_scan(
        scan_session_id=scan_session_id,
        project_id=project_id,
        organization_id=organization_id,
        source_path=source_path,
        scan_config=config,
        ai_analysis_enabled=bool(api_key),
        api_key=api_key,
    )


async def _finalize_stopped_scan(
    scan_session_id: str,
    scan_id: str,
    source_path: str,
    total_files: int,
    detected_languages: list[str],
    issues_found: int = 0,
) -> dict:
    """Finalize a scan that was explicitly stopped before completion."""
    from app.core.database import AsyncSessionLocal
    from app.models.sast_scan import SastScanSession
    from sqlalchemy import select
    from .code_extractor import cleanup_source

    async with AsyncSessionLocal() as db:
        session_q = await db.execute(
            select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
        )
        session = session_q.scalar_one_or_none()
        if session:
            session.status = "stopped"
            session.completed_at = datetime.utcnow()
            session.total_files = total_files
            session.files_scanned = total_files
            session.total_issues = issues_found
            await db.commit()

    _progress_set(scan_id, {
        "status": "stopped",
        "phase": "done",
        "message": "Scan stopped by user",
        "files_scanned": total_files,
        "total_files": total_files,
        "issues_found": issues_found,
        "languages": detected_languages,
        "duration_seconds": 0,
    })

    if source_path:
        cleanup_source(source_path)

    return {
        "scan_session_id": scan_session_id,
        "total_findings": issues_found,
        "severity_counts": {},
        "duration_seconds": 0,
        "policy_result": None,
        "status": "stopped",
    }
