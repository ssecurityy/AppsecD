"""DAST AI RAG — retrieval-augmented generation for learning from past scans.

Stores confirmed findings, WAF bypass techniques, and domain profiles.
Retrieved before each scan to reduce redundant testing and improve accuracy.
"""
import logging
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from sqlalchemy import select, func, and_, or_, desc, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.models.dast_learning import DastLearning

logger = logging.getLogger(__name__)


async def retrieve_learnings(
    db: AsyncSession,
    domain: str,
    technology_stack: dict | None = None,
    categories: list[str] | None = None,
    organization_id: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Retrieve past learnings for a specific domain and optional tech stack/categories."""
    conditions = [
        or_(
            DastLearning.domain == domain,
            DastLearning.is_global == True,
        )
    ]
    if categories:
        conditions.append(DastLearning.category.in_(categories))
    if organization_id:
        conditions.append(
            or_(
                DastLearning.organization_id == organization_id,
                DastLearning.is_global == True,
            )
        )

    query = (
        select(DastLearning)
        .where(and_(*conditions))
        .order_by(desc(DastLearning.times_confirmed), desc(DastLearning.confidence))
        .limit(limit)
    )
    result = await db.execute(query)
    learnings = result.scalars().all()
    return [_learning_to_dict(l) for l in learnings]


async def retrieve_similar_learnings(
    db: AsyncSession,
    domain: str,
    technology_stack: dict | None = None,
    organization_id: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Fuzzy match learnings based on similar technology stacks across all domains."""
    conditions = []
    if organization_id:
        conditions.append(
            or_(
                DastLearning.organization_id == organization_id,
                DastLearning.is_global == True,
            )
        )
    # Exclude exact domain matches (those come from retrieve_learnings)
    conditions.append(DastLearning.domain != domain)
    # Only high-confidence learnings from other domains
    conditions.append(DastLearning.confidence >= 0.7)
    conditions.append(DastLearning.times_confirmed >= 2)

    if technology_stack:
        # Match on server, framework, or WAF
        for key in ["server", "framework", "waf"]:
            val = technology_stack.get(key)
            if val:
                conditions.append(
                    DastLearning.technology_stack[key].astext == val
                )

    query = (
        select(DastLearning)
        .where(and_(*conditions))
        .order_by(desc(DastLearning.confidence), desc(DastLearning.times_confirmed))
        .limit(limit)
    )
    result = await db.execute(query)
    learnings = result.scalars().all()
    return [_learning_to_dict(l) for l in learnings]


async def store_learning(
    db: AsyncSession,
    finding_data: dict,
    scan_context: dict,
) -> str | None:
    """Persist a new learning from a scan finding. Returns learning ID or None if duplicate updated."""
    domain = scan_context.get("domain", "")
    category = _categorize_finding(finding_data)

    # Check for existing learning on same domain + URL + parameter
    existing = await db.execute(
        select(DastLearning).where(
            and_(
                DastLearning.domain == domain,
                DastLearning.category == category,
                DastLearning.target_url == finding_data.get("affected_url", ""),
                DastLearning.parameter == finding_data.get("parameter", ""),
            )
        )
    )
    existing_learning = existing.scalar_one_or_none()

    if existing_learning:
        # Update confirmation count and confidence
        existing_learning.times_confirmed += 1
        existing_learning.last_confirmed = datetime.utcnow()
        existing_learning.confidence = min(1.0, existing_learning.confidence + 0.05)
        if finding_data.get("evidence"):
            existing_learning.evidence = finding_data["evidence"]
        await db.flush()
        logger.info("Updated existing learning %s (confirmed %dx)", existing_learning.id, existing_learning.times_confirmed)
        return str(existing_learning.id)

    learning = DastLearning(
        domain=domain,
        category=category,
        subcategory=finding_data.get("subcategory", ""),
        title=finding_data.get("title", ""),
        description=finding_data.get("description", ""),
        payload=finding_data.get("payload", ""),
        payload_type=finding_data.get("payload_type", "successful_attack"),
        target_url=finding_data.get("affected_url", ""),
        parameter=finding_data.get("parameter", ""),
        technology_stack=scan_context.get("technology_stack", {}),
        evidence=finding_data.get("evidence", {}),
        severity=finding_data.get("severity", "medium"),
        cwe_id=finding_data.get("cwe_id", ""),
        owasp_ref=finding_data.get("owasp_ref", ""),
        confidence=0.8,
        source=scan_context.get("source", "claude_scan"),
        project_id=scan_context.get("project_id"),
        organization_id=scan_context.get("organization_id"),
        is_global=scan_context.get("is_global", False),
        last_confirmed=datetime.utcnow(),
    )
    db.add(learning)
    await db.flush()
    logger.info("Stored new learning: %s on %s [%s]", learning.title, domain, category)
    return str(learning.id)


async def store_waf_bypass(
    db: AsyncSession,
    bypass_data: dict,
    scan_context: dict,
) -> str | None:
    """Store a WAF bypass technique as a learning."""
    domain = scan_context.get("domain", "")
    learning = DastLearning(
        domain=domain,
        category="waf_bypass",
        subcategory=bypass_data.get("waf_type", "unknown"),
        title=f"WAF Bypass: {bypass_data.get('waf_type', 'unknown')}",
        description=bypass_data.get("description", ""),
        payload=bypass_data.get("payload", ""),
        payload_type="waf_bypass",
        target_url=bypass_data.get("target_url", ""),
        parameter=bypass_data.get("parameter", ""),
        technology_stack=scan_context.get("technology_stack", {}),
        evidence=bypass_data.get("evidence", {}),
        severity="info",
        confidence=0.9,
        source="claude_scan",
        project_id=scan_context.get("project_id"),
        organization_id=scan_context.get("organization_id"),
        is_global=True,  # WAF bypasses are useful globally
        last_confirmed=datetime.utcnow(),
    )
    db.add(learning)
    await db.flush()
    logger.info("Stored WAF bypass: %s for %s", bypass_data.get("waf_type"), domain)
    return str(learning.id)


async def get_domain_profile(
    db: AsyncSession,
    domain: str,
    organization_id: str | None = None,
) -> dict:
    """Aggregate domain knowledge: tech stack, known vulns, WAF type, scan count."""
    conditions = [DastLearning.domain == domain]
    if organization_id:
        conditions.append(
            or_(
                DastLearning.organization_id == organization_id,
                DastLearning.is_global == True,
            )
        )

    result = await db.execute(
        select(DastLearning).where(and_(*conditions)).order_by(desc(DastLearning.updated_at))
    )
    learnings = result.scalars().all()

    if not learnings:
        return {"domain": domain, "known": False}

    # Aggregate technology stack from latest entries
    tech_stack = {}
    categories = {}
    waf_bypasses = []
    known_vulns = []
    total_scans = set()

    for l in learnings:
        if l.technology_stack:
            for k, v in l.technology_stack.items():
                if v and k not in tech_stack:
                    tech_stack[k] = v
        cat = l.category
        categories[cat] = categories.get(cat, 0) + 1
        if l.category == "waf_bypass":
            waf_bypasses.append({
                "waf_type": l.subcategory,
                "payload": l.payload,
                "confidence": l.confidence,
            })
        elif l.payload_type == "successful_attack":
            known_vulns.append({
                "category": l.category,
                "title": l.title,
                "severity": l.severity,
                "url": l.target_url,
                "parameter": l.parameter,
                "confidence": l.confidence,
                "times_confirmed": l.times_confirmed,
            })
        if l.project_id:
            total_scans.add(str(l.project_id))

    return {
        "domain": domain,
        "known": True,
        "technology_stack": tech_stack,
        "vulnerability_categories": categories,
        "waf_bypasses": waf_bypasses[:10],
        "known_vulnerabilities": known_vulns[:20],
        "total_projects_scanned": len(total_scans),
        "total_learnings": len(learnings),
        "last_scan": learnings[0].updated_at.isoformat() if learnings else None,
    }


def format_learnings_for_prompt(learnings: list[dict], domain_profile: dict | None = None) -> str:
    """Format learnings and domain profile as context for Claude system prompt."""
    if not learnings and (not domain_profile or not domain_profile.get("known")):
        return ""

    sections = []

    if domain_profile and domain_profile.get("known"):
        sections.append("## Domain Intelligence")
        tech = domain_profile.get("technology_stack", {})
        if tech:
            tech_str = ", ".join(f"{k}: {v}" for k, v in tech.items())
            sections.append(f"**Technology Stack:** {tech_str}")

        waf_bypasses = domain_profile.get("waf_bypasses", [])
        if waf_bypasses:
            sections.append(f"**WAF Detected:** {waf_bypasses[0].get('waf_type', 'unknown')}")
            sections.append("**Known WAF Bypass Techniques:**")
            for wb in waf_bypasses[:5]:
                sections.append(f"  - Payload: `{wb['payload'][:100]}` (confidence: {wb['confidence']})")

        known_vulns = domain_profile.get("known_vulnerabilities", [])
        if known_vulns:
            sections.append(f"\n**Known Vulnerabilities ({len(known_vulns)}):**")
            for v in known_vulns[:10]:
                sections.append(
                    f"  - [{v['severity'].upper()}] {v['title']} at {v.get('url', 'N/A')} "
                    f"(param: {v.get('parameter', 'N/A')}, confirmed {v['times_confirmed']}x)"
                )

    if learnings:
        # Group by category
        by_cat = {}
        for l in learnings:
            cat = l.get("category", "other")
            by_cat.setdefault(cat, []).append(l)

        sections.append("\n## Past Scan Learnings")
        for cat, items in by_cat.items():
            sections.append(f"\n### {cat.upper()} ({len(items)} learnings)")
            for item in items[:5]:
                payload_str = f" | payload: `{item['payload'][:80]}`" if item.get("payload") else ""
                sections.append(
                    f"  - {item['title']} [{item.get('severity', 'info')}] "
                    f"at {item.get('target_url', 'N/A')}{payload_str}"
                )

    sections.append("\n**Use these learnings to prioritize testing. Skip areas already confirmed as not vulnerable. Use known-working payloads first.**")

    return "\n".join(sections)


async def update_learning_confidence(
    db: AsyncSession,
    domain: str,
    target_url: str,
    parameter: str,
    new_confidence: float,
) -> None:
    """Update confidence for a learning (e.g., after failed retest)."""
    await db.execute(
        update(DastLearning)
        .where(
            and_(
                DastLearning.domain == domain,
                DastLearning.target_url == target_url,
                DastLearning.parameter == parameter,
            )
        )
        .values(confidence=new_confidence, updated_at=datetime.utcnow())
    )


async def delete_learnings_for_project(db: AsyncSession, project_id: str) -> int:
    """Delete all learnings associated with a project (for project cleanup)."""
    from sqlalchemy import delete as sa_delete
    result = await db.execute(
        sa_delete(DastLearning).where(DastLearning.project_id == project_id)
    )
    return result.rowcount


async def get_learnings_stats(
    db: AsyncSession,
    organization_id: str | None = None,
) -> dict:
    """Get statistics about stored learnings."""
    conditions = []
    if organization_id:
        conditions.append(
            or_(
                DastLearning.organization_id == organization_id,
                DastLearning.is_global == True,
            )
        )

    base_q = select(func.count(DastLearning.id))
    if conditions:
        base_q = base_q.where(and_(*conditions))
    total = (await db.execute(base_q)).scalar() or 0

    # By category
    cat_q = (
        select(DastLearning.category, func.count(DastLearning.id))
        .group_by(DastLearning.category)
    )
    if conditions:
        cat_q = cat_q.where(and_(*conditions))
    cat_result = await db.execute(cat_q)
    by_category = {row[0]: row[1] for row in cat_result.all()}

    # Unique domains
    domain_q = select(func.count(func.distinct(DastLearning.domain)))
    if conditions:
        domain_q = domain_q.where(and_(*conditions))
    unique_domains = (await db.execute(domain_q)).scalar() or 0

    return {
        "total_learnings": total,
        "by_category": by_category,
        "unique_domains": unique_domains,
    }


def _categorize_finding(finding_data: dict) -> str:
    """Map finding data to a learning category."""
    title = (finding_data.get("title") or "").lower()
    cwe = finding_data.get("cwe_id", "")
    check_id = (finding_data.get("check_id") or "").lower()

    category_map = {
        "sqli": ["sql injection", "sqli", "cwe-89"],
        "xss": ["cross-site scripting", "xss", "cwe-79"],
        "ssrf": ["server-side request", "ssrf", "cwe-918"],
        "lfi": ["path traversal", "local file", "lfi", "cwe-22"],
        "rce": ["command injection", "remote code", "cwe-78"],
        "csrf": ["cross-site request forgery", "csrf", "cwe-352"],
        "auth": ["authentication", "authorization", "broken access", "cwe-287", "cwe-862"],
        "idor": ["insecure direct object", "idor", "cwe-639"],
        "ssti": ["template injection", "ssti", "cwe-1336"],
        "xxe": ["xml external", "xxe", "cwe-611"],
        "deserialization": ["deserialization", "cwe-502"],
        "cors": ["cors", "cross-origin", "cwe-942"],
        "jwt": ["jwt", "json web token", "cwe-347"],
        "exposure": ["exposure", "disclosure", "leak", "cwe-200"],
        "config": ["misconfiguration", "config", "cwe-16"],
        "header": ["header", "csp", "hsts"],
        "crypto": ["cryptographic", "encryption", "cwe-327"],
    }

    for cat, keywords in category_map.items():
        for kw in keywords:
            if kw in title or kw in cwe or kw in check_id:
                return cat
    return "other"


def _learning_to_dict(learning: DastLearning) -> dict:
    """Convert a DastLearning ORM object to dict."""
    return {
        "id": str(learning.id),
        "domain": learning.domain,
        "category": learning.category,
        "subcategory": learning.subcategory,
        "title": learning.title,
        "description": learning.description,
        "payload": learning.payload,
        "payload_type": learning.payload_type,
        "target_url": learning.target_url,
        "parameter": learning.parameter,
        "technology_stack": learning.technology_stack,
        "evidence": learning.evidence,
        "severity": learning.severity,
        "cwe_id": learning.cwe_id,
        "owasp_ref": learning.owasp_ref,
        "confidence": learning.confidence,
        "times_confirmed": learning.times_confirmed,
        "last_confirmed": learning.last_confirmed.isoformat() if learning.last_confirmed else None,
        "source": learning.source,
        "is_global": learning.is_global,
        "created_at": learning.created_at.isoformat() if learning.created_at else None,
    }
