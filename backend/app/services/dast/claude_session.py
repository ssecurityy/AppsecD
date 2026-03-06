"""Claude DAST session manager — per-project context persistence in Redis."""
import json
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

SESSION_KEY_PREFIX = "claude:session:"
DEFAULT_TTL_DAYS = 30


def _get_redis():
    """Get synchronous Redis client."""
    import redis as redis_lib
    from app.core.config import get_settings
    return redis_lib.from_url(get_settings().redis_url, decode_responses=True)


def get_session(project_id: str) -> Optional[dict]:
    """Load session context for a project from Redis."""
    try:
        r = _get_redis()
        raw = r.get(f"{SESSION_KEY_PREFIX}{project_id}")
        if raw:
            return json.loads(raw)
    except Exception as e:
        logger.warning("Session load failed for %s: %s", project_id, e)
    return None


def save_session(
    project_id: str,
    target_url: str,
    messages: list[dict],
    scan_id: str,
    findings_count: int = 0,
    crawl_count: int = 0,
    technology_stack: dict | None = None,
    waf_detected: str | None = None,
    discovered_endpoints: list[str] | None = None,
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> None:
    """Save/update session context after a scan."""
    try:
        r = _get_redis()
        key = f"{SESSION_KEY_PREFIX}{project_id}"

        # Load existing session to merge
        existing = None
        raw = r.get(key)
        if raw:
            existing = json.loads(raw)

        # Build session data
        session = {
            "project_id": project_id,
            "target_url": target_url,
            "last_scan_id": scan_id,
            "last_scan_at": time.time(),
            "summary": f"Last scan: {findings_count} findings, {crawl_count} pages crawled",
            "scan_count": (existing.get("scan_count", 0) + 1) if existing else 1,
            # Keep last 30 messages for context
            "messages": messages[-30:] if messages else [],
        }

        # Merge accumulated knowledge
        if existing:
            # Merge technology stack
            if technology_stack:
                old_stack = existing.get("technology_stack", {})
                old_stack.update(technology_stack)
                session["technology_stack"] = old_stack
            else:
                session["technology_stack"] = existing.get("technology_stack", {})

            # Merge discovered endpoints (deduplicate)
            old_endpoints = set(existing.get("discovered_endpoints", []))
            if discovered_endpoints:
                old_endpoints.update(discovered_endpoints)
            session["discovered_endpoints"] = list(old_endpoints)[:500]

            # Keep WAF detection
            session["waf_detected"] = waf_detected or existing.get("waf_detected")

            # Keep scan history summaries
            scan_history = existing.get("scan_history", [])
            scan_history.append({
                "scan_id": scan_id,
                "date": time.time(),
                "findings": findings_count,
                "pages": crawl_count,
            })
            session["scan_history"] = scan_history[-20:]  # Keep last 20

            # Keep interesting behaviors
            session["interesting_behaviors"] = existing.get("interesting_behaviors", [])
        else:
            session["technology_stack"] = technology_stack or {}
            session["discovered_endpoints"] = discovered_endpoints or []
            session["waf_detected"] = waf_detected
            session["scan_history"] = [{
                "scan_id": scan_id,
                "date": time.time(),
                "findings": findings_count,
                "pages": crawl_count,
            }]
            session["interesting_behaviors"] = []

        r.setex(key, ttl_days * 86400, json.dumps(session, default=str))
    except Exception as e:
        logger.warning("Session save failed for %s: %s", project_id, e)


def clear_session(project_id: str) -> bool:
    """Clear session context for a project."""
    try:
        r = _get_redis()
        r.delete(f"{SESSION_KEY_PREFIX}{project_id}")
        return True
    except Exception as e:
        logger.warning("Session clear failed for %s: %s", project_id, e)
        return False


def add_interesting_behavior(project_id: str, behavior: str) -> None:
    """Add an interesting behavior observation to the session."""
    try:
        session = get_session(project_id)
        if not session:
            return
        behaviors = session.get("interesting_behaviors", [])
        if behavior not in behaviors:
            behaviors.append(behavior)
            session["interesting_behaviors"] = behaviors[-50:]
            r = _get_redis()
            from app.core.config import get_settings
            ttl = get_settings().claude_dast_session_ttl_days * 86400
            r.setex(f"{SESSION_KEY_PREFIX}{project_id}", ttl, json.dumps(session, default=str))
    except Exception as e:
        logger.warning("Add behavior failed for %s: %s", project_id, e)


def get_session_summary(project_id: str) -> dict:
    """Get a summary of the session (safe for frontend display)."""
    session = get_session(project_id)
    if not session:
        return {"has_session": False}

    return {
        "has_session": True,
        "target_url": session.get("target_url"),
        "scan_count": session.get("scan_count", 0),
        "last_scan_at": session.get("last_scan_at"),
        "summary": session.get("summary"),
        "technology_stack": session.get("technology_stack", {}),
        "waf_detected": session.get("waf_detected"),
        "discovered_endpoints_count": len(session.get("discovered_endpoints", [])),
        "interesting_behaviors": session.get("interesting_behaviors", [])[:10],
        "scan_history": session.get("scan_history", [])[-5:],
    }


def compact_messages(messages: list[dict], max_messages: int = 30) -> list[dict]:
    """Compact conversation messages to fit within context limits.

    Keeps the most recent messages and summarizes older ones.
    """
    if len(messages) <= max_messages:
        return messages

    # Keep last max_messages messages
    recent = messages[-max_messages:]

    # Create a summary of older messages
    older = messages[:-max_messages]
    tool_calls = sum(
        1 for m in older
        if isinstance(m.get("content"), list)
        and any(b.get("type") == "tool_use" for b in m["content"] if isinstance(b, dict))
    )
    summary_text = (
        f"[Session context: {len(older)} earlier messages with {tool_calls} tool calls "
        f"have been compacted for context efficiency.]"
    )

    return [{"role": "user", "content": summary_text}] + recent
