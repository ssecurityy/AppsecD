"""Finding lifecycle management — assignment, SLA tracking, exceptions, audit trail.

Provides enterprise-grade finding management with:
- User/team assignment
- SLA enforcement with auto-escalation
- Risk acceptance/exception workflows with approval and expiry
- Append-only audit trail for compliance
"""

from __future__ import annotations

import logging
import uuid as _uuid
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import select, update, and_

logger = logging.getLogger(__name__)

# ── Valid Status Transitions ─────────────────────────────────────────
# Maps current_status -> set of allowed next statuses.
VALID_TRANSITIONS: dict[str, set[str]] = {
    "open": {"confirmed", "false_positive", "ignored", "wont_fix", "in_progress"},
    "confirmed": {"in_progress", "false_positive", "wont_fix"},
    "in_progress": {"fixed", "open"},        # open = reopen
    "fixed": {"open"},                        # open = regression
    "false_positive": {"open"},               # open = re-evaluate
    "ignored": {"open"},
    "wont_fix": {"open"},
}

ALL_STATUSES = set(VALID_TRANSITIONS.keys()) | {"fixed"}

# ── SLA Deadlines by Severity ───────────────────────────────────────
# Number of calendar days from finding creation until SLA breach.
SLA_DAYS: dict[str, int] = {
    "critical": 1,
    "high": 3,
    "medium": 7,
    "low": 30,
    "info": 90,
}

# Escalation chain: severity -> escalated severity label used in notifications
ESCALATION_MAP: dict[str, str] = {
    "info": "low",
    "low": "medium",
    "medium": "high",
    "high": "critical",
    "critical": "critical",
}


def _is_valid_transition(current_status: str, new_status: str) -> bool:
    """Return True if the transition is allowed by the state machine."""
    allowed = VALID_TRANSITIONS.get(current_status)
    if allowed is None:
        return False
    return new_status in allowed


def _sla_deadline(severity: str, created_at: datetime) -> datetime:
    """Calculate the SLA deadline for a finding based on severity."""
    days = SLA_DAYS.get(severity, 90)
    return created_at + timedelta(days=days)


def _build_audit_entry(
    action: str,
    changed_by: str,
    *,
    old_status: str | None = None,
    new_status: str | None = None,
    reason: str | None = None,
    extra: dict | None = None,
) -> dict:
    """Create a single audit-trail entry (append-only)."""
    entry: dict[str, Any] = {
        "action": action,
        "changed_by": str(changed_by),
        "timestamp": datetime.utcnow().isoformat(),
    }
    if old_status is not None:
        entry["old_status"] = old_status
    if new_status is not None:
        entry["new_status"] = new_status
    if reason:
        entry["reason"] = reason
    if extra:
        entry.update(extra)
    return entry


class FindingLifecycleManager:
    """Manages the full lifecycle of SAST findings.

    All operations are performed against the database via ``AsyncSessionLocal``.
    Every mutation is recorded in an append-only JSONB audit trail stored on the
    finding's ``ai_analysis`` field under the key ``"lifecycle_audit"``.
    """

    # ── Assignment ───────────────────────────────────────────────────

    @staticmethod
    async def assign_finding(
        finding_id: str,
        assigned_to: str,
        assigned_by: str,
    ) -> dict:
        """Assign a finding to a user or team.

        Args:
            finding_id: UUID of the SastFinding.
            assigned_to: UUID (or identifier) of the assignee.
            assigned_by: UUID of the user performing the assignment.

        Returns:
            ``{"ok": True, "finding_id": ..., "assigned_to": ...}`` on success,
            ``{"ok": False, "error": ...}`` on failure.
        """
        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastFinding

            async with AsyncSessionLocal() as db:
                finding = (
                    await db.execute(
                        select(SastFinding).where(
                            SastFinding.id == _uuid.UUID(finding_id)
                        )
                    )
                ).scalar_one_or_none()

                if finding is None:
                    return {"ok": False, "error": "Finding not found"}

                # Store assignment in ai_analysis JSONB
                ai = finding.ai_analysis or {}
                if not isinstance(ai, dict):
                    ai = {}

                previous_assignee = ai.get("assigned_to")
                ai["assigned_to"] = str(assigned_to)
                ai["assigned_by"] = str(assigned_by)
                ai["assigned_at"] = datetime.utcnow().isoformat()

                # Append audit entry
                audit = ai.get("lifecycle_audit", [])
                audit.append(
                    _build_audit_entry(
                        "assign",
                        assigned_by,
                        extra={
                            "assigned_to": str(assigned_to),
                            "previous_assignee": previous_assignee,
                        },
                    )
                )
                ai["lifecycle_audit"] = audit
                finding.ai_analysis = ai
                await db.commit()

                return {
                    "ok": True,
                    "finding_id": str(finding.id),
                    "assigned_to": str(assigned_to),
                }
        except Exception as exc:
            logger.exception("assign_finding failed: %s", exc)
            return {"ok": False, "error": str(exc)}

    # ── Status Transition ────────────────────────────────────────────

    @staticmethod
    async def update_status(
        finding_id: str,
        new_status: str,
        changed_by: str,
        reason: str | None = None,
    ) -> dict:
        """Transition a finding to *new_status* with state-machine validation.

        Args:
            finding_id: UUID of the SastFinding.
            new_status: Target status (must be a valid transition).
            changed_by: UUID of the user making the change.
            reason: Optional human-readable reason for the change.

        Returns:
            ``{"ok": True, ...}`` on success, ``{"ok": False, "error": ...}``
            on failure (invalid transition, not found, etc.).
        """
        if new_status not in ALL_STATUSES:
            return {"ok": False, "error": f"Unknown status: {new_status}"}

        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastFinding

            async with AsyncSessionLocal() as db:
                finding = (
                    await db.execute(
                        select(SastFinding).where(
                            SastFinding.id == _uuid.UUID(finding_id)
                        )
                    )
                ).scalar_one_or_none()

                if finding is None:
                    return {"ok": False, "error": "Finding not found"}

                old_status = finding.status or "open"

                if not _is_valid_transition(old_status, new_status):
                    return {
                        "ok": False,
                        "error": (
                            f"Invalid transition: {old_status} -> {new_status}. "
                            f"Allowed: {sorted(VALID_TRANSITIONS.get(old_status, set()))}"
                        ),
                    }

                finding.status = new_status

                # Audit trail
                ai = finding.ai_analysis or {}
                if not isinstance(ai, dict):
                    ai = {}
                audit = ai.get("lifecycle_audit", [])
                audit.append(
                    _build_audit_entry(
                        "status_change",
                        changed_by,
                        old_status=old_status,
                        new_status=new_status,
                        reason=reason,
                    )
                )
                ai["lifecycle_audit"] = audit
                finding.ai_analysis = ai
                await db.commit()

                return {
                    "ok": True,
                    "finding_id": str(finding.id),
                    "old_status": old_status,
                    "new_status": new_status,
                }
        except Exception as exc:
            logger.exception("update_status failed: %s", exc)
            return {"ok": False, "error": str(exc)}

    # ── Risk Acceptance / Exception ──────────────────────────────────

    @staticmethod
    async def create_exception(
        finding_id: str,
        approved_by: str,
        reason: str,
        expires_at: datetime | None = None,
    ) -> dict:
        """Create a risk-acceptance exception for a finding.

        The finding is moved to ``wont_fix`` status and an expiry date is
        recorded.  When the exception expires the finding should be
        automatically reopened (see ``check_sla_violations``).

        Args:
            finding_id: UUID of the SastFinding.
            approved_by: UUID of the approver (must have appropriate role).
            reason: Justification for accepting the risk.
            expires_at: Optional expiry datetime; defaults to 90 days from now.
        """
        if expires_at is None:
            expires_at = datetime.utcnow() + timedelta(days=90)

        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastFinding

            async with AsyncSessionLocal() as db:
                finding = (
                    await db.execute(
                        select(SastFinding).where(
                            SastFinding.id == _uuid.UUID(finding_id)
                        )
                    )
                ).scalar_one_or_none()

                if finding is None:
                    return {"ok": False, "error": "Finding not found"}

                old_status = finding.status or "open"

                # Exceptions can be created from open or confirmed findings
                if old_status not in ("open", "confirmed"):
                    return {
                        "ok": False,
                        "error": (
                            f"Cannot create exception for finding in status "
                            f"'{old_status}'. Must be 'open' or 'confirmed'."
                        ),
                    }

                finding.status = "wont_fix"

                ai = finding.ai_analysis or {}
                if not isinstance(ai, dict):
                    ai = {}

                # Record exception metadata
                ai["exception"] = {
                    "approved_by": str(approved_by),
                    "reason": reason,
                    "created_at": datetime.utcnow().isoformat(),
                    "expires_at": expires_at.isoformat(),
                    "active": True,
                }

                # Audit trail
                audit = ai.get("lifecycle_audit", [])
                audit.append(
                    _build_audit_entry(
                        "exception_created",
                        approved_by,
                        old_status=old_status,
                        new_status="wont_fix",
                        reason=reason,
                        extra={"expires_at": expires_at.isoformat()},
                    )
                )
                ai["lifecycle_audit"] = audit
                finding.ai_analysis = ai
                await db.commit()

                return {
                    "ok": True,
                    "finding_id": str(finding.id),
                    "exception_expires_at": expires_at.isoformat(),
                }
        except Exception as exc:
            logger.exception("create_exception failed: %s", exc)
            return {"ok": False, "error": str(exc)}

    # ── SLA Violation Check ──────────────────────────────────────────

    @staticmethod
    async def check_sla_violations(project_id: str) -> dict:
        """Find all findings past their SLA deadline for a project.

        Also checks for expired risk-acceptance exceptions and reopens them.

        Returns:
            ``{"violations": [...], "expired_exceptions": [...]}``
        """
        violations: list[dict] = []
        expired_exceptions: list[dict] = []
        now = datetime.utcnow()

        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastFinding

            async with AsyncSessionLocal() as db:
                # Active (non-resolved) findings
                result = await db.execute(
                    select(SastFinding).where(
                        SastFinding.project_id == _uuid.UUID(project_id),
                        SastFinding.status.in_(
                            ["open", "confirmed", "in_progress"]
                        ),
                    )
                )
                findings = result.scalars().all()

                for f in findings:
                    deadline = _sla_deadline(f.severity or "medium", f.created_at)
                    if now > deadline:
                        days_overdue = (now - deadline).days
                        violations.append(
                            {
                                "finding_id": str(f.id),
                                "title": f.title,
                                "severity": f.severity,
                                "status": f.status,
                                "created_at": f.created_at.isoformat(),
                                "sla_deadline": deadline.isoformat(),
                                "days_overdue": days_overdue,
                                "file_path": f.file_path,
                                "assigned_to": (f.ai_analysis or {}).get(
                                    "assigned_to"
                                ),
                            }
                        )

                # Expired exceptions (wont_fix findings with expired exception)
                wontfix_result = await db.execute(
                    select(SastFinding).where(
                        SastFinding.project_id == _uuid.UUID(project_id),
                        SastFinding.status == "wont_fix",
                    )
                )
                wontfix_findings = wontfix_result.scalars().all()

                for f in wontfix_findings:
                    ai = f.ai_analysis or {}
                    if not isinstance(ai, dict):
                        continue
                    exception = ai.get("exception", {})
                    if not exception or not exception.get("active"):
                        continue
                    exp_str = exception.get("expires_at")
                    if exp_str:
                        try:
                            exp_dt = datetime.fromisoformat(exp_str)
                        except (ValueError, TypeError):
                            continue
                        if now > exp_dt:
                            # Reopen the finding
                            f.status = "open"
                            exception["active"] = False
                            ai["exception"] = exception

                            audit = ai.get("lifecycle_audit", [])
                            audit.append(
                                _build_audit_entry(
                                    "exception_expired",
                                    "system",
                                    old_status="wont_fix",
                                    new_status="open",
                                    reason=f"Exception expired on {exp_str}",
                                )
                            )
                            ai["lifecycle_audit"] = audit
                            f.ai_analysis = ai

                            expired_exceptions.append(
                                {
                                    "finding_id": str(f.id),
                                    "title": f.title,
                                    "severity": f.severity,
                                    "expired_at": exp_str,
                                }
                            )

                await db.commit()

        except Exception as exc:
            logger.exception("check_sla_violations failed: %s", exc)

        return {
            "project_id": project_id,
            "checked_at": now.isoformat(),
            "violations_count": len(violations),
            "violations": violations,
            "expired_exceptions_count": len(expired_exceptions),
            "expired_exceptions": expired_exceptions,
        }

    # ── Auto-Escalation ──────────────────────────────────────────────

    @staticmethod
    async def auto_escalate_overdue(project_id: str) -> dict:
        """Auto-escalate overdue findings by bumping effective severity.

        Findings that have exceeded their SLA deadline by more than 1x the
        original window are escalated.  The original severity is preserved; an
        ``escalated_severity`` field is added to ``ai_analysis``.

        Returns:
            ``{"escalated": [...]}`` with details of escalated findings.
        """
        escalated: list[dict] = []
        now = datetime.utcnow()

        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastFinding

            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(SastFinding).where(
                        SastFinding.project_id == _uuid.UUID(project_id),
                        SastFinding.status.in_(
                            ["open", "confirmed", "in_progress"]
                        ),
                    )
                )
                findings = result.scalars().all()

                for f in findings:
                    sev = f.severity or "medium"
                    deadline = _sla_deadline(sev, f.created_at)
                    if now <= deadline:
                        continue

                    # Only escalate if overdue by more than the original window
                    sla_window = timedelta(days=SLA_DAYS.get(sev, 90))
                    double_deadline = deadline + sla_window
                    ai = f.ai_analysis or {}
                    if not isinstance(ai, dict):
                        ai = {}

                    already_escalated = ai.get("escalated_severity")
                    if already_escalated:
                        # Already escalated — do not escalate again
                        continue

                    if now > double_deadline or sev == "critical":
                        new_esc_sev = ESCALATION_MAP.get(sev, sev)
                        ai["escalated_severity"] = new_esc_sev
                        ai["escalated_at"] = now.isoformat()

                        audit = ai.get("lifecycle_audit", [])
                        audit.append(
                            _build_audit_entry(
                                "auto_escalation",
                                "system",
                                reason=(
                                    f"SLA overdue — escalated from {sev} to "
                                    f"{new_esc_sev}"
                                ),
                                extra={
                                    "original_severity": sev,
                                    "escalated_severity": new_esc_sev,
                                    "days_overdue": (now - deadline).days,
                                },
                            )
                        )
                        ai["lifecycle_audit"] = audit
                        f.ai_analysis = ai

                        escalated.append(
                            {
                                "finding_id": str(f.id),
                                "title": f.title,
                                "original_severity": sev,
                                "escalated_severity": new_esc_sev,
                                "days_overdue": (now - deadline).days,
                            }
                        )

                await db.commit()

        except Exception as exc:
            logger.exception("auto_escalate_overdue failed: %s", exc)

        return {
            "project_id": project_id,
            "escalated_count": len(escalated),
            "escalated": escalated,
        }

    # ── Audit Trail ──────────────────────────────────────────────────

    @staticmethod
    async def get_audit_trail(finding_id: str) -> dict:
        """Return the complete append-only audit trail for a finding.

        Returns:
            ``{"finding_id": ..., "trail": [...]}`` — the trail is a list of
            chronologically ordered audit entries.
        """
        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastFinding

            async with AsyncSessionLocal() as db:
                finding = (
                    await db.execute(
                        select(SastFinding).where(
                            SastFinding.id == _uuid.UUID(finding_id)
                        )
                    )
                ).scalar_one_or_none()

                if finding is None:
                    return {"finding_id": finding_id, "trail": [], "error": "Finding not found"}

                ai = finding.ai_analysis or {}
                if not isinstance(ai, dict):
                    ai = {}

                trail = ai.get("lifecycle_audit", [])

                return {
                    "finding_id": str(finding.id),
                    "current_status": finding.status,
                    "severity": finding.severity,
                    "assigned_to": ai.get("assigned_to"),
                    "exception": ai.get("exception"),
                    "escalated_severity": ai.get("escalated_severity"),
                    "trail": trail,
                }
        except Exception as exc:
            logger.exception("get_audit_trail failed: %s", exc)
            return {"finding_id": finding_id, "trail": [], "error": str(exc)}

    # ── Bulk Operations ──────────────────────────────────────────────

    @staticmethod
    async def bulk_update_status(
        finding_ids: list[str],
        new_status: str,
        changed_by: str,
        reason: str | None = None,
    ) -> dict:
        """Transition multiple findings to *new_status* in a single transaction.

        Findings whose current status does not allow the transition are skipped
        (reported in ``skipped``).

        Args:
            finding_ids: List of SastFinding UUIDs.
            new_status: Target status.
            changed_by: UUID of the user making the change.
            reason: Optional reason recorded in the audit trail.

        Returns:
            ``{"updated": [...], "skipped": [...]}``
        """
        if new_status not in ALL_STATUSES:
            return {
                "ok": False,
                "error": f"Unknown status: {new_status}",
                "updated": [],
                "skipped": [],
            }

        updated: list[dict] = []
        skipped: list[dict] = []

        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastFinding

            async with AsyncSessionLocal() as db:
                uuids = [_uuid.UUID(fid) for fid in finding_ids]
                result = await db.execute(
                    select(SastFinding).where(SastFinding.id.in_(uuids))
                )
                findings = result.scalars().all()

                found_ids = {str(f.id) for f in findings}
                for fid in finding_ids:
                    if fid not in found_ids:
                        skipped.append({"finding_id": fid, "reason": "not_found"})

                for f in findings:
                    old_status = f.status or "open"
                    if not _is_valid_transition(old_status, new_status):
                        skipped.append(
                            {
                                "finding_id": str(f.id),
                                "reason": (
                                    f"Invalid transition: {old_status} -> "
                                    f"{new_status}"
                                ),
                            }
                        )
                        continue

                    f.status = new_status

                    ai = f.ai_analysis or {}
                    if not isinstance(ai, dict):
                        ai = {}
                    audit = ai.get("lifecycle_audit", [])
                    audit.append(
                        _build_audit_entry(
                            "bulk_status_change",
                            changed_by,
                            old_status=old_status,
                            new_status=new_status,
                            reason=reason,
                            extra={"bulk_operation": True},
                        )
                    )
                    ai["lifecycle_audit"] = audit
                    f.ai_analysis = ai

                    updated.append(
                        {
                            "finding_id": str(f.id),
                            "old_status": old_status,
                            "new_status": new_status,
                        }
                    )

                await db.commit()

        except Exception as exc:
            logger.exception("bulk_update_status failed: %s", exc)
            return {
                "ok": False,
                "error": str(exc),
                "updated": updated,
                "skipped": skipped,
            }

        return {
            "ok": True,
            "updated_count": len(updated),
            "skipped_count": len(skipped),
            "updated": updated,
            "skipped": skipped,
        }
