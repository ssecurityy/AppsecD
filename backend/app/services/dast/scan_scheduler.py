"""DAST scan scheduler — cron-based recurring scans with baseline comparison."""
import json
import logging
import uuid
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

REDIS_SCHEDULE_PREFIX = "dast_schedule:"


def _parse_cron(cron_expr: str) -> dict:
    """Parse a simple cron expression into components.

    Supports: daily, weekly, monthly, or standard 5-field cron.
    """
    shortcuts = {
        "@daily": {"hour": 2, "minute": 0, "interval_hours": 24},
        "@weekly": {"hour": 2, "minute": 0, "interval_hours": 168},
        "@monthly": {"hour": 2, "minute": 0, "interval_hours": 720},
        "@hourly": {"hour": -1, "minute": 0, "interval_hours": 1},
    }

    if cron_expr.lower() in shortcuts:
        return shortcuts[cron_expr.lower()]

    parts = cron_expr.strip().split()
    if len(parts) == 5:
        minute, hour = parts[0], parts[1]
        return {
            "minute": int(minute) if minute != "*" else 0,
            "hour": int(hour) if hour != "*" else -1,
            "interval_hours": 24,
            "raw": cron_expr,
        }

    return {"hour": 2, "minute": 0, "interval_hours": 24}


def calculate_next_run(cron_expr: str, from_time: datetime | None = None) -> datetime:
    """Calculate the next run time from a cron expression."""
    now = from_time or datetime.utcnow()
    parsed = _parse_cron(cron_expr)
    interval = timedelta(hours=parsed["interval_hours"])

    if parsed.get("hour", -1) >= 0:
        next_run = now.replace(
            hour=parsed["hour"], minute=parsed.get("minute", 0),
            second=0, microsecond=0,
        )
        if next_run <= now:
            next_run += timedelta(days=1)
        return next_run

    return now + interval


class ScanScheduler:
    """Manages recurring DAST scan schedules."""

    @staticmethod
    async def create_schedule(
        db,
        project_id: str,
        organization_id: str,
        cron_expression: str,
        scan_config: dict | None = None,
        created_by: str | None = None,
    ) -> dict:
        """Create or update a scan schedule for a project."""
        from app.models.sast_scan import DastSchedule
        from sqlalchemy import select

        next_run = calculate_next_run(cron_expression)

        existing = (await db.execute(
            select(DastSchedule).where(
                DastSchedule.project_id == uuid.UUID(project_id)
            )
        )).scalar_one_or_none()

        if existing:
            existing.cron_expression = cron_expression
            existing.scan_config = scan_config
            existing.next_run_at = next_run
            existing.is_active = True
            existing.updated_at = datetime.utcnow()
            await db.commit()
            return {
                "id": str(existing.id),
                "project_id": project_id,
                "cron_expression": cron_expression,
                "next_run_at": next_run.isoformat(),
                "is_active": True,
                "updated": True,
            }

        schedule = DastSchedule(
            project_id=uuid.UUID(project_id),
            organization_id=uuid.UUID(organization_id),
            cron_expression=cron_expression,
            scan_config=scan_config,
            is_active=True,
            next_run_at=next_run,
            created_by=uuid.UUID(created_by) if created_by else None,
        )
        db.add(schedule)
        await db.commit()

        return {
            "id": str(schedule.id),
            "project_id": project_id,
            "cron_expression": cron_expression,
            "next_run_at": next_run.isoformat(),
            "is_active": True,
            "created": True,
        }

    @staticmethod
    async def get_schedule(db, project_id: str) -> dict | None:
        """Get the schedule for a project."""
        from app.models.sast_scan import DastSchedule
        from sqlalchemy import select

        schedule = (await db.execute(
            select(DastSchedule).where(
                DastSchedule.project_id == uuid.UUID(project_id)
            )
        )).scalar_one_or_none()

        if not schedule:
            return None

        return {
            "id": str(schedule.id),
            "project_id": str(schedule.project_id),
            "cron_expression": schedule.cron_expression,
            "scan_config": schedule.scan_config,
            "is_active": schedule.is_active,
            "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else None,
            "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        }

    @staticmethod
    async def delete_schedule(db, project_id: str) -> bool:
        """Delete a schedule."""
        from app.models.sast_scan import DastSchedule
        from sqlalchemy import select, delete

        result = await db.execute(
            delete(DastSchedule).where(
                DastSchedule.project_id == uuid.UUID(project_id)
            )
        )
        await db.commit()
        return result.rowcount > 0

    @staticmethod
    async def get_due_schedules(db) -> list[dict]:
        """Get all schedules that are due for execution."""
        from app.models.sast_scan import DastSchedule
        from sqlalchemy import select

        now = datetime.utcnow()
        schedules = (await db.execute(
            select(DastSchedule).where(
                DastSchedule.is_active == True,
                DastSchedule.next_run_at <= now,
            )
        )).scalars().all()

        return [
            {
                "id": str(s.id),
                "project_id": str(s.project_id),
                "organization_id": str(s.organization_id),
                "cron_expression": s.cron_expression,
                "scan_config": s.scan_config,
            }
            for s in schedules
        ]

    @staticmethod
    async def mark_run_complete(db, project_id: str) -> None:
        """Update schedule after a scan completes."""
        from app.models.sast_scan import DastSchedule
        from sqlalchemy import select

        schedule = (await db.execute(
            select(DastSchedule).where(
                DastSchedule.project_id == uuid.UUID(project_id)
            )
        )).scalar_one_or_none()

        if schedule:
            schedule.last_run_at = datetime.utcnow()
            schedule.next_run_at = calculate_next_run(schedule.cron_expression)
            schedule.updated_at = datetime.utcnow()
            await db.commit()


class BaselineComparer:
    """Compare scan results against previous baselines for delta reporting."""

    @staticmethod
    async def create_baseline(
        db,
        project_id: str,
        scan_session_id: str,
        findings: list[dict],
    ) -> dict:
        """Create a baseline snapshot from scan findings."""
        from app.models.sast_scan import DastBaseline

        severity_counts = {}
        fingerprints = set()
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            fp = f.get("fingerprint") or f.get("title", "")
            fingerprints.add(fp)

        baseline = DastBaseline(
            project_id=uuid.UUID(project_id),
            scan_session_id=scan_session_id,
            total_findings=len(findings),
            findings_by_severity=severity_counts,
            findings_snapshot=list(fingerprints),
        )
        db.add(baseline)
        await db.commit()

        return {
            "id": str(baseline.id),
            "total_findings": len(findings),
            "findings_by_severity": severity_counts,
        }

    @staticmethod
    async def compare_with_latest(
        db,
        project_id: str,
        current_findings: list[dict],
    ) -> dict:
        """Compare current findings with the most recent baseline."""
        from app.models.sast_scan import DastBaseline
        from sqlalchemy import select, desc

        latest = (await db.execute(
            select(DastBaseline)
            .where(DastBaseline.project_id == uuid.UUID(project_id))
            .order_by(desc(DastBaseline.created_at))
            .limit(1)
        )).scalar_one_or_none()

        if not latest or not latest.findings_snapshot:
            return {
                "has_baseline": False,
                "new_findings": len(current_findings),
                "fixed_findings": 0,
                "unchanged_findings": 0,
            }

        prev_fps = set(latest.findings_snapshot) if isinstance(latest.findings_snapshot, list) else set()
        current_fps = set()
        for f in current_findings:
            fp = f.get("fingerprint") or f.get("title", "")
            current_fps.add(fp)

        new = current_fps - prev_fps
        fixed = prev_fps - current_fps
        unchanged = current_fps & prev_fps

        return {
            "has_baseline": True,
            "baseline_id": str(latest.id),
            "baseline_total": latest.total_findings,
            "new_findings": len(new),
            "fixed_findings": len(fixed),
            "unchanged_findings": len(unchanged),
            "trend": "improving" if len(fixed) > len(new) else (
                "stable" if len(new) == 0 else "degrading"
            ),
        }
