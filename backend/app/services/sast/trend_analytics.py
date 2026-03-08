"""Trend analytics — track security metrics over time, compare scan baselines.

Provides:
- Scan-to-scan delta comparison (new/fixed/unchanged findings)
- Historical trend data for frontend charts
- Security debt tracking (MTTR, fix rate, issues per KLOC)
- Alert thresholds for security regression detection
"""

from __future__ import annotations

import logging
import uuid as _uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import select, func, and_, desc

logger = logging.getLogger(__name__)

# ── Default Thresholds ───────────────────────────────────────────────
# If a scan introduces more than these counts of new issues, flag a regression.
DEFAULT_REGRESSION_THRESHOLDS: dict[str, int] = {
    "critical": 1,   # any new critical = regression
    "high": 3,
    "medium": 10,
    "low": 25,
}

# Severity weights for composite scoring
SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "info": 0.1,
}


def _fingerprint_set(findings: list[dict]) -> dict[str, dict]:
    """Build a fingerprint -> finding map for delta comparison."""
    result: dict[str, dict] = {}
    for f in findings:
        fp = f.get("fingerprint") or ""
        if fp:
            result[fp] = f
        else:
            # Fallback: compose a pseudo-fingerprint from rule+file+line
            pseudo = f"{f.get('rule_id', '')}:{f.get('file_path', '')}:{f.get('line_start', 0)}"
            result[pseudo] = f
    return result


class TrendAnalyzer:
    """Track security metrics over time and detect regressions.

    All database access uses ``AsyncSessionLocal`` and the
    ``SastScanSession`` / ``SastFinding`` models.

    Usage::

        analyzer = TrendAnalyzer()
        delta = await analyzer.compare_scans(scan_a_id, scan_b_id)
        trends = await analyzer.get_project_trends(project_id, days=90)
    """

    # ── Scan-to-Scan Delta ───────────────────────────────────────────

    @staticmethod
    async def compare_scans(
        scan_a_id: str,
        scan_b_id: str,
    ) -> dict:
        """Compare two scans and produce a delta report.

        *scan_a* is treated as the **baseline** (older) and *scan_b* as the
        **current** scan.  The result includes new, fixed, and unchanged
        findings.

        Args:
            scan_a_id: UUID of the baseline scan session.
            scan_b_id: UUID of the current scan session.

        Returns:
            ``{"new": [...], "fixed": [...], "unchanged": [...], "summary": {...}}``
        """
        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastFinding

            async with AsyncSessionLocal() as db:
                # Load findings for both scans
                result_a = await db.execute(
                    select(SastFinding).where(
                        SastFinding.scan_session_id == _uuid.UUID(scan_a_id)
                    )
                )
                findings_a = result_a.scalars().all()

                result_b = await db.execute(
                    select(SastFinding).where(
                        SastFinding.scan_session_id == _uuid.UUID(scan_b_id)
                    )
                )
                findings_b = result_b.scalars().all()

            # Convert to dicts for comparison
            def _to_dict(f: Any) -> dict:
                return {
                    "id": str(f.id),
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "file_path": f.file_path,
                    "line_start": f.line_start,
                    "line_end": f.line_end,
                    "status": f.status,
                    "cwe_id": f.cwe_id,
                    "fingerprint": f.fingerprint,
                    "rule_source": f.rule_source,
                }

            dicts_a = [_to_dict(f) for f in findings_a]
            dicts_b = [_to_dict(f) for f in findings_b]

            fps_a = _fingerprint_set(dicts_a)
            fps_b = _fingerprint_set(dicts_b)

            keys_a = set(fps_a.keys())
            keys_b = set(fps_b.keys())

            new_keys = keys_b - keys_a
            fixed_keys = keys_a - keys_b
            unchanged_keys = keys_a & keys_b

            new_findings = [fps_b[k] for k in new_keys]
            fixed_findings = [fps_a[k] for k in fixed_keys]
            unchanged_findings = [fps_b[k] for k in unchanged_keys]

            # Severity breakdown for new issues
            new_by_severity = defaultdict(int)
            for nf in new_findings:
                new_by_severity[nf.get("severity", "info")] += 1

            fixed_by_severity = defaultdict(int)
            for ff in fixed_findings:
                fixed_by_severity[ff.get("severity", "info")] += 1

            return {
                "baseline_scan_id": scan_a_id,
                "current_scan_id": scan_b_id,
                "baseline_total": len(dicts_a),
                "current_total": len(dicts_b),
                "new_count": len(new_findings),
                "fixed_count": len(fixed_findings),
                "unchanged_count": len(unchanged_findings),
                "new_by_severity": dict(new_by_severity),
                "fixed_by_severity": dict(fixed_by_severity),
                "net_change": len(dicts_b) - len(dicts_a),
                "new": sorted(new_findings, key=lambda f: SEVERITY_WEIGHT.get(f.get("severity", "info"), 0), reverse=True),
                "fixed": sorted(fixed_findings, key=lambda f: SEVERITY_WEIGHT.get(f.get("severity", "info"), 0), reverse=True),
                "unchanged": unchanged_findings,
            }

        except Exception as exc:
            logger.exception("compare_scans failed: %s", exc)
            return {
                "error": str(exc),
                "baseline_scan_id": scan_a_id,
                "current_scan_id": scan_b_id,
                "new_count": 0,
                "fixed_count": 0,
                "unchanged_count": 0,
            }

    # ── Historical Trends ────────────────────────────────────────────

    @staticmethod
    async def get_project_trends(
        project_id: str,
        days: int = 90,
    ) -> dict:
        """Retrieve historical trend data for the last *days* days.

        Queries completed scan sessions and aggregates metrics per scan for
        frontend charting.

        Returns:
            ``{"data_points": [...], "summary": {...}}``
        """
        cutoff = datetime.utcnow() - timedelta(days=days)

        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastScanSession, SastFinding

            async with AsyncSessionLocal() as db:
                # Get completed scans in the period
                result = await db.execute(
                    select(SastScanSession)
                    .where(
                        SastScanSession.project_id == _uuid.UUID(project_id),
                        SastScanSession.status == "completed",
                        SastScanSession.created_at >= cutoff,
                    )
                    .order_by(SastScanSession.created_at.asc())
                )
                scans = result.scalars().all()

                data_points: list[dict] = []
                prev_fps: set[str] = set()

                for scan in scans:
                    # Get findings for this scan
                    findings_result = await db.execute(
                        select(SastFinding).where(
                            SastFinding.scan_session_id == scan.id
                        )
                    )
                    findings = findings_result.scalars().all()

                    # Severity distribution
                    sev_dist: dict[str, int] = defaultdict(int)
                    current_fps: set[str] = set()
                    for f in findings:
                        sev_dist[f.severity or "info"] += 1
                        fp = f.fingerprint or f"{f.rule_id}:{f.file_path}:{f.line_start}"
                        current_fps.add(fp)

                    # Delta vs previous scan
                    new_count = len(current_fps - prev_fps) if prev_fps else 0
                    fixed_count = len(prev_fps - current_fps) if prev_fps else 0

                    # Weighted security score (lower = better)
                    security_score = sum(
                        sev_dist.get(sev, 0) * weight
                        for sev, weight in SEVERITY_WEIGHT.items()
                    )

                    # Issues per KLOC
                    total_files = scan.total_files or 0
                    # Rough estimate: avg 50 lines per file
                    estimated_kloc = (total_files * 50) / 1000 if total_files else 0
                    issues_per_kloc = (
                        round(len(findings) / estimated_kloc, 2)
                        if estimated_kloc > 0
                        else 0
                    )

                    data_points.append({
                        "scan_id": str(scan.id),
                        "scan_date": scan.created_at.isoformat(),
                        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                        "total_issues": len(findings),
                        "severity_distribution": dict(sev_dist),
                        "new_issues": new_count,
                        "fixed_issues": fixed_count,
                        "net_change": new_count - fixed_count,
                        "security_score": round(security_score, 1),
                        "issues_per_kloc": issues_per_kloc,
                        "total_files": total_files,
                        "scan_duration_seconds": scan.scan_duration_seconds,
                    })

                    prev_fps = current_fps

            # Compute summary
            if data_points:
                latest = data_points[-1]
                earliest = data_points[0]
                total_change = latest["total_issues"] - earliest["total_issues"]
                avg_issues = round(
                    sum(dp["total_issues"] for dp in data_points) / len(data_points),
                    1,
                )
            else:
                total_change = 0
                avg_issues = 0

            return {
                "project_id": project_id,
                "period_days": days,
                "scan_count": len(data_points),
                "data_points": data_points,
                "summary": {
                    "total_change": total_change,
                    "average_issues": avg_issues,
                    "trend_direction": (
                        "improving" if total_change < 0
                        else "worsening" if total_change > 0
                        else "stable"
                    ),
                },
            }

        except Exception as exc:
            logger.exception("get_project_trends failed: %s", exc)
            return {
                "project_id": project_id,
                "period_days": days,
                "scan_count": 0,
                "data_points": [],
                "error": str(exc),
            }

    # ── Mean Time to Remediate ───────────────────────────────────────

    @staticmethod
    async def calculate_mttr(project_id: str) -> dict:
        """Calculate Mean Time to Remediate for a project.

        MTTR is computed from findings that have been moved to ``fixed``
        status, measuring the time from ``created_at`` to the latest audit
        trail entry showing the fix.

        Returns:
            ``{"mttr_days": float, "mttr_by_severity": {...}, "sample_size": int}``
        """
        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastFinding

            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(SastFinding).where(
                        SastFinding.project_id == _uuid.UUID(project_id),
                        SastFinding.status == "fixed",
                    )
                )
                fixed_findings = result.scalars().all()

            if not fixed_findings:
                return {
                    "project_id": project_id,
                    "mttr_days": None,
                    "mttr_by_severity": {},
                    "sample_size": 0,
                }

            remediation_times: dict[str, list[float]] = defaultdict(list)

            for f in fixed_findings:
                created = f.created_at
                # Try to get fix timestamp from audit trail
                fix_time = None
                ai = f.ai_analysis or {}
                if isinstance(ai, dict):
                    trail = ai.get("lifecycle_audit", [])
                    for entry in reversed(trail):
                        if entry.get("new_status") == "fixed":
                            try:
                                fix_time = datetime.fromisoformat(
                                    entry["timestamp"]
                                )
                            except (ValueError, KeyError, TypeError):
                                pass
                            break

                if fix_time is None:
                    # Fallback: use a heuristic — assume fixed around now
                    # This is imprecise but better than excluding the data point
                    fix_time = datetime.utcnow()

                delta_days = (fix_time - created).total_seconds() / 86400
                if delta_days < 0:
                    delta_days = 0

                sev = f.severity or "medium"
                remediation_times[sev].append(delta_days)
                remediation_times["_all"].append(delta_days)

            # Compute averages
            all_times = remediation_times.pop("_all", [])
            overall_mttr = round(sum(all_times) / len(all_times), 1) if all_times else 0

            mttr_by_severity: dict[str, dict] = {}
            for sev, times in remediation_times.items():
                mttr_by_severity[sev] = {
                    "mttr_days": round(sum(times) / len(times), 1),
                    "min_days": round(min(times), 1),
                    "max_days": round(max(times), 1),
                    "sample_size": len(times),
                }

            return {
                "project_id": project_id,
                "mttr_days": overall_mttr,
                "mttr_by_severity": mttr_by_severity,
                "sample_size": len(all_times),
            }

        except Exception as exc:
            logger.exception("calculate_mttr failed: %s", exc)
            return {
                "project_id": project_id,
                "mttr_days": None,
                "error": str(exc),
            }

    # ── Fix Rate ─────────────────────────────────────────────────────

    @staticmethod
    async def calculate_fix_rate(project_id: str) -> dict:
        """Calculate the fix rate percentage for a project.

        Fix rate = fixed / (fixed + open + confirmed + in_progress) * 100

        Returns:
            ``{"fix_rate_pct": float, "by_severity": {...}, "counts": {...}}``
        """
        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastFinding

            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(
                        SastFinding.status,
                        SastFinding.severity,
                        func.count(SastFinding.id),
                    )
                    .where(
                        SastFinding.project_id == _uuid.UUID(project_id),
                    )
                    .group_by(SastFinding.status, SastFinding.severity)
                )
                rows = result.all()

            # Aggregate counts
            counts: dict[str, int] = defaultdict(int)
            sev_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

            for status, severity, count in rows:
                counts[status or "open"] += count
                sev_counts[severity or "medium"][status or "open"] += count

            fixed = counts.get("fixed", 0)
            # Total actionable (excluding false_positive, ignored, wont_fix)
            actionable = fixed + counts.get("open", 0) + counts.get("confirmed", 0) + counts.get("in_progress", 0)

            overall_rate = round(fixed / actionable * 100, 1) if actionable > 0 else 0.0

            by_severity: dict[str, dict] = {}
            for sev, status_map in sev_counts.items():
                sev_fixed = status_map.get("fixed", 0)
                sev_actionable = (
                    sev_fixed
                    + status_map.get("open", 0)
                    + status_map.get("confirmed", 0)
                    + status_map.get("in_progress", 0)
                )
                by_severity[sev] = {
                    "fix_rate_pct": round(sev_fixed / sev_actionable * 100, 1) if sev_actionable > 0 else 0.0,
                    "fixed": sev_fixed,
                    "actionable": sev_actionable,
                }

            return {
                "project_id": project_id,
                "fix_rate_pct": overall_rate,
                "by_severity": by_severity,
                "counts": dict(counts),
                "total_actionable": actionable,
                "total_fixed": fixed,
            }

        except Exception as exc:
            logger.exception("calculate_fix_rate failed: %s", exc)
            return {
                "project_id": project_id,
                "fix_rate_pct": None,
                "error": str(exc),
            }

    # ── Regression Detection ─────────────────────────────────────────

    @staticmethod
    async def detect_regression(
        project_id: str,
        current_scan_id: str,
        thresholds: dict[str, int] | None = None,
    ) -> dict:
        """Detect if the current scan represents a security regression.

        Compares the current scan against the most recent previous completed
        scan for the same project.  If new critical/high findings exceed the
        configured thresholds, a regression alert is raised.

        Args:
            project_id: UUID of the project.
            current_scan_id: UUID of the current scan session.
            thresholds: Optional per-severity thresholds; defaults to
                ``DEFAULT_REGRESSION_THRESHOLDS``.

        Returns:
            ``{"is_regression": bool, "alerts": [...], "delta": {...}}``
        """
        if thresholds is None:
            thresholds = DEFAULT_REGRESSION_THRESHOLDS

        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastScanSession, SastFinding

            async with AsyncSessionLocal() as db:
                # Find the previous completed scan
                result = await db.execute(
                    select(SastScanSession)
                    .where(
                        SastScanSession.project_id == _uuid.UUID(project_id),
                        SastScanSession.status == "completed",
                        SastScanSession.id != _uuid.UUID(current_scan_id),
                    )
                    .order_by(desc(SastScanSession.created_at))
                    .limit(1)
                )
                prev_scan = result.scalar_one_or_none()

                if prev_scan is None:
                    return {
                        "project_id": project_id,
                        "current_scan_id": current_scan_id,
                        "is_regression": False,
                        "reason": "No previous scan to compare against",
                        "alerts": [],
                    }

                prev_scan_id = str(prev_scan.id)

            # Use compare_scans for the delta
            analyzer = TrendAnalyzer()
            delta = await analyzer.compare_scans(prev_scan_id, current_scan_id)

            if "error" in delta:
                return {
                    "project_id": project_id,
                    "current_scan_id": current_scan_id,
                    "is_regression": False,
                    "error": delta["error"],
                    "alerts": [],
                }

            # Check thresholds
            new_by_severity = delta.get("new_by_severity", {})
            alerts: list[dict] = []

            for sev, threshold in thresholds.items():
                new_count = new_by_severity.get(sev, 0)
                if new_count >= threshold:
                    alerts.append({
                        "severity": sev,
                        "new_count": new_count,
                        "threshold": threshold,
                        "message": (
                            f"Regression: {new_count} new {sev} finding(s) "
                            f"(threshold: {threshold})"
                        ),
                    })

            is_regression = len(alerts) > 0

            return {
                "project_id": project_id,
                "current_scan_id": current_scan_id,
                "previous_scan_id": prev_scan_id,
                "is_regression": is_regression,
                "alerts": alerts,
                "delta_summary": {
                    "new_count": delta.get("new_count", 0),
                    "fixed_count": delta.get("fixed_count", 0),
                    "net_change": delta.get("net_change", 0),
                    "new_by_severity": new_by_severity,
                },
            }

        except Exception as exc:
            logger.exception("detect_regression failed: %s", exc)
            return {
                "project_id": project_id,
                "current_scan_id": current_scan_id,
                "is_regression": False,
                "error": str(exc),
                "alerts": [],
            }

    # ── Trend Snapshot ───────────────────────────────────────────────

    @staticmethod
    async def generate_trend_snapshot(
        project_id: str,
        scan_id: str,
    ) -> dict:
        """Generate and store a trend data point for a completed scan.

        This method is intended to be called after each scan completes.  It
        computes all trend metrics and returns them as a dict suitable for
        storage in the ``DastBaseline`` table or a dedicated trends table.

        Returns:
            A dict with keys: total_issues, new_issues, fixed_issues,
            mttr_days, fix_rate_pct, issues_per_kloc, severity_distribution,
            security_score.
        """
        try:
            from app.core.database import AsyncSessionLocal
            from app.models.sast_scan import SastScanSession, SastFinding

            async with AsyncSessionLocal() as db:
                # Load current scan
                scan_result = await db.execute(
                    select(SastScanSession).where(
                        SastScanSession.id == _uuid.UUID(scan_id)
                    )
                )
                scan = scan_result.scalar_one_or_none()
                if scan is None:
                    return {"error": "Scan not found"}

                # Load findings
                findings_result = await db.execute(
                    select(SastFinding).where(
                        SastFinding.scan_session_id == _uuid.UUID(scan_id)
                    )
                )
                findings = findings_result.scalars().all()

            # Severity distribution
            sev_dist: dict[str, int] = defaultdict(int)
            for f in findings:
                sev_dist[f.severity or "info"] += 1

            # Security score
            security_score = sum(
                sev_dist.get(sev, 0) * weight
                for sev, weight in SEVERITY_WEIGHT.items()
            )

            # Issues per KLOC
            total_files = scan.total_files or 0
            estimated_kloc = (total_files * 50) / 1000 if total_files else 0
            issues_per_kloc = (
                round(len(findings) / estimated_kloc, 2) if estimated_kloc > 0 else 0
            )

            # Get delta vs previous scan
            analyzer = TrendAnalyzer()
            regression = await analyzer.detect_regression(project_id, scan_id)
            delta_summary = regression.get("delta_summary", {})

            # MTTR and fix rate
            mttr = await analyzer.calculate_mttr(project_id)
            fix_rate = await analyzer.calculate_fix_rate(project_id)

            snapshot = {
                "project_id": project_id,
                "scan_id": scan_id,
                "timestamp": datetime.utcnow().isoformat(),
                "total_issues": len(findings),
                "new_issues": delta_summary.get("new_count", 0),
                "fixed_issues": delta_summary.get("fixed_count", 0),
                "net_change": delta_summary.get("net_change", 0),
                "severity_distribution": dict(sev_dist),
                "security_score": round(security_score, 1),
                "issues_per_kloc": issues_per_kloc,
                "mttr_days": mttr.get("mttr_days"),
                "fix_rate_pct": fix_rate.get("fix_rate_pct"),
                "is_regression": regression.get("is_regression", False),
                "regression_alerts": regression.get("alerts", []),
                "total_files": total_files,
                "scan_duration_seconds": scan.scan_duration_seconds,
            }

            logger.info(
                "Trend snapshot for project %s scan %s: %d issues, score=%.1f, "
                "MTTR=%s days, fix_rate=%s%%",
                project_id,
                scan_id,
                len(findings),
                security_score,
                mttr.get("mttr_days", "N/A"),
                fix_rate.get("fix_rate_pct", "N/A"),
            )

            return snapshot

        except Exception as exc:
            logger.exception("generate_trend_snapshot failed: %s", exc)
            return {"error": str(exc), "project_id": project_id, "scan_id": scan_id}
