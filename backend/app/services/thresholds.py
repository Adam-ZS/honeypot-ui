"""Deciding whether a session is worth waking someone up for.

The settings page lets an admin create alert thresholds — a minimum severity,
an anomaly score, and which channels to notify — and the API stores them
faithfully. Nothing read them. The pipeline decided with a hardcoded
``severity in (HIGH, CRITICAL)``, so an operator could set a threshold, watch
it save, and never see it change a single alert.

That is worse than not offering the control: it is a setting that lies. This
module is what makes the stored rows the actual policy.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AlertThreshold, AttackSeverity

logger = logging.getLogger(__name__)

#: Ordering for "at least this severe". The enum is not ordered on its own.
SEVERITY_RANK = {
    AttackSeverity.LOW: 1,
    AttackSeverity.MEDIUM: 2,
    AttackSeverity.HIGH: 3,
    AttackSeverity.CRITICAL: 4,
}

#: What the pipeline did before thresholds were consulted. Used when no active
#: threshold exists, so a deployment that has never opened the settings page
#: keeps alerting exactly as it did rather than falling silent — a change that
#: would be invisible until the first missed intrusion.
DEFAULT_MIN_SEVERITY = AttackSeverity.HIGH


@dataclass
class AlertDecision:
    """Whether to raise, and through which channels."""

    should_alert: bool
    email: bool = False
    webhook: bool = False
    #: Which rule fired, for the audit trail and for the operator asking why.
    matched: list[str] = None

    def __post_init__(self) -> None:
        if self.matched is None:
            self.matched = []


def _matches(threshold: AlertThreshold, severity: AttackSeverity, anomaly: float) -> bool:
    """A threshold fires on severity *or* on anomaly score.

    Or, not and: an anomaly threshold exists precisely to catch the session
    that the severity heuristic scored low and should not have. Requiring both
    would make the anomaly setting unable to ever add an alert.
    """
    min_severity = threshold.min_severity or DEFAULT_MIN_SEVERITY
    if SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(min_severity, 99):
        return True
    limit = threshold.anomaly_score_threshold
    return limit is not None and anomaly >= limit


async def evaluate(
    db: AsyncSession, severity: AttackSeverity, anomaly_score: float
) -> AlertDecision:
    """Apply every active threshold to one session's verdict."""
    try:
        rows = (
            await db.execute(
                select(AlertThreshold).where(AlertThreshold.is_active.is_(True))
            )
        ).scalars().all()
    except Exception as exc:
        # A failure to read policy must not stop a detection being recorded.
        # Fall back to the built-in rule and say so.
        logger.warning("Could not read alert thresholds (%s); using the default", exc)
        rows = []

    if not rows:
        fires = SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK[DEFAULT_MIN_SEVERITY]
        return AlertDecision(
            should_alert=fires,
            email=fires,
            webhook=fires,
            matched=["default"] if fires else [],
        )

    matched = [t for t in rows if _matches(t, severity, anomaly_score or 0.0)]
    return AlertDecision(
        should_alert=bool(matched),
        # Channels union across the rules that fired: a rule that wants email
        # should get email even if another matching rule does not.
        email=any(t.email_enabled for t in matched),
        webhook=any(t.webhook_enabled for t in matched),
        matched=[t.name for t in matched],
    )
