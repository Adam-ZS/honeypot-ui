"""Bulk export of captured sessions in SIEM-friendly formats."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_role
from app.models import AuditLog, HoneypotSession
from app.services.report_generator import report_generator

router = APIRouter()

#: A single export request should never be able to pull the entire dataset
#: into memory.
MAX_EXPORT_SESSIONS = 5000

MEDIA_TYPES = {
    "json": "application/json",
    "cef": "text/plain",
    "stix": "application/json",
}

FILE_EXTENSIONS = {"json": "json", "cef": "cef", "stix": "json"}


def _session_to_dict(session: HoneypotSession) -> dict:
    return {
        "session_uuid": session.session_uuid,
        "protocol": session.protocol or "unknown",
        "attacker_ip": session.attacker_ip,
        "attacker_port": session.attacker_port,
        "geo": {
            "country": session.geo_country,
            "country_name": session.geo_country_name,
            "city": session.geo_city,
            "lat": session.geo_lat,
            "lon": session.geo_lon,
        },
        "started_at": session.started_at.isoformat(),
        "ended_at": session.ended_at.isoformat() if session.ended_at else None,
        "duration_seconds": session.duration_seconds,
        "status": session.status.value,
        "uploads": session.uploaded_files or [],
    }


def _session_to_analysis(session: HoneypotSession) -> dict:
    return {
        "category": (
            session.attack_category.value if session.attack_category else "unknown"
        ),
        "confidence": session.attack_confidence,
        "profile": (
            session.attacker_profile.value
            if session.attacker_profile
            else "unknown"
        ),
        "anomaly_score": session.anomaly_score,
        "is_anomalous": session.is_anomalous,
        "detected_tools": session.detected_tools or [],
        "detected_intents": session.detected_intents or [],
        "command_count": session.command_count or 0,
        "mitre": {
            "tactics": session.mitre_tactics or [],
            "techniques": session.mitre_techniques or [],
        },
    }


@router.post("/")
async def export_sessions(
    format: str = Query("json", pattern="^(json|cef|stix)$"),
    session_ids: Optional[list[int]] = Query(None),
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    # Exports contain full attacker telemetry, so they are not a read-only
    # viewer capability.
    current_user: dict = Depends(require_role("analyst")),
):
    query = select(HoneypotSession)

    if session_ids:
        if len(session_ids) > MAX_EXPORT_SESSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"At most {MAX_EXPORT_SESSIONS} sessions per export",
            )
        query = query.where(HoneypotSession.id.in_(session_ids))
    if date_from:
        query = query.where(HoneypotSession.started_at >= date_from)
    if date_to:
        query = query.where(HoneypotSession.started_at <= date_to)

    query = query.order_by(HoneypotSession.started_at.desc()).limit(
        MAX_EXPORT_SESSIONS
    )
    sessions = (await db.execute(query)).scalars().all()

    content = _render(format, sessions)

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="sessions_exported",
            resource_type="session",
            details={"format": format, "count": len(sessions)},
        )
    )
    await db.commit()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"honeysentinel_export_{stamp}.{FILE_EXTENSIONS[format]}"

    return Response(
        content=content,
        media_type=MEDIA_TYPES[format],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _render(format: str, sessions: list[HoneypotSession]) -> str:
    """Serialise sessions in the requested format.

    `import json` used to sit *inside* the branches of this function, which
    made `json` a function-local name everywhere — so the default JSON branch
    raised UnboundLocalError before reaching its own import, and every plain
    export returned a 500.
    """
    pairs = [
        (_session_to_dict(session), _session_to_analysis(session))
        for session in sessions
    ]

    if format == "cef":
        return "\n".join(
            report_generator.generate_cef_report(data, analysis)
            for data, analysis in pairs
        )

    if format == "stix":
        objects = []
        for data, analysis in pairs:
            try:
                bundle = json.loads(
                    report_generator.generate_stix_report(data, analysis)
                )
            except (json.JSONDecodeError, ValueError):
                continue
            objects.extend(bundle.get("objects", []))
        return json.dumps(
            {"type": "bundle", "id": "bundle--1", "objects": objects}, indent=2
        )

    reports = [
        json.loads(report_generator.generate_json_report(data, analysis))
        for data, analysis in pairs
    ]
    return json.dumps(reports, indent=2, default=str)
