from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional

from app.core.database import get_db
from app.core.security import get_current_user, require_role, verify_honeypot_token
from app.models import HoneypotSession, HoneypotNode, AuditLog, SessionStatus, AttackCategory, AttackerProfile
from app.schemas import HoneypotSessionResponse, SessionListResponse, SessionFilter
from app.api.export import FILE_EXTENSIONS, MEDIA_TYPES, _render
from app.services.analysis import analysis_pipeline
from app.services import enrichment

router = APIRouter()


def _escape_like(value: str) -> str:
    """Neutralise LIKE wildcards in user-supplied search text."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _parse_enum(enum_cls, value: str, field: str):
    """Map a query-string value onto an enum, or raise 400.

    Passing the raw value to the enum constructor made an unknown filter
    value raise ValueError, which surfaced to the client as a 500.
    """
    try:
        return enum_cls(value)
    except ValueError:
        allowed = ", ".join(member.value for member in enum_cls)
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field} {value!r}. Expected one of: {allowed}",
        )


@router.post("/ingest-internal", dependencies=[Depends(verify_honeypot_token)])
async def ingest_session_from_honeypot(
    session_data: dict,
    node_id: int = Query(1),
    db: AsyncSession = Depends(get_db),
):
    """Ingest a session from the honeypot engine (service-to-service)."""
    node_result = await db.execute(select(HoneypotNode).where(HoneypotNode.id == node_id))
    node = node_result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Honeypot node not found")

    result = await analysis_pipeline.process_session(db, session_data, node_id)

    audit = AuditLog(
        user_id=None,
        action="session_ingested_honeypot",
        resource_type="session",
        resource_id=result["session_id"],
        details={
            "category": result["ai_classification"]["category"],
            "source": "honeypot_engine",
        },
    )
    db.add(audit)
    await db.commit()

    # Stage 2 runs detached, after the response. It reads the stored
    # transcript and asks Chimera what the attacker was attempting; a slow or
    # absent model degrades the depth of analysis, never the capture.
    enrichment.schedule(result["session_id"])

    return result


@router.get("/", response_model=SessionListResponse)
async def list_sessions(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    attack_category: Optional[str] = None,
    attacker_profile: Optional[str] = None,
    country: Optional[str] = None,
    ip_address: Optional[str] = None,
    is_anomalous: Optional[bool] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(HoneypotSession)
    count_query = select(func.count(HoneypotSession.id))

    if status:
        parsed = _parse_enum(SessionStatus, status, "status")
        query = query.where(HoneypotSession.status == parsed)
        count_query = count_query.where(HoneypotSession.status == parsed)
    if attack_category:
        parsed = _parse_enum(AttackCategory, attack_category, "attack_category")
        query = query.where(HoneypotSession.attack_category == parsed)
        count_query = count_query.where(HoneypotSession.attack_category == parsed)
    if attacker_profile:
        parsed = _parse_enum(
            AttackerProfile, attacker_profile, "attacker_profile"
        )
        query = query.where(HoneypotSession.attacker_profile == parsed)
        count_query = count_query.where(
            HoneypotSession.attacker_profile == parsed
        )
    if country:
        query = query.where(HoneypotSession.geo_country == country.upper())
        count_query = count_query.where(HoneypotSession.geo_country == country.upper())
    if ip_address:
        pattern = f"%{_escape_like(ip_address)}%"
        query = query.where(HoneypotSession.attacker_ip.ilike(pattern, escape="\\"))
        count_query = count_query.where(
            HoneypotSession.attacker_ip.ilike(pattern, escape="\\")
        )
    if is_anomalous is not None:
        query = query.where(HoneypotSession.is_anomalous == is_anomalous)
        count_query = count_query.where(HoneypotSession.is_anomalous == is_anomalous)
    if search:
        pattern = f"%{_escape_like(search)}%"
        search_filter = (
            HoneypotSession.attacker_ip.ilike(pattern, escape="\\")
            | HoneypotSession.session_uuid.ilike(pattern, escape="\\")
            | HoneypotSession.command_summary.ilike(pattern, escape="\\")
        )
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(desc(HoneypotSession.started_at)).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    sessions = result.scalars().all()

    return SessionListResponse(
        sessions=[HoneypotSessionResponse.from_model(s) for s in sessions],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{session_id}", response_model=HoneypotSessionResponse)
async def get_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(HoneypotSession).where(HoneypotSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return HoneypotSessionResponse.from_model(session)


@router.get("/uuid/{session_uuid}", response_model=HoneypotSessionResponse)
async def get_session_by_uuid(
    session_uuid: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(HoneypotSession).where(HoneypotSession.session_uuid == session_uuid))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return HoneypotSessionResponse.from_model(session)


@router.post("/ingest")
async def ingest_session(
    session_data: dict,
    node_id: int = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("analyst")),
):
    node_result = await db.execute(select(HoneypotNode).where(HoneypotNode.id == node_id))
    node = node_result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Honeypot node not found")

    result = await analysis_pipeline.process_session(db, session_data, node_id)

    audit = AuditLog(
        user_id=current_user["id"],
        action="session_ingested",
        resource_type="session",
        resource_id=result["session_id"],
        details={"category": result["ai_classification"]["category"]},
    )
    db.add(audit)
    await db.commit()

    # Stage 2 runs detached, after the response. It reads the stored
    # transcript and asks Chimera what the attacker was attempting; a slow or
    # absent model degrades the depth of analysis, never the capture.
    enrichment.schedule(result["session_id"])

    return result


@router.post("/{session_id}/export")
async def export_session(
    session_id: int,
    format: str = Query("json", pattern="^(json|cef|stix)$"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("analyst")),
):
    result = await db.execute(select(HoneypotSession).where(HoneypotSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    content = _render(format, [session])
    return Response(
        content=content,
        media_type=MEDIA_TYPES[format],
        headers={
            "Content-Disposition": (
                f'attachment; filename="session_{session.session_uuid}'
                f'.{FILE_EXTENSIONS[format]}"'
            )
        },
    )
