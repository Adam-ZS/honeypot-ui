from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models import Alert, AlertStatus, AttackSeverity, AuditLog, User
from app.schemas import AlertResponse, AlertListResponse, AlertUpdate

router = APIRouter()


def _parse_enum(enum_cls, value: str, field: str):
    try:
        return enum_cls(value)
    except ValueError:
        allowed = ", ".join(member.value for member in enum_cls)
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field} {value!r}. Expected one of: {allowed}",
        )


def _to_response(alert: Alert) -> AlertResponse:
    return _to_response(alert)


@router.get("/", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(Alert)
    count_query = select(func.count(Alert.id))

    if severity:
        parsed = _parse_enum(AttackSeverity, severity, "severity")
        query = query.where(Alert.severity == parsed)
        count_query = count_query.where(Alert.severity == parsed)
    if status:
        parsed = _parse_enum(AlertStatus, status, "status")
        query = query.where(Alert.status == parsed)
        count_query = count_query.where(Alert.status == parsed)

    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(desc(Alert.created_at)).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return AlertListResponse(
        alerts=[_to_response(a) for a in alerts],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/stats")
async def alert_stats(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    new_q = select(func.count(Alert.id)).where(Alert.status == AlertStatus.NEW)
    new_count = (await db.execute(new_q)).scalar() or 0

    ack_q = select(func.count(Alert.id)).where(Alert.status == AlertStatus.ACKNOWLEDGED)
    ack_count = (await db.execute(ack_q)).scalar() or 0

    resolved_q = select(func.count(Alert.id)).where(Alert.status.in_([AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]))
    resolved_count = (await db.execute(resolved_q)).scalar() or 0

    severity_q = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    severity_result = await db.execute(severity_q)
    severity_dist = {s.value: c for s, c in severity_result.all()}

    return {
        "new": new_count,
        "acknowledged": ack_count,
        "resolved": resolved_count,
        "by_severity": severity_dist,
    }


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return _to_response(alert)


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    update_data: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("analyst")),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if update_data.assigned_to_id is not None:
        assignee = await db.execute(
            select(User.id).where(User.id == update_data.assigned_to_id)
        )
        if assignee.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=400, detail="Assigned user does not exist"
            )

    if update_data.status is not None:
        alert.status = AlertStatus(update_data.status)
        if update_data.status == AlertStatus.ACKNOWLEDGED:
            alert.acknowledged_at = datetime.now(timezone.utc)
        elif update_data.status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
            alert.resolved_at = datetime.now(timezone.utc)

    if update_data.assigned_to_id is not None:
        alert.assigned_to_id = update_data.assigned_to_id

    audit = AuditLog(
        user_id=current_user["id"],
        action="alert_updated",
        resource_type="alert",
        resource_id=alert.id,
        details={"status": alert.status.value},
    )
    db.add(audit)
    await db.commit()
    await db.refresh(alert)

    return _to_response(alert)
