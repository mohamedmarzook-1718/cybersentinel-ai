"""Audit log router for compliance and tracking analyst actions."""
from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.audit import AuditLog
from app.schemas import AuditLogOut

router = APIRouter(tags=["audit"])


from app.core.deps import require_analyst_or_admin
from app.models.user import User

@router.get("", response_model=List[AuditLogOut])
def get_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    action: Optional[str] = None,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    return query.order_by(desc(AuditLog.created_at)).limit(limit).all()
