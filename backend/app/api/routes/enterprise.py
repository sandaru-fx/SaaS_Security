from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import get_current_user
from app.database import get_db
from app.models.enterprise import (
    ApiKey,
    CustomRule,
    Organization,
    OrganizationMember,
    ScanSchedule,
)
from app.models.issue import Issue
from app.models.project import Project
from app.models.user import User
from app.schemas.enterprise import (
    ApiKeyCreate,
    ApiKeyCreatedResponse,
    ApiKeyResponse,
    CustomRuleCreate,
    CustomRuleResponse,
    IssueDismissRequest,
    MemberInvite,
    MemberResponse,
    NotificationSettings,
    OrganizationCreate,
    OrganizationResponse,
    ScheduleCreate,
    ScheduleResponse,
    WebhookUpdate,
)
from app.services import api_key_service, project_service
from app.services.enterprise_service import has_api_access, has_enterprise
from app.services.schedule_service import compute_next_run

MAX_TEAM_MEMBERS = 5

router = APIRouter(prefix="/enterprise", tags=["enterprise"])


def _require_enterprise(user: User) -> None:
    if not has_enterprise(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Team plan required for enterprise features.",
        )


def _require_api_access(user: User) -> None:
    if not has_api_access(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Pro or Team plan required for API access.",
        )


@router.post("/organizations", response_model=OrganizationResponse, status_code=201)
async def create_organization(
    payload: OrganizationCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Organization:
    _require_enterprise(current_user)
    org = Organization(
        name=payload.name,
        owner_id=current_user.id,
        brand_name=payload.brand_name,
    )
    db.add(org)
    await db.flush()
    db.add(
        OrganizationMember(
            organization_id=org.id,
            user_id=current_user.id,
            role="owner",
        )
    )
    await db.commit()
    await db.refresh(org)
    return org


@router.get("/organizations", response_model=list[OrganizationResponse])
async def list_organizations(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[Organization]:
    _require_enterprise(current_user)
    result = await db.execute(
        select(Organization)
        .join(OrganizationMember, OrganizationMember.organization_id == Organization.id)
        .where(OrganizationMember.user_id == current_user.id)
    )
    return list(result.scalars().unique().all())


@router.post("/organizations/{org_id}/members", response_model=MemberResponse, status_code=201)
async def invite_member(
    org_id: UUID,
    payload: MemberInvite,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> OrganizationMember:
    _require_enterprise(current_user)
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    count_result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.organization_id == org_id)
    )
    if len(list(count_result.scalars().all())) >= MAX_TEAM_MEMBERS:
        raise HTTPException(
            status_code=400,
            detail=f"Team plan allows up to {MAX_TEAM_MEMBERS} members per organization.",
        )

    dup = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.invited_email == payload.email,
        )
    )
    if dup.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Member already invited")

    user_result = await db.execute(select(User).where(User.email == payload.email))
    invited_user = user_result.scalar_one_or_none()

    member = OrganizationMember(
        organization_id=org_id,
        user_id=invited_user.id if invited_user else None,
        role=payload.role,
        invited_email=payload.email,
    )
    db.add(member)
    await db.commit()
    await db.refresh(member)
    return member


@router.get("/organizations/{org_id}/members", response_model=list[MemberResponse])
async def list_members(
    org_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[OrganizationMember]:
    _require_enterprise(current_user)
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.organization_id == org_id)
    )
    return list(result.scalars().all())


@router.delete("/organizations/{org_id}/members/{member_id}", status_code=204)
async def remove_member(
    org_id: UUID,
    member_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    _require_enterprise(current_user)
    org = await db.get(Organization, org_id)
    if not org or org.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Organization not found")

    member = await db.get(OrganizationMember, member_id)
    if not member or member.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Member not found")
    if member.user_id == current_user.id and member.role == "owner":
        raise HTTPException(status_code=400, detail="Owner cannot remove themselves")

    await db.delete(member)
    await db.commit()


@router.post("/api-keys", response_model=ApiKeyCreatedResponse, status_code=201)
async def create_api_key(
    payload: ApiKeyCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ApiKeyCreatedResponse:
    _require_api_access(current_user)
    record, full_key = await api_key_service.create_api_key_record(
        db, current_user, payload.name
    )
    return ApiKeyCreatedResponse(
        id=record.id,
        name=record.name,
        key_prefix=record.key_prefix,
        last_used_at=record.last_used_at,
        created_at=record.created_at,
        api_key=full_key,
    )


@router.get("/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[ApiKey]:
    _require_api_access(current_user)
    result = await db.execute(select(ApiKey).where(ApiKey.user_id == current_user.id))
    return list(result.scalars().all())


@router.delete("/api-keys/{key_id}", status_code=204)
async def delete_api_key(
    key_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    _require_api_access(current_user)
    key = await db.get(ApiKey, key_id)
    if not key or key.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="API key not found")
    await db.delete(key)
    await db.commit()


@router.post("/schedules", response_model=ScheduleResponse, status_code=201)
async def create_schedule(
    payload: ScheduleCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ScanSchedule:
    _require_enterprise(current_user)
    project = await project_service.get_user_project(db, current_user.id, payload.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    schedule = ScanSchedule(
        project_id=payload.project_id,
        user_id=current_user.id,
        frequency=payload.frequency,
        next_run_at=compute_next_run(payload.frequency),
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return schedule


@router.get("/schedules", response_model=list[ScheduleResponse])
async def list_schedules(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[ScanSchedule]:
    _require_enterprise(current_user)
    result = await db.execute(
        select(ScanSchedule).where(ScanSchedule.user_id == current_user.id)
    )
    return list(result.scalars().all())


@router.delete("/schedules/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    _require_enterprise(current_user)
    schedule = await db.get(ScanSchedule, schedule_id)
    if not schedule or schedule.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.delete(schedule)
    await db.commit()


@router.post("/custom-rules", response_model=CustomRuleResponse, status_code=201)
async def create_custom_rule(
    payload: CustomRuleCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> CustomRule:
    _require_enterprise(current_user)
    rule = CustomRule(
        user_id=current_user.id,
        name=payload.name,
        pattern=payload.pattern,
        category=payload.category,
        severity=payload.severity,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


@router.get("/custom-rules", response_model=list[CustomRuleResponse])
async def list_custom_rules(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[CustomRule]:
    _require_enterprise(current_user)
    result = await db.execute(select(CustomRule).where(CustomRule.user_id == current_user.id))
    return list(result.scalars().all())


@router.delete("/custom-rules/{rule_id}", status_code=204)
async def delete_custom_rule(
    rule_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    _require_enterprise(current_user)
    rule = await db.get(CustomRule, rule_id)
    if not rule or rule.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Custom rule not found")
    await db.delete(rule)
    await db.commit()


@router.patch("/notifications", response_model=NotificationSettings)
async def update_notifications(
    payload: NotificationSettings,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> NotificationSettings:
    current_user.email_alerts_enabled = payload.email_alerts_enabled
    await db.commit()
    return payload


@router.patch("/projects/{project_id}/webhook")
async def update_project_webhook(
    project_id: UUID,
    payload: WebhookUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    _require_enterprise(current_user)
    project = await project_service.get_user_project(db, current_user.id, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if payload.webhook_url is not None:
        project.webhook_url = payload.webhook_url or None
    if payload.webhook_secret is not None:
        project.webhook_secret = payload.webhook_secret or None
    await db.commit()
    return {"webhook_url": project.webhook_url, "configured": bool(project.webhook_url)}


@router.patch("/issues/{issue_id}/dismiss")
async def dismiss_issue(
    issue_id: UUID,
    payload: IssueDismissRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    from app.models.scan import Scan

    issue = await db.get(Issue, issue_id)
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    scan = await db.get(Scan, issue.scan_id)
    if not scan or scan.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Issue not found")

    issue.dismissed = True
    issue.dismissed_reason = payload.reason
    issue.dismissed_at = datetime.now(timezone.utc)
    await db.commit()
    return {"id": str(issue.id), "dismissed": True}
