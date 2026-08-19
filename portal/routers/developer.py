from __future__ import annotations

import hashlib
import logging
import secrets
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from portal.auth import require_user
from portal.database import get_db_session
from portal.models import DeveloperAccount, OAuthClient

logger = logging.getLogger(__name__)

router = APIRouter()

_BASE_DIR = Path(__file__).resolve().parent.parent.parent
templates = Jinja2Templates(directory=str(_BASE_DIR / "templates"))


@router.get("/developer", include_in_schema=False)
async def developer_dashboard(
    request: Request,
    user: dict = Depends(require_user),
    db: AsyncSession = Depends(get_db_session),
):
    result = await db.execute(select(DeveloperAccount).where(DeveloperAccount.user_id == int(user["sub"])))
    account = result.scalars().first()

    clients = []
    if account and account.status == "approved":
        client_result = await db.execute(select(OAuthClient).where(OAuthClient.developer_account_id == account.id))
        clients = client_result.scalars().all()

    return templates.TemplateResponse(
        request=request,
        name="developer/dashboard.html",
        context={
            "user": user,
            "account": account,
            "clients": clients,
        },
    )


@router.post("/api/developer/apply")
async def apply_for_developer(
    organization_name: str = Form(...),
    user: dict = Depends(require_user),
    db: AsyncSession = Depends(get_db_session),
):
    result = await db.execute(select(DeveloperAccount).where(DeveloperAccount.user_id == int(user["sub"])))
    existing = result.scalars().first()

    if existing:
        return RedirectResponse(url="/developer", status_code=status.HTTP_303_SEE_OTHER)

    account = DeveloperAccount(
        user_id=int(user["sub"]),
        status="pending",
        organization_name=organization_name,
    )
    db.add(account)
    await db.flush()

    return RedirectResponse(url="/developer", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/api/developer/clients")
async def create_oauth_client(
    request: Request,
    app_name: str = Form(...),
    redirect_uris: str = Form(...),
    user: dict = Depends(require_user),
    db: AsyncSession = Depends(get_db_session),
):
    result = await db.execute(select(DeveloperAccount).where(DeveloperAccount.user_id == int(user["sub"])))
    account = result.scalars().first()

    if not account or account.status != "approved":
        return RedirectResponse(url="/developer", status_code=status.HTTP_303_SEE_OTHER)

    uris = [uri.strip() for uri in redirect_uris.split(",") if uri.strip()]

    raw_client_id = f"client_{secrets.token_urlsafe(24)}"
    raw_secret = f"secret_{secrets.token_urlsafe(32)}"
    secret_hash = hashlib.sha256(raw_secret.encode()).hexdigest()

    client = OAuthClient(
        developer_account_id=account.id,
        client_id=raw_client_id,
        client_secret_hash=secret_hash,
        name=app_name,
        redirect_uris=uris,
    )
    db.add(client)
    await db.flush()

    # Re-fetch all clients to render the dashboard
    client_result = await db.execute(select(OAuthClient).where(OAuthClient.developer_account_id == account.id))
    clients = client_result.scalars().all()

    return templates.TemplateResponse(
        request=request,
        name="developer/dashboard.html",
        context={
            "user": user,
            "account": account,
            "clients": clients,
            "new_client": client,
            "new_secret": raw_secret,
        },
    )
