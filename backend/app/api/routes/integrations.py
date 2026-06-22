"""GitHub integration webhooks."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException, Request, status

from app.services.github_pr_service import handle_pull_request_event, verify_github_signature

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/github", tags=["integrations"])


@router.post("/webhook", status_code=status.HTTP_200_OK)
async def github_webhook(request: Request) -> dict[str, str]:
  payload_bytes = await request.body()
  signature = request.headers.get("X-Hub-Signature-256")
  if not verify_github_signature(payload_bytes, signature):
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature")

  event = request.headers.get("X-GitHub-Event", "")
  try:
    payload = json.loads(payload_bytes)
  except json.JSONDecodeError as exc:
    raise HTTPException(status_code=400, detail="Invalid JSON") from exc

  if event == "pull_request":
    handle_pull_request_event(payload)
    return {"status": "accepted"}

  return {"status": "ignored", "event": event}
