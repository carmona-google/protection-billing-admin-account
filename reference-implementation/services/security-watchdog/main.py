"""
Real-Time Billing Security Watchdog & 15-Minute Drift Reconciler (v1.0)
-----------------------------------------------------------------------
Implements the HLD Section 8 Asymmetric Two-Tier Remediation Policy:
  - Tier 1A (Unregistered / External Project Linked):
      Checks `approved_project_bindings` AND active `LINKING_LEASE_ACQUIRED` leases.
      If unapproved:
        * DRY_RUN mode: Logs P1 alert without detaching (used during Phase 1-3 backfill).
        * ENFORCE mode: Detaches billing (`billingAccountName=""`) in <10s and logs P1 incident.
  - Tier 1B (Unauthorized Billing IAM SetIamPolicy):
      Detects external consumer accounts (@gmail.com) or unapproved roles/billing.admin &
      roles/billing.user bindings on Partner subaccounts and triggers immediate P1 SecOps alert.
  - 15-Minute Reconciler (`/internal/reconcile`):
      Enumerates live subaccount bindings via Cloud Billing API to defeat missed Pub/Sub events.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from datetime import datetime, timezone

import google.auth
import google.auth.transport.requests
import httpx
from fastapi import FastAPI, Request
from google.cloud import firestore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("security-watchdog")

FIRESTORE_PROJECT_ID = os.environ.get("FIRESTORE_PROJECT_ID")
WATCHDOG_MODE = os.environ.get("WATCHDOG_MODE", "DRY_RUN")  # DRY_RUN | ENFORCE
LINKERS_PROJECT_ID = os.environ.get("LINKERS_PROJECT_ID", "partner-billing-linkers-prod")
ALLOWED_BILLING_PRINCIPALS = {
    p.strip().lower()
    for p in os.environ.get("ALLOWED_BILLING_PRINCIPALS", "").split(",")
    if p.strip()
}
GCP_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

app = FastAPI(title="Partner Billing Security Watchdog", version="1.1.0")
_db: firestore.AsyncClient | None = None


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "billing-security-watchdog", "mode": WATCHDOG_MODE}


def is_authorized_billing_member(member: str) -> bool:
    """
    Strictly allows ONLY:
      1. Per-tenant Linker SAs inside the Partner's isolated Linkers project (`sa-linker-*@<LINKERS_PROJECT_ID>.iam.gserviceaccount.com`)
      2. Explicitly allowlisted Partner PAM groups / principals (`ALLOWED_BILLING_PRINCIPALS`)
    Blocks @gmail.com AND any external attacker `.iam.gserviceaccount.com` service accounts.
    """
    normalized = member.strip().lower()
    if normalized in ALLOWED_BILLING_PRINCIPALS:
        return True
    expected_sa_suffix = f"@{LINKERS_PROJECT_ID.lower()}.iam.gserviceaccount.com"
    return normalized.startswith("serviceaccount:sa-linker-") and normalized.endswith(expected_sa_suffix)


def get_db() -> firestore.AsyncClient:
    global _db
    if _db is None:
        _db = firestore.AsyncClient(project=FIRESTORE_PROJECT_ID)
    return _db


def _get_watchdog_token() -> str:
    creds, _ = google.auth.default(scopes=GCP_SCOPES)
    creds.refresh(google.auth.transport.requests.Request())
    return creds.token


async def is_project_authorized_or_leased(db: firestore.AsyncClient, project_id: str, subaccount_id: str) -> bool:
    """Returns True if `project_id` has an ACTIVE binding OR an unexpired write-ahead LINKING lease."""
    binding_snap = await db.collection("approved_project_bindings").document(project_id).get()
    if binding_snap.exists:
        b = binding_snap.to_dict()
        if b.get("status") == "ACTIVE" and b.get("billing_subaccount_id") == subaccount_id:
            return True

    # Check active write-ahead lease to avoid racing with in-flight Broker links
    now = datetime.now(timezone.utc)
    leases = (
        await db.collection("link_requests")
        .where("project_id", "==", project_id)
        .where("state", "==", "LINKING_LEASE_ACQUIRED")
        .get()
    )
    for lease_doc in leases:
        exp = lease_doc.to_dict().get("lease_expires_at")
        if exp and exp > now:
            return True

    return False


async def emergency_unlink_rogue_project(
    db: firestore.AsyncClient,
    project_id: str,
    subaccount_id: str,
    actor_email: str,
    detection_source: str,
) -> str:
    """Executes Tier 1A <10s auto-unlink (or logs DRY_RUN alert) for unregistered projects."""
    action_taken = "DRY_RUN_ALERT_ONLY"

    if WATCHDOG_MODE == "ENFORCE":
        token = await asyncio.to_thread(_get_watchdog_token)
        url = f"https://cloudbilling.googleapis.com/v1/projects/{project_id}/billingInfo"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.put(
                url,
                headers={"Authorization": f"Bearer {token}"},
                json={"billingAccountName": ""},
            )
            if resp.status_code == 200:
                action_taken = "AUTO_UNLINKED"
                logger.critical(
                    "TIER-1A ENFORCE: Auto-unlinked unauthorized project=%s from subaccount=%s (actor=%s)",
                    project_id,
                    subaccount_id,
                    actor_email,
                )
            else:
                action_taken = f"UNLINK_FAILED_HTTP_{resp.status_code}"
                logger.error("Failed to auto-unlink %s: %s", project_id, resp.text)
    else:
        logger.warning(
            "TIER-1A DRY_RUN: Would have unlinked unauthorized project=%s from subaccount=%s (actor=%s)",
            project_id,
            subaccount_id,
            actor_email,
        )

    await db.collection("security_incidents").add(
        {
            "billing_subaccount_id": subaccount_id,
            "project_id": project_id,
            "actor_email": actor_email,
            "severity": "P1_CRITICAL",
            "incident_type": "ROGUE_EXTERNAL_LINK",
            "detection_source": detection_source,
            "auto_action_taken": action_taken,
            "detected_at": datetime.now(timezone.utc),
        }
    )
    return action_taken


@app.post("/events/audit-log")
async def handle_audit_log_push(request: Request):
    """Handles Eventarc / PubSub push messages from the Org-level Cloud Billing Audit Sink."""
    envelope = await request.json()
    msg = envelope.get("message", {})
    raw_data = msg.get("data")
    if not raw_data:
        return {"status": "ignored_empty"}

    log_entry = json.loads(base64.b64decode(raw_data).decode("utf-8"))
    proto = log_entry.get("protoPayload", {})
    method_name = proto.get("methodName", "")
    actor_email = proto.get("authenticationInfo", {}).get("principalEmail", "unknown")
    db = get_db()

    # Case 1: Project Billing Attachment (`UpdateProjectBillingInfo`)
    if "UpdateProjectBillingInfo" in method_name:
        req_body = proto.get("request", {})
        resp_body = proto.get("response", {})
        project_resource = req_body.get("name") or resp_body.get("name", "")
        billing_acct = resp_body.get("billingAccountName") or req_body.get(
            "projectBillingInfo", {}
        ).get("billingAccountName", "")

        # Ignore unlinking events (empty billingAccountName)
        if not billing_acct or not project_resource.startswith("projects/"):
            return {"status": "ignored_unlink_event"}

        project_id = project_resource.split("/")[1]
        subaccount_id = billing_acct.split("/")[1]

        if await is_project_authorized_or_leased(db, project_id, subaccount_id):
            logger.info("Verified authorized Broker link: project=%s subaccount=%s", project_id, subaccount_id)
            return {"status": "authorized"}

        action = await emergency_unlink_rogue_project(
            db=db,
            project_id=project_id,
            subaccount_id=subaccount_id,
            actor_email=actor_email,
            detection_source="REALTIME_AUDIT_SINK",
        )
        return {"status": "remediated", "action": action, "projectId": project_id}

    # Case 2: Billing IAM Modification (`SetIamPolicy`) -> Tier 1B Detection
    if "SetIamPolicy" in method_name:
        resource_name = proto.get("resourceName", "")
        bindings = proto.get("request", {}).get("policy", {}).get("bindings", [])
        rogue_grants: list[str] = []

        for b in bindings:
            role = b.get("role", "")
            if role in ("roles/billing.admin", "roles/billing.user"):
                for member in b.get("members", []):
                    if not is_authorized_billing_member(member):
                        rogue_grants.append(f"{role}:{member}")

        if rogue_grants:
            logger.critical(
                "TIER-1B ALERT: Suspicious Billing SetIamPolicy on %s by %s -> %s",
                resource_name,
                actor_email,
                rogue_grants,
            )
            await db.collection("security_incidents").add(
                {
                    "billing_subaccount_id": resource_name.replace("billingAccounts/", ""),
                    "actor_email": actor_email,
                    "severity": "P1_CRITICAL",
                    "incident_type": "ROGUE_BILLING_IAM",
                    "rogue_grants": rogue_grants,
                    "auto_action_taken": "P1_HUMAN_ESCALATED",
                    "detected_at": datetime.now(timezone.utc),
                }
            )
            return {"status": "alerted_rogue_iam", "grants": rogue_grants}

    return {"status": "ok"}


@app.post("/internal/reconcile")
async def reconcile_all_subaccounts():
    """15-minute full-state drift reconciler invoked by Cloud Scheduler."""
    db = get_db()
    token = await asyncio.to_thread(_get_watchdog_token)
    tenants = await db.collection("tenants").where("status", "==", "ACTIVE").get()
    remediated = []

    async with httpx.AsyncClient(timeout=20.0) as client:
        for t_doc in tenants:
            subaccount_id = t_doc.to_dict()["billing_subaccount_id"]
            page_token: str | None = None

            while True:
                url = f"https://cloudbilling.googleapis.com/v1/billingAccounts/{subaccount_id}/projects"
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = await client.get(url, headers={"Authorization": f"Bearer {token}"}, params=params)
                if resp.status_code != 200:
                    logger.error("Reconcile list failed for %s: %s", subaccount_id, resp.text)
                    break

                body = resp.json()
                for info in body.get("projectBillingInfo", []):
                    if not info.get("billingEnabled"):
                        continue
                    project_id = info["projectId"]
                    if not await is_project_authorized_or_leased(db, project_id, subaccount_id):
                        action = await emergency_unlink_rogue_project(
                            db=db,
                            project_id=project_id,
                            subaccount_id=subaccount_id,
                            actor_email="drift-reconciler-detected",
                            detection_source="SCHEDULED_15M_RECONCILER",
                        )
                        remediated.append({"projectId": project_id, "subaccountId": subaccount_id, "action": action})

                page_token = body.get("nextPageToken")
                if not page_token:
                    break

    return {"reconciledTenants": len(tenants), "driftRemediations": remediated}
