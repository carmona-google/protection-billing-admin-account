"""
Partner Billing Broker API (v1.1 Reference Implementation — Dual-Mode)
----------------------------------------------------------------------
Enforces zero standing customer roles/billing.user privileges across Modes A and B:
  - Mode A: Ephemeral 30-minute IAM condition on target project (gcloud intent generator)
  - Mode B: Folder-scoped OIDC/Terraform automation (plus optional hybrid ephemeral variant)

Key architectural guarantees:
  1. 1:1 Per-Tenant Linker SA short-lived impersonation (10m OAuth2 token, zero static keys).
  2. Cloud Resource Manager v1 `projects.getAncestry` check with exponential backoff;
     hard-blocks any foreign-Org or No-Organization project with 403 ANCESTRY_VIOLATION.
  3. Write-ahead Firestore `LINKING_LEASE_ACQUIRED` lease BEFORE calling Cloud Billing API
     to prevent race conditions with the <10s Real-Time Security Watchdog.
  4. Automatic baseline Cloud Billing Budget creation upon attachment & velocity burst gate.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal

import google.auth
import google.auth.transport.requests
from google.oauth2 import id_token as google_id_token
import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Path, status
from google.cloud import firestore
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("billing-broker")

FIRESTORE_PROJECT_ID = os.environ.get("FIRESTORE_PROJECT_ID")
LEASE_TTL_SECONDS = int(os.environ.get("LEASE_TTL_SECONDS", "90"))
AUTH_MODE = os.environ.get("AUTH_MODE", "ENFORCE_JWT")  # ENFORCE_JWT | DEV_HEADER_ONLY
BROKER_AUDIENCE = os.environ.get("BROKER_AUDIENCE")
FINOPS_APPROVER_EMAILS = {
    e.strip().lower()
    for e in os.environ.get("FINOPS_APPROVER_EMAILS", "").split(",")
    if e.strip()
}
GCP_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

_db: firestore.AsyncClient | None = None
_http_client: httpx.AsyncClient | None = None
_token_cache: dict[str, tuple[str, datetime]] = {}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _http_client
    _http_client = httpx.AsyncClient(timeout=20.0)
    try:
        yield
    finally:
        await _http_client.aclose()
        _http_client = None


app = FastAPI(
    title="Partner Billing Broker API",
    version="1.1.0",
    description="Zero-Standing-Privilege Billing Subaccount Linking Control Plane",
    lifespan=lifespan,
)


def get_db() -> firestore.AsyncClient:
    global _db
    if _db is None:
        _db = firestore.AsyncClient(project=FIRESTORE_PROJECT_ID)
    return _db


def get_http() -> httpx.AsyncClient:
    if _http_client is None:
        raise RuntimeError("HTTP client not initialized")
    return _http_client


async def verify_caller_identity(
    authorization: str | None = Header(default=None),
    x_authenticated_principal: str = Header(default=""),
) -> str:
    """
    Validates Google OIDC / Identity Platform Bearer JWT in production (`AUTH_MODE=ENFORCE_JWT`).
    In `DEV_HEADER_ONLY` (unit tests / local dev), falls back to `x-authenticated-principal`.
    """
    if AUTH_MODE == "DEV_HEADER_ONLY":
        if not x_authenticated_principal:
            raise HTTPException(status_code=401, detail="Missing x-authenticated-principal in dev mode")
        return x_authenticated_principal

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bearer Authorization header")

    raw_jwt = authorization.removeprefix("Bearer ").strip()
    try:
        req = google.auth.transport.requests.Request()
        claims = await asyncio.to_thread(google_id_token.verify_oauth2_token, raw_jwt, req, BROKER_AUDIENCE)
    except Exception as exc:
        logger.warning("JWT verification failed: %s", exc)
        raise HTTPException(status_code=401, detail="Invalid or expired OIDC token") from exc

    principal = claims.get("email") or claims.get("sub")
    if not principal:
        raise HTTPException(status_code=401, detail="OIDC token missing email/sub claim")
    return str(principal).lower()


# ---------------------------------------------------------------------------
# Pydantic v2 API Contracts (Matching HLD Section 5)
# ---------------------------------------------------------------------------


class LinkIntentRequest(BaseModel):
    projectId: str = Field(..., pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


class LinkIntentResponse(BaseModel):
    tenantId: str
    projectId: str
    linkerServiceAccount: str
    expiresAtUtc: str
    gcloudCommand: str


class BillingLinkRequest(BaseModel):
    projectId: str = Field(..., pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
    accessMode: Literal["EPHEMERAL_PROJECT", "FOLDER_DELEGATED"] = "EPHEMERAL_PROJECT"
    costCenter: str = Field(..., min_length=2, max_length=64)
    environment: Literal["PRODUCTION", "STAGING", "DEVELOPMENT", "SANDBOX"] = "PRODUCTION"
    monthlyBudgetEur: int = Field(default=500, ge=50, le=500000)
    alertContactEmails: list[str] = Field(default_factory=list)
    justification: str = Field(default="", max_length=500)


class ApprovalDecisionRequest(BaseModel):
    decision: Literal["APPROVE", "REJECT"]
    approverNote: str = Field(..., min_length=5, max_length=500)


# ---------------------------------------------------------------------------
# Keyless Impersonation & GCP Control Plane Helpers
# ---------------------------------------------------------------------------


def _get_orchestrator_access_token() -> str:
    creds, _ = google.auth.default(scopes=GCP_SCOPES)
    creds.refresh(google.auth.transport.requests.Request())
    return creds.token


async def mint_tenant_linker_token(client: httpx.AsyncClient, linker_sa_email: str) -> str:
    """Mints (and caches for 5m) a short-lived 10m OAuth2 token for the isolated Tenant Linker SA."""
    now = datetime.now(timezone.utc)
    cached = _token_cache.get(linker_sa_email)
    if cached and cached[1] > now:
        return cached[0]

    orch_token = await asyncio.to_thread(_get_orchestrator_access_token)
    url = (
        f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
        f"{linker_sa_email}:generateAccessToken"
    )
    resp = await client.post(
        url,
        headers={"Authorization": f"Bearer {orch_token}"},
        json={"scope": GCP_SCOPES, "lifetime": "600s"},
    )
    if resp.status_code != 200:
        logger.error("Impersonation failed for %s: %s", linker_sa_email, resp.text)
        raise HTTPException(status_code=502, detail="Failed to impersonate tenant linker identity")
    token = resp.json()["accessToken"]
    _token_cache[linker_sa_email] = (token, now + timedelta(minutes=5))
    return token


async def fetch_project_ancestry_v1(
    client: httpx.AsyncClient, tenant_token: str, project_id: str
) -> list[dict]:
    """
    Calls Cloud Resource Manager v1 `projects.getAncestry` with exponential backoff
    (1s, 2s, 4s, 8s) to absorb Mode A IAM binding propagation latency transparently.
    """
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getAncestry"
    delays = [1, 2, 4, 8]

    for attempt, delay in enumerate([0, *delays]):
        if delay:
            await asyncio.sleep(delay)
        resp = await client.post(url, headers={"Authorization": f"Bearer {tenant_token}"}, json={})
        if resp.status_code == 200:
            return resp.json().get("ancestor", [])
        if resp.status_code != 403 or attempt == len(delays):
            if resp.status_code == 403:
                raise HTTPException(
                    status_code=status.HTTP_412_PRECONDITION_FAILED,
                    detail={
                        "errorCode": "IAM_PROPAGATION_PENDING",
                        "message": (
                            f"Tenant Linker SA lacks roles/billing.projectManager on {project_id} "
                            "after 15s retry backoff. Run the Mode A gcloud command or check Folder IAM."
                        ),
                    },
                )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"errorCode": "PROJECT_LOOKUP_FAILED", "upstream": resp.text},
            )
    return []


async def attach_billing_and_create_budget(
    client: httpx.AsyncClient,
    tenant_token: str,
    project_id: str,
    subaccount_id: str,
    budget_eur: int,
) -> tuple[dict, str | None]:
    """Attaches the Partner Billing Subaccount and creates a standardized baseline Spend Budget."""
    headers = {"Authorization": f"Bearer {tenant_token}"}
    billing_account_name = f"billingAccounts/{subaccount_id}"

    # Step 1: Attach Billing Subaccount (`UpdateProjectBillingInfo`)
    link_url = f"https://cloudbilling.googleapis.com/v1/projects/{project_id}/billingInfo"
    link_resp = await client.put(
        link_url,
        headers=headers,
        json={"billingAccountName": billing_account_name},
    )
    if link_resp.status_code != 200:
        logger.error("Billing link failed for %s: %s", project_id, link_resp.text)
        raise HTTPException(status_code=502, detail={"errorCode": "BILLING_LINK_FAILED", "upstream": link_resp.text})

    billing_info = link_resp.json()

    # Step 2: Provision Baseline Project Budget (Non-fatal saga: queued for retry if 5xx)
    budget_url = f"https://billingbudgets.googleapis.com/v1/{billing_account_name}/budgets"
    budget_payload = {
        "displayName": f"broker-baseline-{project_id}",
        "budgetFilter": {"projects": [f"projects/{project_id}"]},
        "amount": {"specifiedAmount": {"currencyCode": "EUR", "units": str(budget_eur)}},
        "thresholdRules": [
            {"thresholdPercent": 0.5, "spendBasis": "CURRENT_SPEND"},
            {"thresholdPercent": 0.9, "spendBasis": "CURRENT_SPEND"},
            {"thresholdPercent": 1.0, "spendBasis": "CURRENT_SPEND"},
        ],
    }
    budget_resp = await client.post(budget_url, headers=headers, json=budget_payload)
    budget_name = budget_resp.json().get("name") if budget_resp.status_code in (200, 201) else None
    return billing_info, budget_name


# ---------------------------------------------------------------------------
# REST v1 Endpoints
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "billing-broker-api", "version": "1.1.0"}


@app.post("/v1/tenants/{tenant_id}/link-intents", response_model=LinkIntentResponse)
async def create_mode_a_link_intent(
    payload: LinkIntentRequest,
    tenant_id: str = Path(...),
    _caller: str = Depends(verify_caller_identity),
) -> LinkIntentResponse:
    """Generates the Mode A 30-minute auto-expiring `gcloud` IAM command for a customer project."""
    db = get_db()
    tenant_snap = await db.collection("tenants").document(tenant_id).get()
    if not tenant_snap.exists:
        raise HTTPException(status_code=404, detail="Unknown tenantId")

    tenant = tenant_snap.to_dict()
    linker_sa = tenant["linker_sa_email"]
    expires_dt = datetime.now(timezone.utc) + timedelta(minutes=30)
    expires_iso = expires_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    gcloud_cmd = (
        f'gcloud projects add-iam-policy-binding "{payload.projectId}" \\\n'
        f'  --member="serviceAccount:{linker_sa}" \\\n'
        f'  --role="roles/billing.projectManager" \\\n'
        f"  --condition=\"expression=request.time < timestamp('{expires_iso}'),"
        f'title=partner-ephemeral-billing-link"'
    )
    return LinkIntentResponse(
        tenantId=tenant_id,
        projectId=payload.projectId,
        linkerServiceAccount=linker_sa,
        expiresAtUtc=expires_iso,
        gcloudCommand=gcloud_cmd,
    )


@app.post("/v1/tenants/{tenant_id}/billing-links", status_code=status.HTTP_201_CREATED)
async def create_billing_link(
    payload: BillingLinkRequest,
    tenant_id: str = Path(...),
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    caller_principal: str = Depends(verify_caller_identity),
):
    """Validates ancestry & rate limits, acquires write-ahead lease, and links Billing Subaccount."""
    db = get_db()
    client = get_http()

    # 1. Idempotency check
    idem_query = (
        await db.collection("link_requests")
        .where("idempotency_key", "==", idempotency_key)
        .limit(1)
        .get()
    )
    if idem_query:
        existing = idem_query[0].to_dict()
        if existing.get("response_cache"):
            return existing["response_cache"]

    # 2. Load Tenant Policy
    tenant_snap = await db.collection("tenants").document(tenant_id).get()
    if not tenant_snap.exists or tenant_snap.to_dict().get("status") != "ACTIVE":
        raise HTTPException(status_code=403, detail="Tenant inactive or unknown")
    tenant = tenant_snap.to_dict()

    # 3. Sliding-Window Hourly Velocity Guardrail
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    recent_links = (
        await db.collection("link_requests")
        .where("tenant_id", "==", tenant_id)
        .where("created_at", ">=", one_hour_ago)
        .get()
    )
    velocity_exceeded = len(recent_links) >= int(tenant.get("max_links_per_hour", 5))

    request_id = f"req_{uuid.uuid4()}"
    now = datetime.now(timezone.utc)

    tenant_token = await mint_tenant_linker_token(client, tenant["linker_sa_email"])
    ancestors = await fetch_project_ancestry_v1(client, tenant_token, payload.projectId)

    # Extract root Organization ID if present
    org_ancestors = [
        f"organizations/{a['resourceId']['id']}"
        for a in ancestors
        if a.get("resourceId", {}).get("type") == "organization"
    ]
    detected_org = org_ancestors[0] if org_ancestors else "NO_ORGANIZATION"
    allowed_orgs = set(tenant.get("allowed_org_ids", []))

    # 4. Hard-Block Foreign Organization OR "No-Organization" Projects
    if detected_org == "NO_ORGANIZATION" or detected_org not in allowed_orgs:
        await db.collection("security_incidents").add(
            {
                "tenant_id": tenant_id,
                "billing_subaccount_id": tenant["billing_subaccount_id"],
                "severity": "P2_HIGH",
                "incident_type": "ANCESTRY_SPOOF_ATTEMPT",
                "project_id": payload.projectId,
                "detected_org_id": detected_org,
                "caller_principal": caller_principal,
                "detected_at": now,
            }
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "errorCode": "ANCESTRY_VIOLATION",
                "message": f"Project root {detected_org} is not in tenant allowlist.",
            },
        )

    # 4B. Velocity Burst Gate -> Queue for Partner FinOps Approval (HTTP 202)
    if velocity_exceeded:
        await db.collection("link_requests").document(request_id).set(
            {
                "request_id": request_id,
                "idempotency_key": idempotency_key,
                "tenant_id": tenant_id,
                "project_id": payload.projectId,
                "detected_org_id": detected_org,
                "state": "PENDING_FINOPS_APPROVAL",
                "caller_principal": caller_principal,
                "payload": payload.model_dump(),
                "created_at": now,
            }
        )
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail={
                "requestId": request_id,
                "status": "PENDING_FINOPS_APPROVAL",
                "errorCode": "VELOCITY_GATE_TRIGGERED",
                "message": "Hourly linking velocity limit exceeded; queued for Partner FinOps approval.",
            },
        )

    # 5. Write-Ahead Lease BEFORE calling Cloud Billing API (Zero Watchdog race condition!)
    lease_expiry = now + timedelta(seconds=LEASE_TTL_SECONDS)
    req_ref = db.collection("link_requests").document(request_id)
    await req_ref.set(
        {
            "request_id": request_id,
            "idempotency_key": idempotency_key,
            "tenant_id": tenant_id,
            "project_id": payload.projectId,
            "detected_org_id": detected_org,
            "state": "LINKING_LEASE_ACQUIRED",
            "caller_principal": caller_principal,
            "lease_expires_at": lease_expiry,
            "created_at": now,
        }
    )

    # 6. Execute Billing Link + Baseline Budget
    budget_eur = payload.monthlyBudgetEur or int(tenant.get("default_project_budget_eur", 500))
    _, budget_name = await attach_billing_and_create_budget(
        client=client,
        tenant_token=tenant_token,
        project_id=payload.projectId,
        subaccount_id=tenant["billing_subaccount_id"],
        budget_eur=budget_eur,
    )

    final_state = "ACTIVE" if budget_name else "ACTIVE_BUDGET_RETRY_QUEUED"
    linked_at_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 7. Persist Approved Project Binding for Watchdog & Reconciler
    await db.collection("approved_project_bindings").document(payload.projectId).set(
        {
            "project_id": payload.projectId,
            "tenant_id": tenant_id,
            "billing_subaccount_id": tenant["billing_subaccount_id"],
            "verified_org_id": detected_org,
            "budget_resource_name": budget_name,
            "source": "BROKER_AUTO",
            "production_unlink_protected": payload.environment == "PRODUCTION",
            "status": "ACTIVE",
            "linked_at": now,
        }
    )

    response_payload = {
        "requestId": request_id,
        "status": final_state,
        "tenantId": tenant_id,
        "projectId": payload.projectId,
        "verifiedOrganizationId": detected_org,
        "billingSubaccountName": f"billingAccounts/{tenant['billing_subaccount_id']}",
        "baselineBudgetName": budget_name,
        "linkedAt": linked_at_iso,
        "authenticatedPrincipal": caller_principal,
    }
    await req_ref.update({"state": final_state, "response_cache": response_payload})
    return response_payload


@app.post("/v1/admin/approvals/{request_id}:decide")
async def decide_manual_approval(
    decision_req: ApprovalDecisionRequest,
    request_id: str = Path(...),
    approver_principal: str = Depends(verify_caller_identity),
):
    """Partner FinOps manual approval gate for velocity-burst project linking requests."""
    if FINOPS_APPROVER_EMAILS and approver_principal.lower() not in FINOPS_APPROVER_EMAILS:
        raise HTTPException(status_code=403, detail="Caller is not an authorized Partner FinOps approver")

    db = get_db()
    client = get_http()
    req_ref = db.collection("link_requests").document(request_id)
    req_snap = await req_ref.get()
    if not req_snap.exists:
        raise HTTPException(status_code=404, detail="Unknown requestId")

    req_data = req_snap.to_dict()
    if req_data.get("state") != "PENDING_FINOPS_APPROVAL":
        raise HTTPException(status_code=409, detail=f"Request already in state {req_data.get('state')}")

    now = datetime.now(timezone.utc)
    if decision_req.decision == "REJECT":
        await req_ref.update(
            {
                "state": "REJECTED_POLICY",
                "approver_principal": approver_principal,
                "approver_note": decision_req.approverNote,
            }
        )
        return {"requestId": request_id, "status": "REJECTED_POLICY"}

    tenant_snap = await db.collection("tenants").document(req_data["tenant_id"]).get()
    tenant = tenant_snap.to_dict()
    project_id = req_data["project_id"]

    # Acquire write-ahead lease and link approved burst project
    await req_ref.update(
        {
            "state": "LINKING_LEASE_ACQUIRED",
            "approver_principal": approver_principal,
            "lease_expires_at": now + timedelta(seconds=LEASE_TTL_SECONDS),
        }
    )

    tenant_token = await mint_tenant_linker_token(client, tenant["linker_sa_email"])
    budget_eur = int(req_data.get("payload", {}).get("monthlyBudgetEur", 500))
    _, budget_name = await attach_billing_and_create_budget(
        client=client,
        tenant_token=tenant_token,
        project_id=project_id,
        subaccount_id=tenant["billing_subaccount_id"],
        budget_eur=budget_eur,
    )

    await db.collection("approved_project_bindings").document(project_id).set(
        {
            "project_id": project_id,
            "tenant_id": req_data["tenant_id"],
            "billing_subaccount_id": tenant["billing_subaccount_id"],
            "verified_org_id": req_data["detected_org_id"],
            "budget_resource_name": budget_name,
            "source": "BROKER_VELOCITY_APPROVED",
            "production_unlink_protected": True,
            "status": "ACTIVE",
            "linked_at": now,
        }
    )
    await req_ref.update({"state": "ACTIVE"})
    return {"requestId": request_id, "status": "ACTIVE", "projectId": project_id, "baselineBudgetName": budget_name}
