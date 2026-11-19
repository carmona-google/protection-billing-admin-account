#!/usr/bin/env python3
"""
Phase 1 Brownfield Discovery & Backfill Utility
-----------------------------------------------
Must be executed BEFORE switching `WATCHDOG_MODE` from `DRY_RUN` to `ENFORCE`.
Discovers all currently active GCP projects across Partner Billing Subaccounts,
verifies their CRM v1 Organization ancestry against each Tenant's `allowed_org_ids`,
flags any pre-existing external / No-Org anomalies for SecOps review, and writes
legitimate projects into Firestore `approved_project_bindings`.

Usage:
  python3 scripts/backfill_existing_projects.py --firestore-project partner-billing-broker-prod --dry-run
  python3 scripts/backfill_existing_projects.py --firestore-project partner-billing-broker-prod --commit
"""

from __future__ import annotations

import argparse
import logging
from datetime import datetime, timezone

import google.auth
import google.auth.transport.requests
import httpx
from google.cloud import firestore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("brownfield-backfill")
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def get_token() -> str:
    creds, _ = google.auth.default(scopes=SCOPES)
    creds.refresh(google.auth.transport.requests.Request())
    return creds.token


def lookup_org_id(client: httpx.Client, headers: dict, project_id: str) -> str:
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getAncestry"
    resp = client.post(url, headers=headers, json={})
    if resp.status_code != 200:
        return "ANCESTRY_UNREADABLE"
    for anc in resp.json().get("ancestor", []):
        if anc.get("resourceId", {}).get("type") == "organization":
            return f"organizations/{anc['resourceId']['id']}"
    return "NO_ORGANIZATION"


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill existing subaccount projects into Broker Firestore.")
    parser.add_argument("--firestore-project", required=True, help="GCP Project ID hosting Broker Firestore.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true", help="Report findings without writing to Firestore.")
    group.add_argument("--commit", action="store_true", help="Write verified projects into approved_project_bindings.")
    args = parser.parse_args()

    db = firestore.Client(project=args.firestore_project)
    headers = {"Authorization": f"Bearer {get_token()}"}

    total_backfilled = 0
    anomalies: list[dict] = []

    with httpx.Client(timeout=20.0) as client:
        for tenant_doc in db.collection("tenants").stream():
            tenant_id = tenant_doc.id
            t = tenant_doc.to_dict()
            subaccount_id = t["billing_subaccount_id"]
            allowed_orgs = set(t.get("allowed_org_ids", []))
            tier = t.get("tier", "ENTERPRISE_ORG")

            page_token: str | None = None
            while True:
                url = f"https://cloudbilling.googleapis.com/v1/billingAccounts/{subaccount_id}/projects"
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token
                resp = client.get(url, headers=headers, params=params)
                resp.raise_for_status()
                body = resp.json()

                for item in body.get("projectBillingInfo", []):
                    if not item.get("billingEnabled"):
                        continue
                    project_id = item["projectId"]
                    detected_org = lookup_org_id(client, headers, project_id)

                    if detected_org not in allowed_orgs:
                        anomalies.append(
                            {
                                "tenantId": tenant_id,
                                "subaccountId": subaccount_id,
                                "projectId": project_id,
                                "detectedOrg": detected_org,
                            }
                        )
                        logger.warning(
                            "ANOMALY SKIPPED: tenant=%s subaccount=%s project=%s detected_org=%s",
                            tenant_id,
                            subaccount_id,
                            project_id,
                            detected_org,
                        )
                        continue

                    if args.commit:
                        db.collection("approved_project_bindings").document(project_id).set(
                            {
                                "project_id": project_id,
                                "tenant_id": tenant_id,
                                "billing_subaccount_id": subaccount_id,
                                "verified_org_id": detected_org,
                                "source": "LEGACY_BACKFILL",
                                "production_unlink_protected": True,
                                "status": "ACTIVE",
                                "linked_at": datetime.now(timezone.utc),
                            },
                            merge=True,
                        )
                    total_backfilled += 1
                    logger.info("Verified project=%s (tenant=%s, org=%s)", project_id, tenant_id, detected_org)

                page_token = body.get("nextPageToken")
                if not page_token:
                    break

    logger.info(
        "Summary (%s): %d valid projects processed, %d anomalies flagged for manual review.",
        "COMMIT" if args.commit else "DRY_RUN",
        total_backfilled,
        len(anomalies),
    )


if __name__ == "__main__":
    main()
