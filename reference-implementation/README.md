# Reference Implementation: Partner Billing Broker & Real-Time Security Watchdog

This directory contains the reference infrastructure-as-code (Terraform) and serverless control-plane services (Cloud Run / FastAPI) implementing **[hld_partner_billing_automation.md](file:///Users/carmona/Agy/Caso%20Billling%20Admin/hld_partner_billing_automation.md)** (`v1.1` — Dual-Mode Architecture).

## Directory Structure

```text
reference-implementation/
├── terraform/
│   ├── partner-control-plane/          # Partner GCP Org infrastructure
│   │   ├── versions.tf                 # OpenTofu / Terraform >= 1.6, Google Provider ~> 6.12
│   │   ├── variables.tf                # Multi-tenant map, project IDs & DRY_RUN/ENFORCE toggle
│   │   ├── iam_custom_roles.tf         # Least-privilege custom roles (delete & setIamPolicy stripped)
│   │   ├── tenant_linker_factory.tf    # 1:1 isolated sa-linker-<tenant> factory + Firestore sync
│   │   ├── control_plane_and_watchdog.tf # Firestore, Broker Run, Org Audit Sink, Watchdog & 15m Reconciler
│   │   └── outputs.tf                  # Endpoints & per-customer Linker SA emails
│   └── customer-module/                # Reusable Mode B module for Customer CI/CD (zero billing.user)
│       └── main.tf                     # Keyless OIDC invocation with deterministic Idempotency-Key
├── services/
│   ├── broker-api/                     # Cloud Run Billing Broker REST API v1
│   │   ├── main.py                     # Mode A/B, 10m SA impersonation, CRM v1 getAncestry, Leases & Budgets
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   └── security-watchdog/              # Isolated SecOps Cloud Run Watchdog
│       ├── main.py                     # Tier 1A (<10s auto-unlink), Tier 1B (IAM diff) & 15m Drift Reconciler
│       ├── requirements.txt
│       └── Dockerfile
└── scripts/
    └── backfill_existing_projects.py   # Phase 1 brownfield discovery & Firestore backfill tool
```

## Safe Production Rollout Sequence

1. **Deploy Partner Infrastructure in `DRY_RUN` Mode (Phase 1):**
   Apply `terraform/partner-control-plane` with `watchdog_mode = "DRY_RUN"`. This creates the Organization-level Aggregated Audit Sink, Firestore Native DB, custom least-privilege roles, and per-tenant `sa-linker-<tenant>` Service Accounts without auto-detaching existing workloads.
2. **Execute Brownfield Backfill & Anomaly Audit:**
   ```bash
   python3 scripts/backfill_existing_projects.py \
     --firestore-project partner-billing-broker-prod \
     --dry-run

   # Review any flagged NO_ORGANIZATION or foreign-Org anomalies, then commit:
   python3 scripts/backfill_existing_projects.py \
     --firestore-project partner-billing-broker-prod \
     --commit
   ```
3. **Revoke Standing Customer `roles/billing.user` & Onboard Modes A / B (Phases 2–3):**
   Downgrade customer principals on Partner Billing Subaccounts to `roles/billing.viewer` and transition project creation to the Portal UI (Mode A 30m ephemeral grant) or `terraform/customer-module` (Mode B Folder delegation).
4. **Flip Watchdog to `ENFORCE` (Phase 4):**
   After 7 days of zero false positives in `DRY_RUN` logs, update `watchdog_mode = "ENFORCE"` in Terraform so any unapproved external project linked to any Partner subaccount is detached automatically in `<10s`.
