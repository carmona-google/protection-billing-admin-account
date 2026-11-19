# Reference Implementation: Partner Billing Broker & Real-Time Security Watchdog

This directory contains the reference infrastructure-as-code (Terraform) and serverless control-plane services (Cloud Run / FastAPI) implementing **[hld_partner_billing_automation.md](file:///Users/carmona/Agy/Caso%20Billling%20Admin/hld_partner_billing_automation.md)** (`v1.1` — Dual-Mode Architecture).

## Directory Structure

```text
reference-implementation/
├── terraform/
│   ├── partner-control-plane/          # Partner GCP Org infrastructure
│   │   ├── versions.tf                 # OpenTofu / Terraform >= 1.6, Google Provider ~> 6.12
│   │   ├── apis.tf                     # Deduplicated API enablement (supports single-project GCP setup)
│   │   ├── variables.tf                # Multi-tenant map, project IDs & DRY_RUN/ENFORCE toggle
│   │   ├── single_project.tfvars.example # Ready-to-use single-project GCP template
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

---

## Despliegue Inicial en un Proyecto Único de GCP (Quickstart)

Si quieres desplegar toda la arquitectura sobre un único proyecto en tu entorno de **Google Cloud (GCP)**, sigue estos pasos iniciales:

### 0. Clonar el repositorio
```bash
git clone https://github.com/carmona-google/protection-billing-admin-account.git
cd protection-billing-admin-account
```

### 1. Autenticación y variables de entorno
```bash
export PROJECT_ID="tu-proyecto-gcp"
export REGION="europe-southwest1"

gcloud auth login
gcloud auth application-default login
gcloud config set project "$PROJECT_ID"

# Obtén automáticamente tu Organization ID y Billing Account ID del entorno GCP:
export ORG_ID=$(gcloud projects describe "$PROJECT_ID" --format="value(parent.id)")
export BILLING_ID=$(gcloud billing projects describe "$PROJECT_ID" --format="value(billingAccountName)" | sed 's|billingAccounts/||')
echo "ORG_ID=$ORG_ID  BILLING_ID=$BILLING_ID"
```

### 2. Habilitar Artifact Registry / Cloud Build y construir las imágenes de Cloud Run
```bash
gcloud services enable artifactregistry.googleapis.com cloudbuild.googleapis.com run.googleapis.com

# En proyectos nuevos, Cloud Build usa la Compute Engine SA por defecto y necesita roles/cloudbuild.builds.builder
export PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)")
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/cloudbuild.builds.builder"

gcloud artifacts repositories create billing-broker \
  --repository-format=docker \
  --location="$REGION" \
  --description="Billing Broker & Security Watchdog images"

# Construir y subir Broker API
gcloud builds submit reference-implementation/services/broker-api \
  --tag "${REGION}-docker.pkg.dev/${PROJECT_ID}/billing-broker/broker-api:v1.1"

# Construir y subir Security Watchdog
gcloud builds submit reference-implementation/services/security-watchdog \
  --tag "${REGION}-docker.pkg.dev/${PROJECT_ID}/billing-broker/security-watchdog:v1.1"
```

### 3. Configurar `single_project.tfvars` y desplegar con Terraform
```bash
cd reference-implementation/terraform/partner-control-plane
cp single_project.tfvars.example single_project.tfvars
```
Edita `single_project.tfvars` sustituyendo `<YOUR_GCP_PROJECT_ID>`, `<YOUR_GCP_ORG_ID>` y `<YOUR_BILLING_ACCOUNT_ID>` por los valores obtenidos en el paso 1, y ejecuta:
```bash
terraform init
terraform plan -var-file="single_project.tfvars"
terraform apply -var-file="single_project.tfvars"
```
> **Nota:** `apis.tf` habilita automáticamente las APIs necesarias en el proyecto GCP y deduplica los tres planos (`broker`, `linkers`, `secops`) cuando apuntan al mismo `PROJECT_ID`. El Watchdog arrancará en modo `DRY_RUN` para no desvincular ningún proyecto existente hasta que ejecutes el backfill y valides los logs.

### 4. Cómo acceder y probar la aplicación una vez desplegada

Al finalizar `terraform apply`, obtén la URL del servicio y concédete permiso de invocación en Cloud Run (`roles/run.invoker`):
```bash
export BROKER_URL=$(terraform output -raw broker_api_uri)
export MY_EMAIL=$(gcloud config get-value account)

gcloud run services add-iam-policy-binding billing-broker-api \
  --project="$PROJECT_ID" \
  --region="$REGION" \
  --member="user:${MY_EMAIL}" \
  --role="roles/run.invoker"
```

#### Opción A — Acceso visual a la API (Swagger UI / OpenAPI) mediante proxy autenticado
```bash
gcloud run services proxy billing-broker-api --project="$PROJECT_ID" --region="$REGION" --port=8080
```
Abre en tu navegador **http://127.0.0.1:8080/docs** para explorar y probar los endpoints de forma interactiva.

#### Opción B — Llamada directa por `curl` con token OIDC
```bash
# 1. Verificar estado del servicio
curl -sS -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  "${BROKER_URL}/healthz"

# 2. Generar un comando gcloud efímero de Modo A para un proyecto de prueba
curl -sS -X POST "${BROKER_URL}/v1/tenants/demo_sandbox_tenant/link-intents" \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  -H "Content-Type: application/json" \
  -d '{"projectId": "tu-proyecto-destino"}'
```

#### Verificar los logs del Security Watchdog (`DRY_RUN`)
```bash
gcloud logging read \
  'resource.type="cloud_run_revision" AND resource.labels.service_name="billing-security-watchdog"' \
  --project="$PROJECT_ID" --limit=20 --format="table(timestamp,severity,textPayload)"
```

### 5. Borrar todo el entorno y dejarlo limpio (Teardown)

Si quieres eliminar todos los recursos creados en el proyecto de pruebas:

```bash
# 1. Destruir los recursos gestionados por Terraform (Cloud Run, Firestore, Pub/Sub, Sink, Scheduler, SAs)
cd reference-implementation/terraform/partner-control-plane
terraform destroy -var-file="single_project.tfvars" -auto-approve

# (Si activaste firestore_delete_protection = "DELETE_PROTECTION_ENABLED", desactívalo antes:)
# gcloud firestore databases update --database="(default)" --project="$PROJECT_ID" --no-delete-protection

# 2. Eliminar el repositorio de Artifact Registry y sus imágenes Docker
gcloud artifacts repositories delete billing-broker \
  --project="$PROJECT_ID" \
  --location="$REGION" \
  --quiet

# 3. (Opcional) Retirar el permiso de Cloud Build a la Compute SA y eliminar tu tfvars local
gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/cloudbuild.builds.builder"

rm -f single_project.tfvars
```
