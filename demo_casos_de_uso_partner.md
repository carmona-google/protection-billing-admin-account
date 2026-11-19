# Guion de Demo Guiada para el Partner: Casos de Uso en Vivo (Modo A, Modo B y Prevención de Ataques)

> [!TIP]
> Esta guía está pensada para ejecutarla **en vivo paso a paso** frente al Partner sobre tu instancia desplegada (`http://127.0.0.1:8080/docs` + terminal con `gcloud`), conectando cada pantalla y respuesta de la API con el vector de ataque real descrito en el contexto del incidente (*infostealer / phishing AitM → secuestro de facturación → creación masiva de proyectos Made-for-Abuse fuera de la Organización → quema de cuota Gemini/Vertex AI*).

---

## Preparación Rápida (Antes de Empezar la Demo)

Asegúrate de tener abierto en el navegador **http://127.0.0.1:8080/docs** (con `gcloud run services proxy` activo) y en tu terminal estas variables listas:

```bash
export PROJECT_ID=$(gcloud config get-value project)
export REGION="europe-southwest1"
export BROKER_LOCAL="http://127.0.0.1:8080"
export TENANT_ID="demo_sandbox_tenant"
```

---

## Caso de Uso 0 (Contexto): Qué Ocurre Hoy vs. Qué Cambia con esta Arquitectura

| Escenario | Sin Billing Broker (Situación de Riesgo) | Con Billing Broker + Watchdog (Tu Demo) |
| :--- | :--- | :--- |
| **Permisos del cliente** | Tiene `roles/billing.user` permanente en la subcuenta. | Solo tiene **`roles/billing.viewer`** (cero capacidad de enlazar o tocar IAM). |
| **Si roban la cookie/sesión de un admin o dev** | El atacante enlaza 100 proyectos `@gmail.com` externos y quema €200k en horas (sin pasar por Org Policies). | El atacante **no tiene credenciales** de la SA del Partner y cualquier intento por API o consola es **bloqueado (`403`)** o **desvinculado en `<10s`**. |

---

## Caso de Uso 1: Modo A — Alta Puntual con "Cero Huella Permanente" (UI / CLI)

**Objetivo para el Partner:** Demostrar que un administrador del cliente puede dar de alta la facturación de un proyecto nuevo en segundos, **sin tener `roles/billing.user`** y **sin dejar permisos permanentes del Partner** en su entorno.

### Paso 1.1 — Solicitar la intención de enlace (`POST /v1/tenants/{tenantId}/link-intents`)
En **Swagger UI** (`http://127.0.0.1:8080/docs`) o con `curl`, explica al Partner: *"El cliente entra en vuestro portal e indica qué `projectId` quiere facturar."*

```bash
curl -sS -X POST "${BROKER_LOCAL}/v1/tenants/${TENANT_ID}/link-intents" \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  -H "Content-Type: application/json" \
  -d '{"projectId": "tu-proyecto-dentro-de-org"}' | jq .
```

**Qué mostrar en la respuesta (`200 OK`):**
- Devuelve la Service Account **aislada 1:1** de ese cliente (`sa-linker-demo-sandbox-ten@...`).
- Devuelve el comando `gcloud` de una línea con condición temporal **`request.time < timestamp('...+30m')`**.

### Paso 1.2 — El cliente concede el permiso efímero de 30 minutos
El administrador del cliente copia y ejecuta ese comando en su terminal/Cloud Shell:
```bash
gcloud projects add-iam-policy-binding "tu-proyecto-dentro-de-org" \
  --member="serviceAccount:sa-linker-demo-sandbox...@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/billing.projectManager" \
  --condition="expression=request.time < timestamp('...'),title=partner-ephemeral-billing-link"
```
**Mensaje clave de seguridad al Partner:**
- *"`roles/billing.projectManager` **no da acceso** a VMs, Cloud Storage, Secret Manager, BigQuery ni IAM del proyecto. Y en 30 minutos desaparece automáticamente."*

### Paso 1.3 — Validación criptográfica y vinculación (`POST /v1/tenants/{tenantId}/billing-links`)
```bash
curl -sS -X POST "${BROKER_LOCAL}/v1/tenants/${TENANT_ID}/billing-links" \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "projectId": "tu-proyecto-dentro-de-org",
    "accessMode": "EPHEMERAL_PROJECT",
    "costCenter": "CC-DATA-01",
    "environment": "PRODUCTION",
    "monthlyBudgetEur": 500,
    "alertContactEmails": ["finops@cliente.com"],
    "justification": "Alta controlada Modo A"
  }' | jq .
```

**Qué ocurre internamente (enséñaselo en la respuesta `201 Created`):**
1. El Broker autentica el token OIDC del usuario (`verify_caller_identity`).
2. Impersona a `sa-linker-<tenant>` con un token efímero de 10 minutos (sin claves JSON).
3. Llama a **Cloud Resource Manager v1 (`projects.getAncestry`)** y verifica que la raíz es `organizations/<ORG_ID_DEL_CLIENTE>`.
4. Registra un *lease* previo en Firestore (`LINKING_LEASE_ACQUIRED`), vincula la subcuenta y crea el **presupuesto base de €500** automáticamente.

---

## Caso de Uso 2: Simulación del Ataque Real — Bloqueo de Proyecto Externo *Made-for-Abuse*

**Objetivo para el Partner:** Demostrar qué ocurre si un atacante roba la sesión de un usuario o CI/CD del cliente e intenta vincular un proyecto externo (`@gmail.com` / *"No Organization"* / otra Organización), exactamente como en el guion de ataque habitual.

### Paso 2.1 — Intento de enlace de un proyecto externo o sin Organización
Ejecuta la misma llamada indicando un `projectId` que pertenece a otra Organización o a una cuenta gratuita `@gmail.com` (*No Organization*):

```bash
curl -i -X POST "${BROKER_LOCAL}/v1/tenants/${TENANT_ID}/billing-links" \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "projectId": "proyecto-externo-made-for-abuse",
    "accessMode": "EPHEMERAL_PROJECT",
    "costCenter": "CC-FAKE",
    "environment": "SANDBOX",
    "monthlyBudgetEur": 100
  }'
```

**Qué mostrar al Partner:**
- **Respuesta inmediata `403 Forbidden` (`ANCESTRY_VIOLATION`):** El Broker detecta por `CRM v1 getAncestry` que el proyecto no cuelga de `organizations/<ORG_ID_DEL_CLIENTE>` y **aborta antes de tocar la Cuenta de Facturación**.
- **Auditoría instantánea:** En Firestore (`security_incidents`) queda registrado un incidente **`P2_HIGH` (`ANCESTRY_SPOOF_ATTEMPT`)** con el `caller_principal` y el `detected_org_id`.
- *(Contraste con la Opción 2 descartada: si hubierais dado `roles/billing.user` temporal al usuario, este habría enlazado 100 proyectos `@gmail.com` directamente contra Google Cloud sin que vuestra API pudiera impedirlo).*

---

## Caso de Uso 3: Modo B — Automatización Continua con Terraform / CI/CD (Sin `billing.user`)

**Objetivo para el Partner:** Mostrar cómo los equipos DevOps crean decenas de proyectos al mes con Terraform sin fricción manual, manteniendo **cero permisos de facturación en su pipeline**.

### Paso 3.1 — Configuración única en una Carpeta del Cliente
Explica el flujo mostrando el módulo [reference-implementation/terraform/customer-module/main.tf](file:///Users/carmona/Agy/Caso%20Billling%20Admin/reference-implementation/terraform/customer-module/main.tf):
1. El cliente delega `roles/billing.projectManager` a su `sa-linker-<tenant>` **una sola vez sobre una carpeta dedicada** (ej. `folders/billable-workloads`).
   - *Por qué en carpeta:* Terraform crea proyectos nuevos que no existían antes; al heredar de la carpeta, no hay que darle `setIamPolicy` al pipeline ni esperar propagación IAM. Al acotarlo a esa carpeta, el Partner no ve el resto de la Organización.
2. En cada `terraform apply`, Terraform crea `google_project` con **`billing_account = null`** e invoca el módulo del Partner pasando el token **OIDC** del CI/CD (GitHub Actions / GitLab).

### Paso 3.2 — Simulación de la llamada automática del pipeline (`FOLDER_DELEGATED`)
```bash
curl -sS -X POST "${BROKER_LOCAL}/v1/tenants/${TENANT_ID}/billing-links" \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "projectId": "corp-app-ci-01",
    "accessMode": "FOLDER_DELEGATED",
    "costCenter": "CC-DEVOPS-09",
    "environment": "PRODUCTION",
    "monthlyBudgetEur": 1500,
    "justification": "Provisioned by GitLab CI pipeline"
  }' | jq .
```

**Beneficio clave:** Si mañana se filtra el token o la SA de Terraform del cliente, **un atacante no puede vincular ningún proyecto externo** ni saltarse las *Organization Policies* del cliente.

---

## Caso de Uso 4: Freno a Multiplicación de Cuotas — *Velocity Gate* y Watchdog `<10s`

**Objetivo para el Partner:** Responder a la pregunta *"¿Y si el atacante compromete un desarrollador y crea proyectos **dentro** de la Organización del cliente para multiplicar cuotas?"*

### Paso 4.1 — *Velocity Gate* (Límite por hora + Aprobación FinOps)
Si un script intenta lanzar >5 enlaces en una hora (`max_links_per_hour = 5`), la petición #6 devuelve **`202 Accepted` (`VELOCITY_GATE_TRIGGERED` / `PENDING_FINOPS_APPROVAL`)** y queda pausada hasta que un aprobador FinOps autorizado (`FINOPS_APPROVER_EMAILS`) la valide en:
```bash
curl -sS -X POST "${BROKER_LOCAL}/v1/admin/approvals/<REQUEST_ID>:decide" \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  -H "Content-Type: application/json" \
  -d '{"decision": "APPROVE", "approverNote": "Validado con Tech Lead de Datos"}'
```

### Paso 4.2 — Watchdog en Tiempo Real (`UpdateProjectBillingInfo` y `SetIamPolicy`)
Muestra los logs del servicio `billing-security-watchdog` en Cloud Run:
- **Tier 1A (Proyecto no registrado):** Si alguien (incluso con un rol heredado antiguo) vincula un proyecto saltándose el Broker API, el *Org Aggregated Log Sink* dispara el Watchdog por Pub/Sub; al no existir registro en `approved_project_bindings` ni *lease* activo en Firestore, **en modo `ENFORCE` lo desvincula en `<10 segundos`**.
- **Tier 1B (`SetIamPolicy` sospechoso):** Si alguien añade un `@gmail.com` o una Service Account externa (`@atacante.iam.gserviceaccount.com`) en la subcuenta de facturación, dispara alerta crítica `P1_CRITICAL` al instante.
- **Reconciliador cada 15 min:** Cloud Scheduler barre todas las subcuentas paginando `nextPageToken` para garantizar cero deriva incluso ante pérdidas puntuales de eventos.

---

## Resumen de Valor para Cerrar con el Partner

1. **Eliminación total del riesgo mayorista:** 0 clientes con `roles/billing.user` o `roles/billing.admin` permanentes.
2. **Aislamiento 1:1 y cero claves estáticas:** Cada cliente tiene su propia SA sin JSON descargables ni acceso a datos/cargas de trabajo.
3. **Defensa en profundidad automatizada:** Bloqueo preventivo (`getAncestry` + *Velocity Gate*) + detección/desvinculación reactiva en `<10s` (Watchdog) + presupuestos base creados desde el segundo cero.
