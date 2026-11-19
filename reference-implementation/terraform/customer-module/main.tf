terraform {
  required_version = ">= 1.6.0"
}

variable "broker_base_url" {
  description = "Base HTTPS URL of the Partner Billing Broker API (e.g., https://billing-broker.partner.com)."
  type        = string
}

variable "tenant_id" {
  description = "Partner-assigned Tenant ID."
  type        = string
}

variable "project_id" {
  description = "Target GCP Project ID created inside the customer's delegated Folder."
  type        = string
}

variable "cost_center" {
  description = "Customer internal FinOps cost center tag."
  type        = string
}

variable "environment" {
  description = "Deployment tier (PRODUCTION | STAGING | DEVELOPMENT | SANDBOX)."
  type        = string
  default     = "PRODUCTION"
}

variable "monthly_budget_eur" {
  description = "Baseline monthly budget alert threshold in EUR."
  type        = number
  default     = 1000
}

variable "alert_contact_emails" {
  description = "List of customer FinOps/SecOps emails to receive budget notifications."
  type        = list(string)
  default     = []
}

variable "oidc_token" {
  description = "Short-lived CI/CD OIDC token (GitHub Actions / GitLab CI / Terraform Cloud) — never stored in plain logs."
  type        = string
  sensitive   = true
}

# Deterministic idempotency key per tenant + project
locals {
  idempotency_key = uuidv5("url", "${var.broker_base_url}/v1/tenants/${var.tenant_id}/projects/${var.project_id}")
  request_body = jsonencode({
    projectId          = var.project_id
    accessMode         = "FOLDER_DELEGATED"
    costCenter         = var.cost_center
    environment        = var.environment
    monthlyBudgetEur   = var.monthly_budget_eur
    alertContactEmails = var.alert_contact_emails
    justification      = "Automated Terraform provisioning via Mode B Folder Delegation"
  })
}

# Executes synchronous Partner Billing Link + Baseline Budget creation without needing roles/billing.user
resource "terraform_data" "partner_billing_link" {
  triggers_replace = [
    var.tenant_id,
    var.project_id,
  ]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    environment = {
      BROKER_TOKEN = var.oidc_token
      REQ_PAYLOAD  = local.request_body
    }
    command = <<-EOT
      set -euo pipefail
      HTTP_CODE=$(curl -sS -o /tmp/broker_resp_${var.project_id}.json -w "%%{http_code}" \
        -X POST "${var.broker_base_url}/v1/tenants/${var.tenant_id}/billing-links" \
        -H "Authorization: Bearer $BROKER_TOKEN" \
        -H "Content-Type: application/json" \
        -H "Idempotency-Key: ${local.idempotency_key}" \
        -d "$REQ_PAYLOAD")

      if [ "$HTTP_CODE" -ne 200 ] && [ "$HTTP_CODE" -ne 201 ]; then
        echo "Partner Billing Broker rejected link (HTTP $HTTP_CODE):" >&2
        cat /tmp/broker_resp_${var.project_id}.json >&2
        rm -f /tmp/broker_resp_${var.project_id}.json
        exit 1
      fi
      rm -f /tmp/broker_resp_${var.project_id}.json
    EOT
  }
}

output "linked_project_id" {
  description = "Project ID after verified Partner Billing Subaccount attachment (use in depends_on for google_project_service)."
  value       = var.project_id
  depends_on  = [terraform_data.partner_billing_link]
}
