# Firestore Native Database for Tenant Registry, Write-Ahead Leases & Approved Bindings
resource "google_firestore_database" "broker_db" {
  project                           = var.broker_project_id
  name                              = "(default)"
  location_id                       = var.region
  type                              = "FIRESTORE_NATIVE"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"
  delete_protection_state           = "DELETE_PROTECTION_ENABLED"

  depends_on = [google_project_service.platform_apis]
}

# Composite Index 1: Broker hourly velocity guardrail query (tenant_id + created_at)
resource "google_firestore_index" "link_requests_velocity" {
  project    = var.broker_project_id
  database   = google_firestore_database.broker_db.name
  collection = "link_requests"

  fields {
    field_path = "tenant_id"
    order      = "ASCENDING"
  }
  fields {
    field_path = "created_at"
    order      = "ASCENDING"
  }
}

# Composite Index 2: Watchdog write-ahead lease check (project_id + state)
resource "google_firestore_index" "link_requests_lease" {
  project    = var.broker_project_id
  database   = google_firestore_database.broker_db.name
  collection = "link_requests"

  fields {
    field_path = "project_id"
    order      = "ASCENDING"
  }
  fields {
    field_path = "state"
    order      = "ASCENDING"
  }
}

resource "google_project_iam_member" "orchestrator_datastore_user" {
  project = var.broker_project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.broker_orchestrator.email}"
}

# Billing Broker Cloud Run API (Warm min-instance = 1 in prod for <3.5s P95 latency)
resource "google_cloud_run_v2_service" "billing_broker_api" {
  project  = var.broker_project_id
  name     = "billing-broker-api"
  location = var.region
  ingress  = var.broker_ingress

  depends_on = [google_project_service.platform_apis]

  template {
    service_account = google_service_account.broker_orchestrator.email

    scaling {
      min_instance_count = var.min_instance_count
      max_instance_count = 20
    }

    containers {
      image = var.broker_container_image

      env {
        name  = "FIRESTORE_PROJECT_ID"
        value = var.broker_project_id
      }
      env {
        name  = "LEASE_TTL_SECONDS"
        value = "90"
      }
      env {
        name  = "FINOPS_APPROVER_EMAILS"
        value = var.finops_approver_emails
      }
    }
  }
}

# ============================================================================
# IMMUTABLE SECOPS PLANE: REAL-TIME AUDIT SINK & SECURITY WATCHDOG
# ============================================================================

resource "google_service_account" "security_watchdog" {
  project      = var.secops_project_id
  account_id   = "sa-security-watchdog"
  display_name = "Real-Time Billing Security Watchdog"

  depends_on = [google_project_service.platform_apis]
}

resource "google_service_account" "watchdog_invoker" {
  project      = var.secops_project_id
  account_id   = "sa-watchdog-pubsub-invoker"
  display_name = "Pub/Sub & Scheduler Invoker for Billing Watchdog"

  depends_on = [google_project_service.platform_apis]
}

# Watchdog reads/updates Approved Project Bindings and Security Incidents in Firestore
resource "google_project_iam_member" "watchdog_datastore_user" {
  project = var.broker_project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.security_watchdog.email}"
}

# Grant Watchdog custom detach permissions on each managed Subaccount
resource "google_billing_account_iam_member" "watchdog_subaccount_access" {
  for_each = var.tenants

  billing_account_id = each.value.billing_subaccount_id
  role               = google_organization_iam_custom_role.billing_watchdog.name
  member             = "serviceAccount:${google_service_account.security_watchdog.email}"
}

# Pub/Sub Topic receiving Real-Time Cloud Billing Admin Activity Logs
resource "google_pubsub_topic" "billing_admin_events" {
  project                    = var.secops_project_id
  name                       = "billing-admin-events"
  message_retention_duration = "604800s" # 7 days

  depends_on = [google_project_service.platform_apis]
}

# Dead-Letter Queue (DLQ) Topic for poison/undeliverable audit log events
resource "google_pubsub_topic" "billing_admin_events_dlq" {
  project                    = var.secops_project_id
  name                       = "billing-admin-events-dlq"
  message_retention_duration = "1209600s" # 14 days

  depends_on = [google_project_service.platform_apis]
}

# Organization-Level Aggregated Audit Log Sink (include_children = true)
resource "google_logging_organization_sink" "billing_audit_sink" {
  name             = "org-billing-security-watchdog-sink"
  org_id           = var.partner_org_id
  include_children = true
  destination      = "pubsub.googleapis.com/projects/${var.secops_project_id}/topics/${google_pubsub_topic.billing_admin_events.name}"

  filter = <<-EOT
    logName:"cloudaudit.googleapis.com%2Factivity"
    AND protoPayload.serviceName="cloudbilling.googleapis.com"
    AND (
      protoPayload.methodName="UpdateProjectBillingInfo" OR
      protoPayload.methodName="google.cloud.billing.v1.CloudBilling.UpdateProjectBillingInfo" OR
      protoPayload.methodName="SetIamPolicy" OR
      protoPayload.methodName="google.iam.v1.IAMPolicy.SetIamPolicy"
    )
  EOT

  depends_on = [google_project_service.platform_apis]
}

resource "google_pubsub_topic_iam_member" "sink_publisher" {
  project = var.secops_project_id
  topic   = google_pubsub_topic.billing_admin_events.name
  role    = "roles/pubsub.publisher"
  member  = google_logging_organization_sink.billing_audit_sink.writer_identity
}

# Cloud Run v2 Security Watchdog (Warm instance in prod for <10s MTTR)
resource "google_cloud_run_v2_service" "security_watchdog" {
  project  = var.secops_project_id
  name     = "billing-security-watchdog"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  depends_on = [google_project_service.platform_apis]

  template {
    service_account = google_service_account.security_watchdog.email

    scaling {
      min_instance_count = var.min_instance_count
      max_instance_count = 10
    }

    containers {
      image = var.watchdog_container_image

      env {
        name  = "FIRESTORE_PROJECT_ID"
        value = var.broker_project_id
      }
      env {
        name  = "WATCHDOG_MODE"
        value = var.watchdog_mode
      }
      env {
        name  = "LINKERS_PROJECT_ID"
        value = var.linkers_project_id
      }
      env {
        name  = "ALLOWED_BILLING_PRINCIPALS"
        value = var.allowed_billing_principals
      }
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "watchdog_invoker_binding" {
  project  = var.secops_project_id
  location = var.region
  name     = google_cloud_run_v2_service.security_watchdog.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.watchdog_invoker.email}"
}

# Push Subscription for Instantaneous (<10s) Audit Event Delivery + DLQ
resource "google_pubsub_subscription" "watchdog_push" {
  project = var.secops_project_id
  name    = "billing-admin-events-watchdog-push"
  topic   = google_pubsub_topic.billing_admin_events.name

  ack_deadline_seconds = 30

  push_config {
    push_endpoint = "${google_cloud_run_v2_service.security_watchdog.uri}/events/audit-log"
    oidc_token {
      service_account_email = google_service_account.watchdog_invoker.email
    }
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.billing_admin_events_dlq.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "2s"
    maximum_backoff = "60s"
  }
}

# 15-Minute Full-State Drift Reconciler (Defense-in-Depth against missed events)
resource "google_cloud_scheduler_job" "drift_reconciler" {
  project   = var.secops_project_id
  region    = var.region
  name      = "billing-subaccount-drift-reconciler-15m"
  schedule  = "*/15 * * * *"
  time_zone = "UTC"

  depends_on = [google_project_service.platform_apis]

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.security_watchdog.uri}/internal/reconcile"
    oidc_token {
      service_account_email = google_service_account.watchdog_invoker.email
    }
  }
}
