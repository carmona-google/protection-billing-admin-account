output "broker_api_uri" {
  description = "Internal Load Balancer / Cloud Run URI of the Billing Broker API."
  value       = google_cloud_run_v2_service.billing_broker_api.uri
}

output "watchdog_uri" {
  description = "Cloud Run URI of the Real-Time Security Watchdog."
  value       = google_cloud_run_v2_service.security_watchdog.uri
}

output "tenant_linker_service_accounts" {
  description = "Dedicated 1:1 Tenant Linker Service Account emails to share with each customer."
  value       = { for k, sa in google_service_account.tenant_linker : k => sa.email }
}
