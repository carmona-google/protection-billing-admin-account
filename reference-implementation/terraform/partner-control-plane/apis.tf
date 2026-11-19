variable "enable_apis" {
  description = "Automatically enable required GCP APIs on the target project(s)."
  type        = bool
  default     = true
}

locals {
  unique_platform_projects = toset([
    var.broker_project_id,
    var.linkers_project_id,
    var.secops_project_id,
  ])

  required_apis = [
    "artifactregistry.googleapis.com",
    "billingbudgets.googleapis.com",
    "cloudbilling.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "cloudscheduler.googleapis.com",
    "firestore.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "pubsub.googleapis.com",
    "run.googleapis.com",
  ]

  project_api_pairs = var.enable_apis ? merge([
    for proj in local.unique_platform_projects : {
      for api in local.required_apis : "${proj}/${api}" => {
        project = proj
        service = api
      }
    }
  ]...) : {}
}

resource "google_project_service" "platform_apis" {
  for_each = local.project_api_pairs

  project            = each.value.project
  service            = each.value.service
  disable_on_destroy = false
}
