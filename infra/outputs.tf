output "function_name" {
  description = "Deployed Cloud Run function (2nd gen) name."
  value       = google_cloudfunctions2_function.cf.name
}

output "pubsub_topic" {
  description = "Pub/Sub topic receiving CAI and SCC notifications."
  value       = google_pubsub_topic.cai_changes.id
}

output "resource_feed_name" {
  description = "Organization-level CAI resource feed name."
  value       = google_cloud_asset_organization_feed.crown_jewels_resources.name
}

output "iam_feed_name" {
  description = "Organization-level CAI IAM policy feed name."
  value       = var.enable_iam_feed ? google_cloud_asset_organization_feed.crown_jewels_iam[0].name : null
}

output "runtime_service_account" {
  description = "Least-privilege runtime and Eventarc trigger service account email."
  value       = google_service_account.cainotifier.email
}
