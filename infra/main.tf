#------------------------------------------------------------------------------
# Google Cloud Cloud Asset Inventor (CAI) Asset Change notifications to Slack
#------------------------------------------------------------------------------

###############################################################################
# Enable APIs - Enable required APIs for deployment
###############################################################################

resource "google_project_service" "compute" {
  service                    = "compute.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_project_service" "service_networking" {
  service                    = "servicenetworking.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_project_service" "secretmanager" {
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

###############################################################################
# Deployment of required resource for running CAI notifictions to Slack 
###############################################################################

# Create a feed that sends notifications about network resource updates under a
# particular folder.

resource "google_cloud_asset_folder_feed" "folder_feed" {
  billing_project = "my-project-name"
  folder          = google_folder.my_folder.folder_id
  feed_id         = "network-updates"
  content_type    = "RESOURCE"

  # Define the CAI Asset Types to receive alerts for. 
  asset_types = [
    "compute.googleapis.com/Subnetwork",
    "compute.googleapis.com/Network",
  ]

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.feed_output.id
    }
  }

  condition {
    expression  = <<-EOT
    !temporal_asset.deleted &&
    temporal_asset.prior_asset_state == google.cloud.asset.v1.TemporalAsset.PriorAssetState.DOES_NOT_EXIST
    EOT
    title       = "created"
    description = "Send notifications on creation events"
  }
}

# The topic where the resource change notifications will be sent.
resource "google_pubsub_topic" "feed_output" {
  project = "my-project-name"
  name    = "network-updates"
}

# The folder that will be monitored for resource updates.
resource "google_folder" "my_folder" {
  display_name = "Networking"
  parent       = "organizations/123456789"
}

# Find the project number of the project whose identity will be used for sending
# the asset change notifications.
data "google_project" "project" {
  project_id = "my-project-name"
}

#Create Google Storage bucket that will host source code in region Europe West1
resource "google_storage_bucket" "function_bucket" {
  project                     = var.gcp_project_id
  name                        = "cai-slack-notifier-cf-bucket"
  location                    = var.gcp_region
  uniform_bucket_level_access = true
}

#Generate an archive of the source code compressed as a .zip file. Source is stored in the Terraform directory /app/
data "archive_file" "source" {
  type        = "zip"
  source_dir  = "${path.root}/app/cai-asset-change-notifications"
  output_path = "${path.root}/cf-cai-notification.zip"
}

# Add source code zip to bucket
resource "google_storage_bucket_object" "zip" {
  # Append file MD5 to force bucket to be recreated
  name         = "cf-cai-notification.zip"
  bucket       = google_storage_bucket.function_bucket.name
  source       = data.archive_file.source.output_path
  content_type = "application/zip"
}

# Other code // Added later

resource "google_pubsub_topic" "asset_inventory_topic" {
  name = "asset-inventory-topic"
}

resource "google_cloudfunctions_function" "asset_inventory_function" {
  project     = var.gcp_project_id
  region      = var.gcp_region
  name        = "asset-inventory-function"
  description = "Cloud Asset Inventory feed and send alerts to Slack"
  runtime     = "python310"

  timeout             = 540
  available_memory_mb = 256
  max_instances       = 2
  ingress_settings    = "ALLOW_INTERNAL_AND_GCLB"


  source_archive_bucket = google_storage_bucket.function_bucket.name
  source_archive_object = google_storage_bucket_object.zip.name

  trigger_topic = google_pubsub_topic.asset_inventory_topic.name

  entry_point = "asset_inventory_to_slack"

  environment_variables = {
    SLACK_BOT_TOKEN = format("%s/versions/latest", google_secret_manager_secret.slack_bot_token.id)
  }
}

# Create Secret Manager resource for Slack Bot token. Defined project in resource.
resource "google_secret_manager_secret" "slack_bot_token" {
  project   = var.gcp_project_id
  secret_id = "cainotifier-slack-bot-token"
  replication {
    user_managed {
      replicas {
        location = var.gcp_region
      }
      replicas {
        location = var.gcp_region-2
      }
    }

  }
}

#Secret Manager grant access right to secret.
resource "google_secret_manager_secret_iam_binding" "slack_bot_token" {
  role      = "roles/secretmanager.secretAccessor"
  secret_id = google_secret_manager_secret.slack_bot_token.id
  members = [
    format("serviceAccount:%s", google_service_account.cainotifier.email)
  ]
}

resource "google_secret_manager_secret_version" "slack_bot_token" {
  secret      = google_secret_manager_secret.slack_bot_token.id
  secret_data = "?"

}

resource "google_cloudfunctions_function_iam_binding" "asset_inventory_function_binding" {
  project        = google_cloudfunctions_function.asset_inventory_function.project
  region         = google_cloudfunctions_function.asset_inventory_function.region
  cloud_function = google_cloudfunctions_function.asset_inventory_function.name

  role    = "roles/cloudfunctions.invoker"
  members = ["allUsers"]
}


