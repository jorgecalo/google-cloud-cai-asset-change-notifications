#------------------------------------------------------------------------------
# Google Cloud Asset Inventory (CAI) & SCC Crown Jewel Notifications to Slack
# Stage 2: apply after the kms module in ./kms.
#------------------------------------------------------------------------------

data "google_project" "this" {
  project_id = var.project_id
}

###############################################################################
# Enable required APIs
###############################################################################

locals {
  services = toset([
    "artifactregistry.googleapis.com",
    "binaryauthorization.googleapis.com",
    "cloudasset.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "container.googleapis.com",
    "eventarc.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "orgpolicy.googleapis.com",
    "pubsub.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "securitycenter.googleapis.com",
    "servicenetworking.googleapis.com",
    "storage.googleapis.com",
  ])

  pubsub_service_agent = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

resource "google_project_service" "services" {
  for_each           = local.services
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# Provision the Cloud Asset Inventory Service Agent identity so it can publish
# real-time asset change notifications to the Pub/Sub topic.
resource "google_project_service_identity" "cai_service_agent" {
  provider = google-beta
  project  = var.project_id
  service  = "cloudasset.googleapis.com"

  depends_on = [google_project_service.services]
}

###############################################################################
# Pub/Sub topic, Cloud Asset Inventory Feeds & Optional SCC v2 Notification
###############################################################################

resource "google_pubsub_topic" "cai_changes" {
  project = var.project_id
  name    = var.topic_name

  message_storage_policy {
    allowed_persistence_regions = var.pubsub_allowed_persistence_regions
  }

  depends_on = [google_project_service.services]
}

# Grant the Cloud Asset Inventory service agent permission to publish to the topic.
resource "google_pubsub_topic_iam_member" "cai_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.cai_changes.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_project_service_identity.cai_service_agent.email}"
}

# Organization-wide CAI feed for Crown Jewel RESOURCE configuration changes
# (Compute VMs, VPC Networks, Subnetworks, Firewalls, Secret Manager, KMS, Org Policies, etc.)
resource "google_cloud_asset_organization_feed" "crown_jewels_resources" {
  billing_project = var.project_id
  org_id          = var.org_id
  feed_id         = var.resource_feed_id
  content_type    = "RESOURCE"
  asset_types     = var.monitored_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.cai_changes.id
    }
  }

  dynamic "condition" {
    for_each = var.feed_condition_expression != "" ? [1] : []
    content {
      expression  = var.feed_condition_expression
      title       = "custom_cai_filter"
      description = "Custom CEL condition for Crown Jewel resource changes"
    }
  }

  depends_on = [
    google_project_service.services,
    google_pubsub_topic_iam_member.cai_publisher,
  ]
}

# Organization-wide CAI feed for IAM_POLICY changes on Crown Jewel assets
resource "google_cloud_asset_organization_feed" "crown_jewels_iam" {
  count           = var.enable_iam_feed ? 1 : 0
  billing_project = var.project_id
  org_id          = var.org_id
  feed_id         = var.iam_feed_id
  content_type    = "IAM_POLICY"
  asset_types     = var.monitored_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.cai_changes.id
    }
  }

  depends_on = [
    google_project_service.services,
    google_pubsub_topic_iam_member.cai_publisher,
  ]
}

# Organization-wide CAI feed for ORG_POLICY constraint changes across Org/Folders/Projects
resource "google_cloud_asset_organization_feed" "crown_jewels_org_policy" {
  count           = var.enable_org_policy_feed ? 1 : 0
  billing_project = var.project_id
  org_id          = var.org_id
  feed_id         = var.org_policy_feed_id
  content_type    = "ORG_POLICY"
  asset_types = [
    "cloudresourcemanager.googleapis.com/Organization",
    "cloudresourcemanager.googleapis.com/Folder",
    "cloudresourcemanager.googleapis.com/Project",
  ]

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.cai_changes.id
    }
  }

  depends_on = [
    google_project_service.services,
    google_pubsub_topic_iam_member.cai_publisher,
  ]
}

# Optional Folder-scoped CAI feed when var.folder_id is specified
resource "google_cloud_asset_folder_feed" "folder_feed" {
  count           = var.folder_id != "" ? 1 : 0
  billing_project = var.project_id
  folder          = var.folder_id
  feed_id         = "${var.resource_feed_id}-folder"
  content_type    = "RESOURCE"
  asset_types     = var.monitored_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.cai_changes.id
    }
  }

  depends_on = [
    google_project_service.services,
    google_pubsub_topic_iam_member.cai_publisher,
  ]
}

# Optional Security Command Center (SCC v2) notification config streaming
# to the same Pub/Sub topic (CAI is natively integrated with SCC).
resource "google_scc_v2_organization_notification_config" "slack" {
  count        = var.enable_scc_notification ? 1 : 0
  config_id    = var.scc_notification_config_id
  organization = var.org_id
  location     = "global"
  description  = "Streams active, unmuted HIGH and CRITICAL SCC findings to the CAI Slack notifier"
  pubsub_topic = google_pubsub_topic.cai_changes.id

  streaming_config {
    filter = var.scc_notification_filter
  }

  depends_on = [google_project_service.services]
}

###############################################################################
# Service accounts and least-privilege IAM
###############################################################################

# Runtime identity of the function and identity of the Eventarc trigger.
resource "google_service_account" "cainotifier" {
  project      = var.project_id
  account_id   = "cainotifier"
  display_name = "CAI & SCC to Slack notifier runtime"
}

# Identity used by Cloud Build to build the function.
resource "google_service_account" "build" {
  project      = var.project_id
  account_id   = "cainotifier-build"
  display_name = "CAI & SCC to Slack notifier build"
}

resource "google_project_iam_member" "build_builder" {
  project = var.project_id
  role    = "roles/cloudbuild.builds.builder"
  member  = google_service_account.build.member
}

resource "google_project_iam_member" "trigger_event_receiver" {
  project = var.project_id
  role    = "roles/eventarc.eventReceiver"
  member  = google_service_account.cainotifier.member
}

# Allow the runtime service account to query Cloud Audit Logs for Who/How
# attribution (User vs Service Account, Console vs Terraform vs gcloud CLI).
resource "google_project_iam_member" "audit_log_viewer" {
  count   = var.enable_audit_log_lookup ? 1 : 0
  project = var.project_id
  role    = "roles/logging.viewer"
  member  = google_service_account.cainotifier.member
}

resource "google_organization_iam_member" "org_audit_log_viewer" {
  count  = var.enable_audit_log_lookup ? 1 : 0
  org_id = var.org_id
  role   = "roles/logging.viewer"
  member = google_service_account.cainotifier.member
}

# Lets Pub/Sub mint tokens for authenticated push to the function.
resource "google_service_account_iam_member" "pubsub_token_creator" {
  service_account_id = google_service_account.cainotifier.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = local.pubsub_service_agent

  depends_on = [google_project_service.services]
}

# The trigger identity may invoke only this function's Cloud Run service.
# Public access (allUsers) is strictly prohibited.
resource "google_cloud_run_v2_service_iam_member" "trigger_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloudfunctions2_function.cf.name
  role     = "roles/run.invoker"
  member   = google_service_account.cainotifier.member
}

###############################################################################
# KMS-encrypted Slack bot token in Secret Manager
###############################################################################

data "google_kms_secret" "slack_bot_token" {
  crypto_key = var.kms_crypto_key_id
  ciphertext = var.slack_bot_token_ciphertext
}

resource "google_secret_manager_secret" "slack_bot_token" {
  project   = var.project_id
  secret_id = "cainotifier-slack-bot-token"

  replication {
    user_managed {
      dynamic "replicas" {
        for_each = var.secret_replica_locations
        content {
          location = replicas.value
        }
      }
    }
  }

  depends_on = [google_project_service.services]
}

resource "google_secret_manager_secret_version" "slack_bot_token" {
  secret      = google_secret_manager_secret.slack_bot_token.id
  secret_data = data.google_kms_secret.slack_bot_token.plaintext
}

resource "google_secret_manager_secret_iam_member" "slack_bot_token" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.slack_bot_token.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.cainotifier.member
}

###############################################################################
# Function source archive & storage bucket
###############################################################################

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "google_storage_bucket" "function_source" {
  project                     = var.project_id
  name                        = "${var.project_id}-cai-notifier-src-${random_id.bucket_suffix.hex}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  depends_on = [google_project_service.services]
}

data "archive_file" "source" {
  type        = "zip"
  source_dir  = "${path.module}/../app/cai-asset-change-notifications"
  output_path = "${path.module}/.build/function-source.zip"
  excludes    = ["__pycache__", "**/__pycache__/**", "**/*.pyc", ".venv", "**/.venv/**"]
}

# The MD5 in the object name makes every code change redeploy the function.
resource "google_storage_bucket_object" "source" {
  name         = "function-source-${data.archive_file.source.output_md5}.zip"
  bucket       = google_storage_bucket.function_source.name
  source       = data.archive_file.source.output_path
  content_type = "application/zip"
}

###############################################################################
# Cloud Run function (2nd gen)
###############################################################################

resource "google_cloudfunctions2_function" "cf" {
  project     = var.project_id
  location    = var.region
  name        = var.function_name
  description = "Cloud Asset Inventory (CAI) & SCC Crown Jewel change notifier to Slack"

  build_config {
    runtime         = var.function_runtime
    entry_point     = "send_slack_chat_notification"
    service_account = google_service_account.build.id

    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.source.name
      }
    }
  }

  service_config {
    available_memory               = "256M"
    timeout_seconds                = 60
    max_instance_count             = var.max_instance_count
    ingress_settings               = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision = true
    service_account_email          = google_service_account.cainotifier.email

    environment_variables = {
      GCP_PROJECT             = var.project_id
      SLACK_CHANNEL           = var.slack_channel
      ALLOWED_PROJECTS        = join(",", var.allowed_projects)
      MONITORED_ASSET_TYPES   = join(",", var.monitored_asset_types)
      ENABLE_AUDIT_LOG_LOOKUP = tostring(var.enable_audit_log_lookup)
      DEDUP_WINDOW_SECONDS    = tostring(var.dedup_window_seconds)
      MAX_EVENT_AGE_SECONDS   = tostring(var.max_event_age_seconds)
    }

    secret_environment_variables {
      key        = "SLACK_BOT_TOKEN"
      project_id = var.project_id
      secret     = google_secret_manager_secret.slack_bot_token.secret_id
      version    = "latest"
    }
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic          = google_pubsub_topic.cai_changes.id
    retry_policy          = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.cainotifier.email
  }

  depends_on = [
    google_project_service.services,
    google_project_iam_member.build_builder,
    google_project_iam_member.trigger_event_receiver,
    google_secret_manager_secret_iam_member.slack_bot_token,
    google_secret_manager_secret_version.slack_bot_token,
  ]
}
