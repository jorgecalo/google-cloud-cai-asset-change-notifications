###############################################################################
# General
###############################################################################

variable "org_id" {
  description = "Numeric Google Cloud organization ID where Cloud Asset Inventory and SCC are activated."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.org_id))
    error_message = "org_id must contain digits only, without spaces or tabs."
  }
}

variable "folder_id" {
  description = "Optional numeric folder ID if you also want a folder-scoped CAI feed. Leave empty to use organization-level feeds only."
  type        = string
  default     = ""

  validation {
    condition     = var.folder_id == "" || can(regex("^[0-9]+$", var.folder_id))
    error_message = "folder_id must be empty or contain digits only."
  }
}

variable "project_id" {
  description = "Project that hosts the Pub/Sub topic, Cloud Run function, Secret Manager secret, and source bucket."
  type        = string
}

variable "region" {
  description = "Region for the Cloud Run function, Eventarc trigger, and source bucket."
  type        = string
  default     = "europe-west1"
}

###############################################################################
# Cloud Asset Inventory (CAI) & Crown Jewels Monitoring
###############################################################################

variable "resource_feed_id" {
  description = "ID of the Cloud Asset Inventory feed for Crown Jewel RESOURCE configuration changes."
  type        = string
  default     = "cai-crown-jewels-resource-feed"
}

variable "iam_feed_id" {
  description = "ID of the Cloud Asset Inventory feed for Crown Jewel IAM_POLICY changes."
  type        = string
  default     = "cai-crown-jewels-iam-feed"
}

variable "enable_iam_feed" {
  description = "Whether to create a second CAI feed monitoring IAM_POLICY changes across Crown Jewel resources."
  type        = bool
  default     = true
}

variable "org_policy_feed_id" {
  description = "ID of the Cloud Asset Inventory feed for Organization Policy (ORG_POLICY) constraint changes."
  type        = string
  default     = "cai-crown-jewels-org-policy-feed"
}

variable "enable_org_policy_feed" {
  description = "Whether to create a CAI feed monitoring ORG_POLICY changes across the organization, folders, and projects."
  type        = bool
  default     = true
}

variable "monitored_asset_types" {
  description = "Crown Jewel CAI Asset Types to monitor for configuration, IAM, and Organization Policy changes (compute, VPC networking, hybrid connectivity, firewall rules, secrets, KMS keys, IAM, Org Policies, Cloud SQL, BigQuery)."
  type        = list(string)
  default = [
    # Compute resources
    "compute.googleapis.com/Instance",
    "compute.googleapis.com/InstanceTemplate",
    # VPC Networking, Firewall rules & Hybrid Connectivity
    "compute.googleapis.com/Firewall",
    "compute.googleapis.com/FirewallPolicy",
    "compute.googleapis.com/Network",
    "compute.googleapis.com/Subnetwork",
    "compute.googleapis.com/Route",
    "compute.googleapis.com/Router",
    "compute.googleapis.com/VpnTunnel",
    "compute.googleapis.com/HaVpnGateway",
    "compute.googleapis.com/InterconnectAttachment",
    "networksecurity.googleapis.com/AuthorizationPolicy",
    "networksecurity.googleapis.com/ServerTlsPolicy",
    # Secret & Cryptographic Crown Jewels
    "secretmanager.googleapis.com/Secret",
    "secretmanager.googleapis.com/SecretVersion",
    "cloudkms.googleapis.com/CryptoKey",
    "cloudkms.googleapis.com/KeyRing",
    # Identity, Access (IAM) & Organization Policy Crown Jewels
    "iam.googleapis.com/ServiceAccount",
    "iam.googleapis.com/ServiceAccountKey",
    "iam.googleapis.com/Role",
    "iam.googleapis.com/WorkloadIdentityPool",
    "iam.googleapis.com/WorkloadIdentityPoolProvider",
    "orgpolicy.googleapis.com/Policy",
    "orgpolicy.googleapis.com/CustomConstraint",
    "cloudresourcemanager.googleapis.com/Organization",
    "cloudresourcemanager.googleapis.com/Folder",
    "cloudresourcemanager.googleapis.com/Project",
    # Data Sources (Cloud SQL, BigQuery, Cloud Storage)
    "sqladmin.googleapis.com/Instance",
    "bigquery.googleapis.com/Dataset",
    "bigquery.googleapis.com/Table",
    "storage.googleapis.com/Bucket",
    # Kubernetes (GKE), Service Mesh, Cloud Run & Binary Authorization Crown Jewels
    "container.googleapis.com/Cluster",
    "container.googleapis.com/NodePool",
    "gkehub.googleapis.com/Membership",
    "gkehub.googleapis.com/Feature",
    "run.googleapis.com/Service",
    "run.googleapis.com/Job",
    "run.googleapis.com/DomainMapping",
    "binaryauthorization.googleapis.com/Policy",
    "binaryauthorization.googleapis.com/Attestor",
  ]
}

variable "feed_condition_expression" {
  description = "Optional CEL condition expression for the CAI resource feed. Default alerts on all creations, updates, and deletions."
  type        = string
  default     = ""
}

variable "allowed_projects" {
  description = "Optional project IDs or display names to notify on. Empty means all projects in the organization."
  type        = list(string)
  default     = []
}

variable "enable_audit_log_lookup" {
  description = "Whether the Cloud Run function should query Cloud Audit Logs to enrich Who (User vs Service Account) and How (Console, Terraform, or gcloud CLI)."
  type        = bool
  default     = true
}

variable "dedup_window_seconds" {
  description = "Cooldown window in seconds to deduplicate identical asset change notifications."
  type        = number
  default     = 60
}

###############################################################################
# Security Command Center (SCC v2) Integration
###############################################################################

variable "enable_scc_notification" {
  description = "Also stream active HIGH/CRITICAL Security Command Center (SCC v2) findings for Crown Jewel assets to the same Slack notifier."
  type        = bool
  default     = false
}

variable "scc_notification_config_id" {
  description = "ID of the optional SCC v2 organization notification config."
  type        = string
  default     = "cai-scc-slack-notifier"
}

variable "scc_notification_filter" {
  description = "Filter for optional SCC v2 findings notification config."
  type        = string
  default     = "(severity=\"HIGH\" OR severity=\"CRITICAL\") AND state=\"ACTIVE\" AND -mute=\"MUTED\""
}

###############################################################################
# Pub/Sub
###############################################################################

variable "topic_name" {
  description = "Pub/Sub topic where Cloud Asset Inventory (and optionally SCC) publishes notifications."
  type        = string
  default     = "cai-asset-changes-topic"
}

variable "pubsub_allowed_persistence_regions" {
  description = "Regions where Pub/Sub may store messages."
  type        = list(string)
  default     = ["europe-west1", "europe-west4"]
}

###############################################################################
# Slack and KMS-Encrypted Secrets
###############################################################################

variable "slack_channel" {
  description = "Slack channel ID (recommended, for example C0123456789) or channel name. Invite the bot to the channel."
  type        = string
  default     = "security-gcp-alerts"
}

variable "kms_crypto_key_id" {
  description = "Crypto key ID from the kms module output crypto_key_id."
  type        = string
}

variable "slack_bot_token_ciphertext" {
  description = "Base64 KMS ciphertext of the Slack bot token. See the kms module output encrypt_command."
  type        = string
  sensitive   = true

  validation {
    condition     = !startswith(var.slack_bot_token_ciphertext, "REPLACE-") && can(regex("^[A-Za-z0-9+/]+={0,2}$", var.slack_bot_token_ciphertext))
    error_message = "Replace the placeholder with the single line base64 KMS ciphertext of the Slack bot token."
  }
}

variable "secret_replica_locations" {
  description = "Secret Manager replica locations for secrets."
  type        = list(string)
  default     = ["europe-west1", "europe-west4"]
}

###############################################################################
# Cloud Run Function (2nd Gen)
###############################################################################

variable "function_name" {
  description = "Name of the Cloud Run function."
  type        = string
  default     = "cai-slack-notifier"
}

variable "function_runtime" {
  description = "Python runtime. python313 is supported until October 2029."
  type        = string
  default     = "python313"
}

variable "max_instance_count" {
  description = "Maximum function instances. Keep low to respect Slack rate limits."
  type        = number
  default     = 3
}

variable "max_event_age_seconds" {
  description = "Events older than this are dropped instead of being retried."
  type        = number
  default     = 3600
}
