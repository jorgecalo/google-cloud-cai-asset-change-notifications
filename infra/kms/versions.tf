terraform {
  required_version = ">= 1.9"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.0"
    }
  }

  # Store state remotely and restrict access to it. Example:
  # backend "gcs" {
  #   bucket = "my-terraform-state-bucket"
  #   prefix = "cai-slack-notifier/kms"
  # }
}

provider "google" {
  project = var.project_id
}
