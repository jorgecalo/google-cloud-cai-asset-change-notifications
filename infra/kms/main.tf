#------------------------------------------------------------------------------
# Stage 1: Cloud KMS key ring and crypto key for the Slack bot token.
# Apply this module before the notifier module in the parent directory.
#------------------------------------------------------------------------------

resource "google_project_service" "cloudkms" {
  project            = var.project_id
  service            = "cloudkms.googleapis.com"
  disable_on_destroy = false
}

resource "google_kms_key_ring" "this" {
  project  = var.project_id
  name     = var.key_ring_name
  location = var.kms_location

  depends_on = [google_project_service.cloudkms]
}

resource "google_kms_crypto_key" "this" {
  name            = var.crypto_key_name
  key_ring        = google_kms_key_ring.this.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.rotation_period

  # Destroying the key makes the stored ciphertext unrecoverable.
  lifecycle {
    prevent_destroy = true
  }
}

# Access is granted on the key only, not on the whole project.
resource "google_kms_crypto_key_iam_member" "encrypter" {
  for_each      = toset(var.encrypter_members)
  crypto_key_id = google_kms_crypto_key.this.id
  role          = "roles/cloudkms.cryptoKeyEncrypter"
  member        = each.value
}

resource "google_kms_crypto_key_iam_member" "decrypter" {
  for_each      = toset(var.decrypter_members)
  crypto_key_id = google_kms_crypto_key.this.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = each.value
}
