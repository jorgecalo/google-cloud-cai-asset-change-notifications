output "crypto_key_id" {
  description = "Pass this value as kms_crypto_key_id to the notifier module."
  value       = google_kms_crypto_key.this.id
}

output "encrypt_command" {
  description = "Command that encrypts the Slack bot token for slack_bot_token_ciphertext."
  value       = <<-EOT
    printf '%s' "$SLACK_BOT_TOKEN" | gcloud kms encrypt \
      --project ${var.project_id} \
      --location ${var.kms_location} \
      --keyring ${google_kms_key_ring.this.name} \
      --key ${google_kms_crypto_key.this.name} \
      --plaintext-file - \
      --ciphertext-file - | base64 | tr -d '\n'
  EOT
}
