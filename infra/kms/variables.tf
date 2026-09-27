variable "project_id" {
  description = "Project that holds the KMS key ring. Usually the same project as the notifier."
  type        = string
}

variable "kms_location" {
  description = "Location of the key ring."
  type        = string
  default     = "europe-west4"
}

variable "key_ring_name" {
  description = "Name of the KMS key ring."
  type        = string
  default     = "cai-slack-notifier"
}

variable "crypto_key_name" {
  description = "Name of the symmetric crypto key used to encrypt the Slack bot token."
  type        = string
  default     = "slack-bot-token"
}

variable "rotation_period" {
  description = "Automatic key rotation period. Old key versions stay available for decryption."
  type        = string
  default     = "7776000s" # 90 days
}

variable "encrypter_members" {
  description = "IAM members allowed to encrypt the Slack bot token, for example [\"group:secops@example.com\"]."
  type        = list(string)
  default     = []
}

variable "decrypter_members" {
  description = "IAM members that run the notifier Terraform and must decrypt the ciphertext, for example [\"serviceAccount:terraform@my-project.iam.gserviceaccount.com\"]."
  type        = list(string)
  default     = []
}
