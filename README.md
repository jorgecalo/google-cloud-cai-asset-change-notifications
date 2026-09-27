<div align="center">

# 🛡️ Cloud Asset Inventory (CAI) & SCC Crown Jewel Change Notifications to Slack

**Real-time Google Cloud Asset Inventory (CAI) & Security Command Center (SCC) change alerts for your Crown Jewel resources in Slack.**

![Terraform](https://img.shields.io/badge/Terraform-%E2%89%A51.9-7B42BC?logo=terraform&logoColor=white)
![Google provider](https://img.shields.io/badge/google%20provider-~%3E%208.0-4285F4?logo=googlecloud&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)
![Cloud Run functions](https://img.shields.io/badge/Cloud%20Run%20functions-2nd%20gen-4285F4?logo=googlecloud&logoColor=white)
![Cloud Asset Inventory](https://img.shields.io/badge/Cloud%20Asset%20Inventory-v1%20%2B%20SCC%20v2-34A853?logo=googlecloud&logoColor=white)

</div>

Even when you enforce the **principle of least privilege**, privileged engineers, CI/CD pipelines, or break-glass accounts still require access to your organization's **Crown Jewels**—critical VPC firewall rules, production compute instances, VPC networks, **IAM policies & service accounts**, **Secret Manager vaults**, **Cloud KMS keys**, and **sensitive data sources (Cloud SQL, BigQuery, Cloud Storage)**. Because these resources are so sensitive, any modification requires immediate visibility.

Google Cloud Asset Inventory (natively integrated with **Security Command Center**) streams real-time `RESOURCE` and `IAM_POLICY` changes to a Pub/Sub topic. A 2nd gen **Cloud Run function** computes the **before/after CAI diff**, correlates the event with **Cloud Audit Logs** to attribute **Who** made the change (User vs. Service Account / Impersonation) and **How** it was executed (**Google Cloud Console ClickOps**, **Terraform**, or **`gcloud` CLI**), and posts a rich **Slack Block Kit** alert to your security channel. Everything is deployed with Terraform and secured with **Cloud KMS** secret encryption.

### Component Overview

```mermaid
flowchart LR
    Assets["Crown Jewel Assets
    (VMs, Firewalls, VPCs, IAM, Secrets, KMS, Cloud SQL, BigQuery)"]
    CAI["Cloud Asset Inventory & SCC v2
    (RESOURCE & IAM_POLICY Feeds)"]
    PubSub["Cloud Pub/Sub
    + Eventarc Trigger"]
    Func["Cloud Run Function (2nd gen)
    CAI Diff + Risk & Drift Engine"]
    Audit["Cloud Audit Logs
    Who (User/SA) & How (Console/Terraform/CLI)"]
    KMS["Cloud KMS"]
    SM["Secret Manager
    (Slack Bot Token)"]
    Slack["Slack Channel
    (Block Kit Alert)"]

    Assets -->|State Change| CAI
    CAI -->|TemporalAsset / Finding| PubSub
    PubSub --> Func
    Audit -.->|Enriches Who & How| Func
    KMS -.->|Decrypts at Deploy| SM
    SM -.->|Injects Token| Func
    Func -->|chat.postMessage| Slack
```

---

### What a notification looks like

#### 1️⃣ Crown Jewel VPC Firewall Rule Modified via Google Cloud Console (`ClickOps` Drift Alert)

<table>
  <thead>
    <tr>
      <th colspan="2" align="left">
        🛡️ <b>CAI &amp; SCC Security Notifier</b> &nbsp;<img src="https://img.shields.io/badge/APP-4A154B?logo=slack&logoColor=white" align="absmiddle" alt="Slack App" /> &nbsp;<code>#security-gcp-alerts</code> &nbsp;•&nbsp; <sub>01:15 UTC</sub>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td colspan="2">
        🚨 <b>Crown Jewel Asset Alert</b>: <a href="#-message-content"><b>compute.googleapis.com/Firewall <code>allow-prod-ssh-ingress</code> was MODIFIED</b></a>
      </td>
    </tr>
    <tr>
      <td width="72%" valign="top">
        <b>Resource:</b> <code>allow-prod-ssh-ingress</code><br/>
        <b>Resource type:</b> <code>compute.googleapis.com/Firewall</code><br/>
        <b>Project:</b> <code>prod-networking-01</code> &nbsp;|&nbsp; <b>Location:</b> <code>global</code><br/>
        <b>Action:</b> <b>MODIFIED</b> ✏️ &nbsp;|&nbsp; <b>Event time:</b> <code>2026-09-27T01:15:42.000Z</code>
      </td>
      <td width="28%" align="right" valign="middle">
        <a href="https://console.cloud.google.com/net-security/firewall-manager/firewall-policies"><img src="https://img.shields.io/badge/View_in_Cloud_Console_%E2%86%97-1A73E8?style=for-the-badge&logo=googlecloud&logoColor=white" alt="View in Cloud Console" /></a>
      </td>
    </tr>
    <tr>
      <td colspan="2">
        <b>Change Attribution (Cloud Audit Logs):</b><br/>
        • <b>Who (Actor):</b> <code>j.doe@example.com</code> <i>(User Account)</i><br/>
        • <b>How (Executed via):</b> <b>Google Cloud Console (Web UI / ClickOps) ⚠️</b> &nbsp;<img src="https://img.shields.io/badge/ClickOps-Manual_Change-EA4335?style=flat-square" align="absmiddle" alt="ClickOps" /><br/>
        • <b>API Method:</b> <code>v1.compute.firewalls.patch</code><br/>
        • <b>Caller IP:</b> <code>198.51.100.42</code> &nbsp;|&nbsp; <a href="https://console.cloud.google.com/logs/query">View Audit Trail in Cloud Logging ↗</a>
      </td>
    </tr>
    <tr>
      <td colspan="2">
        <b>Security Posture &amp; Risk Signals:</b><br/>
        • ⚠️ <b>Manual Change Outside IaC (ClickOps / CLI):</b> Executed via Google Cloud Console (Web UI / ClickOps) by <code>j.doe@example.com</code>.<br/>
        • 🚨 <b>Public Internet Ingress (<code>0.0.0.0/0</code>):</b> Firewall rule exposes <code>tcp:22,3389</code> to the public internet.
      </td>
    </tr>
    <tr>
      <td colspan="2">
        <b>Change Diff (Cloud Asset Inventory):</b>
<pre><code>~ allowed: [{"IPProtocol": "tcp", "ports": ["22"]}] -&gt; [{"IPProtocol": "tcp", "ports": ["22", "3389"]}]
+ sourceRanges: added ["0.0.0.0/0"]
- sourceRanges: removed ["10.128.0.0/16"]</code></pre>
      </td>
    </tr>
    <tr>
      <td colspan="2">
        <b>Recommendation:</b><br/>
        Verify whether this manual change was authorized under an emergency break-glass procedure and reconcile it into Terraform to prevent state drift. Restrict <code>sourceRanges</code> to trusted corporate CIDRs, Identity-Aware Proxy (<code>35.235.240.0/20</code>), or internal VPC ranges.
      </td>
    </tr>
  </tbody>
</table>

#### 2️⃣ Production Compute VM Attached External IP via `gcloud` CLI (with Service Account Impersonation)

<table>
  <thead>
    <tr>
      <th colspan="2" align="left">
        🛡️ <b>CAI &amp; SCC Security Notifier</b> &nbsp;<img src="https://img.shields.io/badge/APP-4A154B?logo=slack&logoColor=white" align="absmiddle" alt="Slack App" /> &nbsp;<code>#security-gcp-alerts</code> &nbsp;•&nbsp; <sub>01:22 UTC</sub>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td colspan="2">
        🚨 <b>Crown Jewel Asset Alert</b>: <a href="#-message-content"><b>compute.googleapis.com/Instance <code>prod-payments-db-01</code> was MODIFIED</b></a>
      </td>
    </tr>
    <tr>
      <td width="72%" valign="top">
        <b>Resource:</b> <code>prod-payments-db-01</code><br/>
        <b>Resource type:</b> <code>compute.googleapis.com/Instance</code><br/>
        <b>Project:</b> <code>prod-payments-01</code> &nbsp;|&nbsp; <b>Location:</b> <code>europe-west1-b</code><br/>
        <b>Action:</b> <b>MODIFIED</b> ✏️ &nbsp;|&nbsp; <b>Event time:</b> <code>2026-09-27T01:22:10.000Z</code>
      </td>
      <td width="28%" align="right" valign="middle">
        <a href="https://console.cloud.google.com/compute/instances"><img src="https://img.shields.io/badge/View_in_Cloud_Console_%E2%86%97-1A73E8?style=for-the-badge&logo=googlecloud&logoColor=white" alt="View in Cloud Console" /></a>
      </td>
    </tr>
    <tr>
      <td colspan="2">
        <b>Change Attribution (Cloud Audit Logs):</b><br/>
        • <b>Who (Actor):</b> <code>sre-oncall@example.com</code> <i>(User impersonating Service Account <code>prod-compute-admin@prod-payments-01.iam.gserviceaccount.com</code>)</i><br/>
        • <b>How (Executed via):</b> <b>gcloud CLI (<code>gcloud compute instances add-access-config</code>) ⚠️</b><br/>
        • <b>API Method:</b> <code>v1.compute.instances.addAccessConfig</code><br/>
        • <b>Caller IP:</b> <code>203.0.113.88</code> &nbsp;|&nbsp; <a href="https://console.cloud.google.com/logs/query">View Audit Trail in Cloud Logging ↗</a>
      </td>
    </tr>
    <tr>
      <td colspan="2">
        <b>Security Posture &amp; Risk Signals:</b><br/>
        • ⚠️ <b>Manual Change Outside IaC (ClickOps / CLI):</b> Executed via gcloud CLI.<br/>
        • 🚨 <b>External Public IP Attached:</b> VM instance has <code>ONE_TO_ONE_NAT</code> external IP (<code>34.77.102.19</code>).<br/>
        • 🛡️ <b>Shielded VM Controls Disabled:</b> One or more Shielded VM protections (<code>enableSecureBoot</code>) are disabled.<br/>
        • 💻 <b>Machine Type Changed:</b> <code>n2d-standard-4</code> -&gt; <code>e2-standard-8</code>.
      </td>
    </tr>
    <tr>
      <td colspan="2">
        <b>Change Diff (Cloud Asset Inventory):</b>
<pre><code>~ confidentialInstanceConfig.enableConfidentialCompute: true -&gt; false
~ cpuPlatform: "AMD Milan" -&gt; "Intel Cascade Lake"
~ machineType: ".../machineTypes/n2d-standard-4" -&gt; ".../machineTypes/e2-standard-8"
~ networkInterfaces: added accessConfigs [{"type": "ONE_TO_ONE_NAT", "natIP": "34.77.102.19"}]
~ shieldedInstanceConfig.enableSecureBoot: true -&gt; false</code></pre>
      </td>
    </tr>
  </tbody>
</table>

#### 3️⃣ Secret Manager Crown Jewel IAM Policy Updated via Terraform (`IaC`)

<table>
  <thead>
    <tr>
      <th colspan="2" align="left">
        🛡️ <b>CAI &amp; SCC Security Notifier</b> &nbsp;<img src="https://img.shields.io/badge/APP-4A154B?logo=slack&logoColor=white" align="absmiddle" alt="Slack App" /> &nbsp;<code>#security-gcp-alerts</code> &nbsp;•&nbsp; <sub>01:30 UTC</sub>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td colspan="2">
        🚨 <b>Crown Jewel Asset Alert</b>: <a href="#-message-content"><b>secretmanager.googleapis.com/Secret <code>stripe-live-api-key</code> was MODIFIED</b></a>
      </td>
    </tr>
    <tr>
      <td width="72%" valign="top">
        <b>Resource:</b> <code>stripe-live-api-key</code><br/>
        <b>Resource type:</b> <code>secretmanager.googleapis.com/Secret</code><br/>
        <b>Project:</b> <code>prod-secrets-vault-01</code> &nbsp;|&nbsp; <b>Location:</b> <code>europe-west1</code><br/>
        <b>Action:</b> <b>MODIFIED</b> ✏️ &nbsp;|&nbsp; <b>Event time:</b> <code>2026-09-27T01:30:05.000Z</code>
      </td>
      <td width="28%" align="right" valign="middle">
        <a href="https://console.cloud.google.com/security/secret-manager"><img src="https://img.shields.io/badge/View_in_Cloud_Console_%E2%86%97-1A73E8?style=for-the-badge&logo=googlecloud&logoColor=white" alt="View in Cloud Console" /></a>
      </td>
    </tr>
    <tr>
      <td colspan="2">
        <b>Change Attribution (Cloud Audit Logs):</b><br/>
        • <b>Who (Actor):</b> <code>terraform-ci@prod-automation.iam.gserviceaccount.com</code> <i>(Service Account)</i><br/>
        • <b>How (Executed via):</b> <b>Terraform (Terraform/1.9.8)</b> &nbsp;<img src="https://img.shields.io/badge/IaC-Terraform-7B42BC?style=flat-square&logo=terraform&logoColor=white" align="absmiddle" alt="Terraform" /><br/>
        • <b>API Method:</b> <code>google.iam.v1.IAMPolicy.SetIamPolicy</code><br/>
        • <b>Caller IP:</b> <code>35.190.24.11</code> &nbsp;|&nbsp; <a href="https://console.cloud.google.com/logs/query">View Audit Trail in Cloud Logging ↗</a>
      </td>
    </tr>
    <tr>
      <td colspan="2">
        <b>Security Posture &amp; Risk Signals:</b><br/>
        • 🔒 <b>Crown Jewel Secret / Crypto Asset Modified:</b> Sensitive cryptographic or secret resource was modified.<br/>
        • 🔑 <b>Privileged IAM Role Granted:</b> <code>roles/secretmanager.secretAccessor</code> granted to <code>user:external-contractor@example.com</code>.
      </td>
    </tr>
    <tr>
      <td colspan="2">
        <b>Change Diff (Cloud Asset Inventory):</b>
<pre><code>+ IAM Binding (roles/secretmanager.secretAccessor): added ['user:external-contractor@example.com']</code></pre>
      </td>
    </tr>
  </tbody>
</table>

<details>
<summary><b>▶️ Replay these exact demo messages in your own Slack channel (1 command)</b></summary>

You can preview or post any of the three demo notifications directly into a real Slack channel from your terminal using `--send`:

```bash
# Demo 1: VPC Firewall Rule opened to 0.0.0.0/0 via Google Cloud Console (ClickOps)
SLACK_BOT_TOKEN=xoxb-your-token \
SLACK_CHANNEL=C0123456789 \
python3 app/cai-asset-change-notifications/main.py tests/fixtures/firewall_open_ssh_console.json --send

# Demo 2: Compute Engine VM with External IP & Machine Type changed via gcloud CLI
SLACK_BOT_TOKEN=xoxb-your-token \
SLACK_CHANNEL=C0123456789 \
python3 app/cai-asset-change-notifications/main.py tests/fixtures/compute_vm_external_ip_gcloud.json --send

# Demo 3: Secret Manager IAM Policy modified via Terraform
SLACK_BOT_TOKEN=xoxb-your-token \
SLACK_CHANNEL=C0123456789 \
python3 app/cai-asset-change-notifications/main.py tests/fixtures/secret_manager_iam_terraform.json --send

# Demo 4: IAM Privilege Escalation (existing Service Account gains TokenCreator + added BigQuery Admin role)
SLACK_BOT_TOKEN=xoxb-your-token \
SLACK_CHANNEL=C0123456789 \
python3 app/cai-asset-change-notifications/main.py tests/fixtures/iam_privilege_escalation.json --send

# Demo 5: Cloud SQL Database SSL Enforcement Disabled & Network Access IP Range Expanded
SLACK_BOT_TOKEN=xoxb-your-token \
SLACK_CHANNEL=C0123456789 \
python3 app/cai-asset-change-notifications/main.py tests/fixtures/cloudsql_ssl_and_network_expanded.json --send

# Demo 6: VPC Network Peering Added (with custom route export) & Dynamic Routing Mode Changed
SLACK_BOT_TOKEN=xoxb-your-token \
SLACK_CHANNEL=C0123456789 \
python3 app/cai-asset-change-notifications/main.py tests/fixtures/vpc_network_peering_and_routing.json --send

# Demo 7: VPC Subnetwork Flow Logs & Private Google Access Disabled + CIDR Expanded
SLACK_BOT_TOKEN=xoxb-your-token \
SLACK_CHANNEL=C0123456789 \
python3 app/cai-asset-change-notifications/main.py tests/fixtures/vpc_subnetwork_flowlogs_disabled.json --send

# Demo 8: IAM User-Managed Service Account Key Created via gcloud CLI
SLACK_BOT_TOKEN=xoxb-your-token \
SLACK_CHANNEL=C0123456789 \
python3 app/cai-asset-change-notifications/main.py tests/fixtures/iam_service_account_key_created.json --send

# Demo 9: IAM Custom Role Permissions Expanded with High-Risk Privilege Escalation Permissions
SLACK_BOT_TOKEN=xoxb-your-token \
SLACK_CHANNEL=C0123456789 \
python3 app/cai-asset-change-notifications/main.py tests/fixtures/iam_custom_role_permissions_expanded.json --send

# Demo 10: Organization Policy Constraint Weakened (iam.disableServiceAccountKeyCreation disabled)
SLACK_BOT_TOKEN=xoxb-your-token \
SLACK_CHANNEL=C0123456789 \
python3 app/cai-asset-change-notifications/main.py tests/fixtures/org_policy_constraint_weakened.json --send

# Demo 11: GKE Cluster Security Posture, Confidential Nodes, KMS Encryption, & Networking Weakened
SLACK_BOT_TOKEN=xoxb-your-token \
SLACK_CHANNEL=C0123456789 \
python3 app/cai-asset-change-notifications/main.py tests/fixtures/gke_cluster_security_posture_weakened.json --send

# Demo 12: Cloud Run Unauthenticated Access, Public Ingress, CMEK Removal, Threat Detection & Binary Authorization Breakglass
SLACK_BOT_TOKEN=xoxb-your-token \
SLACK_CHANNEL=C0123456789 \
python3 app/cai-asset-change-notifications/main.py tests/fixtures/cloudrun_auth_ingress_and_binauthz_weakened.json --send
```
</details>

---

### Quick start

```bash
# 1. Stage 1: KMS key for encrypting the Slack bot token
cd infra/kms && cp terraform.tfvars.example terraform.tfvars   # edit project_id & members
terraform init && terraform apply

# 2. Encrypt the Slack bot token with Cloud KMS
read -rs SLACK_BOT_TOKEN && export SLACK_BOT_TOKEN
terraform output -raw encrypt_command | sh && unset SLACK_BOT_TOKEN

# 3. Stage 2: Deploy the CAI & SCC Crown Jewel notifier
cd .. && cp terraform.tfvars.example terraform.tfvars          # edit, paste the KMS ciphertext
terraform init && terraform apply
```

See [Deployment](#-deployment) for the full steps and required permissions.

## Contents

- [Features](#-features)
- [Use Cases](#-use-cases)
- [Crown Jewels Monitored by Default](#-crown-jewels-monitored-by-default)
- [What Every Slack Notification Includes](#-what-every-slack-notification-includes)
- [Architecture](#-architecture)
- [Repository Layout](#-repository-layout)
- [Prerequisites](#-prerequisites)
- [Deployment](#-deployment)
- [Configuration](#-configuration)
- [Error Handling and Monitoring](#-error-handling-and-monitoring)
- [Development & Testing](#-development--testing)
- [Security Considerations](#-security-considerations)
- [Troubleshooting](#-troubleshooting)

---

## ✨ Features

- **Real-time Crown Jewel monitoring (`RESOURCE` + `IAM_POLICY` + `ORG_POLICY`).** Configures organization-wide (and optional folder-scoped) Cloud Asset Inventory feeds for resource configuration changes, IAM policy changes, and Organization Policy constraint changes.
- **Native Security Command Center (SCC v2) compatibility.** Supports streaming SCC v2 findings (`google_scc_v2_organization_notification_config`) into the same Pub/Sub topic and Cloud Run function.
- **Before/After Cloud Asset Inventory Diff Engine.** Automatically computes a clean, human-readable diff between `priorAsset` and `asset` (filtering out volatile metadata like `etag` or `fingerprint` and redacting sensitive fields like `secretData`).
- **Cloud Audit Logs Attribution (`Who` & `How`).** Correlates asset changes with Google Cloud Audit Logs (`cloudaudit.googleapis.com/activity`) to identify:
  - **Who did the change:** Human User (`User Account`), `Service Account`, `Workload Identity`, or **Service Account Impersonation** (`User ➔ Service Account` delegation chain).
  - **How the change was executed:** **Terraform (IaC)**, **Google Cloud Console (Web UI / ClickOps)**, **`gcloud` CLI** (including the exact command), or **API / SDK**.
- **Automated Risk & Drift Detection.** Flags high-risk changes such as **ClickOps / manual changes outside Terraform**, **IAM privilege escalation** (users/SAs gaining additional roles or high-risk custom role permissions), **Organization Policy constraint weakening**, **GKE & Cloud Run security posture regressions** (Confidential Nodes, Cloud KMS CMEK vs. Google-managed keys, Binary Authorization, Threat Detection, Workload Identity, Private Cluster / Authorized Networks, unauthenticated Cloud Run access), **database configuration weakening** (Cloud SQL SSL enforcement disabled or `authorizedNetworks` IP ranges expanded), `0.0.0.0/0` public firewall ingress, and VPC peering / route changes.
- **Encrypted secret handling with Cloud KMS.** The Slack bot token is committed only as **Cloud KMS ciphertext** (`cryptoKeyEncrypter` / `cryptoKeyDecrypter`) and injected into the Cloud Run function via **Secret Manager**.
- **Least-privilege architecture.** Dedicated service accounts for build (`cainotifier-build`) and runtime (`cainotifier`), `ALLOW_INTERNAL_ONLY` ingress, and IAM scoped strictly to the KMS key, secret, and Cloud Run service.

---

## 🎯 Use Cases

Even in cloud environments that strictly enforce the **principle of least privilege**, a subset of engineers, break-glass responders, or CI/CD service accounts must retain permissions to manage critical production assets. This solution addresses **core security & operations use cases**:

### 1. IAM Privilege Escalation, Custom Roles, Workload Identity & Organization Policies
- **Why it matters:** Privilege escalation often happens incrementally—an existing `user:` or `serviceAccount:` with baseline permissions (e.g., `roles/logging.logWriter` or `roles/viewer`) is granted additional roles (`roles/iam.serviceAccountTokenCreator`, `roles/bigquery.admin`, `roles/secretmanager.secretAccessor`), brand-new roles are added to an Organization/Folder/Project/Resource IAM policy, a custom IAM role (`iam.googleapis.com/Role`) has its `includedPermissions` expanded with privilege-escalation permissions, or an Organization Policy constraint (`orgpolicy.googleapis.com/Policy`) is weakened.
- **What you get:** The notifier compares `priorAsset` and `asset` per role, per principal, and per constraint rule, explicitly alerting on:
  - **IAM Privilege Escalation:** When a user or service account gains more permissions than they previously held.
  - **Added IAM Roles & Bindings:** Every newly introduced role (`+ IAM Role Added`) and newly bound principal (`+ IAM Binding`).
  - **Custom Role Permission Expansion & SA Keys:** Added `includedPermissions` (highlighting high-risk permissions like `iam.serviceAccounts.actAs` or `getAccessToken`) on `iam.googleapis.com/Role`, creation of user-managed `iam.googleapis.com/ServiceAccountKey` credentials, and unrestricted `WorkloadIdentityPoolProvider` attribute conditions.
  - **Organization Policy Constraint Weakening:** Disabling boolean constraints (`enforce: true -> false`), setting list constraints to `allowAll`, or overriding parent policy inheritance.

### 2. Database & Data Source Security Configuration Monitoring (Cloud SQL & BigQuery)
- **Why it matters:** Production databases (`sqladmin.googleapis.com/Instance`) and analytics warehouses (`bigquery.googleapis.com/Dataset`, `bigquery.googleapis.com/Table`) hold your most sensitive business data. Subtle configuration changes—such as **disabling SSL enforcement** (`requireSsl: true -> false` or downgrading `sslMode` from `ENCRYPTED_ONLY` to `ALLOW_UNENCRYPTED_AND_ENCRYPTED`) or **expanding the network access IP range** (`settings.ipConfiguration.authorizedNetworks` adding a wider CIDR like `198.51.100.0/24` or `0.0.0.0/0`)—can expose databases to unencrypted traffic or external networks.
- **What you get:** Instant Slack alerts with the exact configuration diff and dedicated risk signals whenever:
  - **Database SSL Enforcement is Disabled** (`requireSsl: false` or `sslMode: ALLOW_UNENCRYPTED_AND_ENCRYPTED`).
  - **Database Network Access IP Range is Expanded** (new CIDR blocks added to Cloud SQL `authorizedNetworks` or `ipv4Enabled` turned on).
  - **BigQuery Dataset ACLs are Expanded** (new entries added to `resource.data.access` or public exposure via `allUsers` / `allAuthenticatedUsers`).

### 3. Kubernetes (GKE), Cloud Run & Binary Authorization Posture Monitoring
- **Why it matters:** Containerized platforms (`container.googleapis.com/Cluster`, `container.googleapis.com/NodePool`, `run.googleapis.com/Service`, `binaryauthorization.googleapis.com/Policy`) combine network exposure, identity, encryption, and runtime security controls in a single resource definition.
- **What you get:** Dedicated security posture rules for:
  - **GKE Clusters & Node Pools:** Confidential GKE Nodes (`confidentialNodes.enabled`), application-layer Secret encryption (`databaseEncryption` Cloud KMS CMEK vs. Google-managed key), boot disk encryption (`bootDiskKmsKey`), Security Posture (`securityPostureConfig.mode`, `vulnerabilityMode`), security bulletin notifications (`notificationConfig.pubsub.enabled`), Private Cluster & Control Plane Authorized Networks (`0.0.0.0/0`), Network Policy, Service Mesh certificates (`meshCertificates`, `gkehub.googleapis.com/*`), Node Service Account & `cloud-platform` access scopes, Binary Authorization, Client Certificates (`issueClientCertificate`), Google Groups for RBAC, Legacy ABAC, Secret Manager CSI add-on, Shielded GKE Nodes (Secure Boot & Integrity Monitoring), and Workload Identity.
  - **Cloud Run & Binary Authorization:** Unauthenticated access (`invokerIamDisabled` or `allUsers` on `roles/run.invoker`), public ingress (`INGRESS_TRAFFIC_ALL`) and VPC egress weakening, Cloud KMS CMEK removal, Threat Detection status (`threatDetectionEnabled`), runtime Service Account changes, Binary Authorization disablement or breakglass usage (`breakglassJustification`), and Binary Authorization policy weakens (`ALWAYS_ALLOW`, `DRYRUN_AUDIT_LOG_ONLY`).

### 4. Detecting "ClickOps" Drift, VPC / Hybrid Networking, Compute Exposure & Secret Vaults
- **Why it matters:** During an incident or debugging session, an authorized engineer might manually modify a production VPC firewall rule (`compute.googleapis.com/Firewall`), establish a new VPC peering (`compute.googleapis.com/Network`) or `0.0.0.0/0` default route (`compute.googleapis.com/Route`), disable subnet VPC Flow Logs (`compute.googleapis.com/Subnetwork`), attach an external IP (`ONE_TO_ONE_NAT`) to a Compute Engine VM (`compute.googleapis.com/Instance`), or modify a Secret Manager secret (`secretmanager.googleapis.com/Secret`) via the **Google Cloud Console** or **`gcloud` CLI**—bypassing Git review and Terraform pipelines.
- **What you get:** Every configuration attribute change is captured in the CAI diff and analyzed for risk, paired with a **⚠️ Manual Change Outside IaC (ClickOps / CLI)** warning whenever the change was not executed by Terraform.

---

## 👑 Crown Jewels Monitored by Default

Even with strict IAM and least privilege, authorized administrators or automation pipelines can modify critical infrastructure. By default, `var.monitored_asset_types` monitors the following **Crown Jewel** asset types across your organization:

| Category | CAI Asset Types (`monitored_asset_types`) | Why It Is a Crown Jewel |
|---|---|---|
| **Identity, Access (IAM) & Organization Policies** | `cloudresourcemanager.googleapis.com/Organization`<br/>`cloudresourcemanager.googleapis.com/Folder`<br/>`cloudresourcemanager.googleapis.com/Project`<br/>`iam.googleapis.com/ServiceAccount`<br/>`iam.googleapis.com/ServiceAccountKey`<br/>`iam.googleapis.com/Role`<br/>`iam.googleapis.com/WorkloadIdentityPool`<br/>`iam.googleapis.com/WorkloadIdentityPoolProvider`<br/>`orgpolicy.googleapis.com/Policy`<br/>`orgpolicy.googleapis.com/CustomConstraint` | Detects **privilege escalation**, **newly added IAM roles**, custom role `includedPermissions` expansion, service account key creation, Workload Identity Federation trust changes, and **Organization Policy constraint weakening**. |
| **Database & Data Sources (Cloud SQL, BigQuery, Storage)** | `sqladmin.googleapis.com/Instance`<br/>`bigquery.googleapis.com/Dataset`<br/>`bigquery.googleapis.com/Table`<br/>`storage.googleapis.com/Bucket` | Detects **disabling SSL enforcement** (`requireSsl: false` / `sslMode` downgrade), **expanding network access IP ranges** (`authorizedNetworks` CIDRs), enabling public IPv4 (`ipv4Enabled`), and expanding BigQuery dataset ACLs or Cloud Storage bucket access. |
| **Kubernetes (GKE), Cloud Run & Binary Authorization** | `container.googleapis.com/Cluster`<br/>`container.googleapis.com/NodePool`<br/>`gkehub.googleapis.com/Membership`<br/>`gkehub.googleapis.com/Feature`<br/>`run.googleapis.com/Service`<br/>`run.googleapis.com/Job`<br/>`run.googleapis.com/DomainMapping`<br/>`binaryauthorization.googleapis.com/Policy`<br/>`binaryauthorization.googleapis.com/Attestor` | Detects GKE Confidential Nodes, Cloud KMS vs. Google-managed encryption, Security Posture & vulnerability scanning, Private Cluster & Authorized Networks, Service Mesh, Shielded Nodes, Workload Identity, Legacy ABAC/Client Certs, Cloud Run authentication/ingress/CMEK/Threat Detection/SA changes, and Binary Authorization policies & breakglass events. |
| **Compute Resources** | `compute.googleapis.com/Instance`<br/>`compute.googleapis.com/InstanceTemplate` | Detects public `ONE_TO_ONE_NAT` IP attachments, machine series drift, or disabled Shielded VM / Confidential Compute. |
| **VPC, Hybrid Networking & Firewall Rules** | `compute.googleapis.com/Firewall`<br/>`compute.googleapis.com/FirewallPolicy`<br/>`compute.googleapis.com/Network`<br/>`compute.googleapis.com/Subnetwork`<br/>`compute.googleapis.com/Route`<br/>`compute.googleapis.com/Router`<br/>`compute.googleapis.com/VpnTunnel`<br/>`compute.googleapis.com/HaVpnGateway`<br/>`compute.googleapis.com/InterconnectAttachment`<br/>`networksecurity.googleapis.com/AuthorizationPolicy`<br/>`networksecurity.googleapis.com/ServerTlsPolicy` | Monitors **every firewall, VPC & hybrid network change**: source & destination IP ranges (`sourceRanges`, `destinationRanges`, `0.0.0.0/0`), port ranges & protocols, **firewall rule logging**, VPC peerings & custom route export, dynamic routing mode, default internet routes, Cloud NAT, VPN tunnels, Interconnects, Private Google Access, and VPC Flow Logs. |
| **Secrets & Encryption Keys** | `secretmanager.googleapis.com/Secret`<br/>`secretmanager.googleapis.com/SecretVersion`<br/>`cloudkms.googleapis.com/CryptoKey`<br/>`cloudkms.googleapis.com/KeyRing` | Detects secret creation/deletion, secret version changes, KMS rotation changes, or unauthorized `secretAccessor` / `cryptoKeyDecrypter` IAM bindings. |

---

## 📋 What Every Slack Notification Includes

| Field | Description |
|---|---|
| **Resource Name & Link** | Short name of the asset + a **View in Cloud Console** button deep-linking directly to the resource in GCP Console. |
| **Resource Type** | Full Cloud Asset Inventory type (e.g., `compute.googleapis.com/Firewall`, `secretmanager.googleapis.com/Secret`). |
| **Project & Location** | Project ID, region/zone (`global`, `europe-west1-b`, etc.), and action state (`CREATED`, `MODIFIED`, `DELETED`). |
| **Change Diff (CAI)** | Side-by-side / unified diff of `priorAsset` vs. `asset` covering both `resource.data` attributes and `iamPolicy.bindings`. |
| **Who Did the Change?** | Principal email from Cloud Audit Logs (`User Account`, `Service Account`, or `User impersonating Service Account`). |
| **How Was It Executed?** | Execution tool classified from `callerSuppliedUserAgent`: **Terraform (IaC)**, **Google Cloud Console (Web UI / ClickOps)**, **`gcloud` CLI**, or **API / SDK**. |
| **Additional Security Context** | **API Method Name** (e.g., `v1.compute.firewalls.patch`), **Caller IP Address**, **1-click Cloud Logging Audit Trail link**, **Risk & Drift Signals**, and **Remediation Recommendations**. |

---

## 🏗️ Architecture

```mermaid
flowchart LR
    CAI["Cloud Asset Inventory
    (Resource & IAM Feeds)"] -->|TemporalAsset| PS["Pub/Sub topic"]
    SCC["Security Command Center
    (Optional SCC v2 Config)"] -.->|Finding| PS
    PS --> EA["Eventarc trigger"]
    EA --> CF["Cloud Run function (2nd gen)
    Python 3.13"]
    CAL["Cloud Audit Logs
    (Cloud Logging API)"] -.->|"Who & How (Console / Terraform / CLI)"| CF
    SM["Secret Manager
    (Slack bot token)"] -.->|env var| CF
    KMS["Cloud KMS"] -.->|decrypts at deploy time| SM
    CF -->|chat.postMessage| SL["Slack channel"]
```

Deployment happens in two Terraform stages:

1. **Stage 1** in [`infra/kms/`](file:///Users/jorgecalo/Documents/GitHub/google-cloud-cai-asset-change-notifications/infra/kms) creates the Cloud KMS key ring and crypto key that encrypts the Slack bot token.
2. **Stage 2** in [`infra/`](file:///Users/jorgecalo/Documents/GitHub/google-cloud-cai-asset-change-notifications/infra) creates the Pub/Sub topic, CAI organization/folder feeds, optional SCC v2 notification config, Secret Manager secret, least-privilege service accounts, and 2nd gen Cloud Run function.

---

## 📁 Repository Layout

| Path | Purpose |
|---|---|
| [`infra/kms/`](file:///Users/jorgecalo/Documents/GitHub/google-cloud-cai-asset-change-notifications/infra/kms) | Stage 1 Terraform: Cloud KMS key ring and symmetric crypto key for secret encryption. |
| [`infra/`](file:///Users/jorgecalo/Documents/GitHub/google-cloud-cai-asset-change-notifications/infra) | Stage 2 Terraform: CAI feeds, optional SCC v2 notification config, Secret Manager, IAM, and Cloud Run function. |
| [`app/cai-asset-change-notifications/`](file:///Users/jorgecalo/Documents/GitHub/google-cloud-cai-asset-change-notifications/app/cai-asset-change-notifications) | Primary Slack Block Kit notifier with CAI diff engine, Cloud Audit Log attribution (`Who` & `How`), and SCC v2 support. |
| [`app/monitor-cpu-machine-type/`](file:///Users/jorgecalo/Documents/GitHub/google-cloud-cai-asset-change-notifications/app/monitor-cpu-machine-type) | Specialized monitor alerting when running Compute Engine VMs deviate from approved machine series (e.g., `n2d-`). |
| [`app/monitor-principals/`](file:///Users/jorgecalo/Documents/GitHub/google-cloud-cai-asset-change-notifications/app/monitor-principals) | Specialized monitor for project/organization IAM policy role and principal changes. |
| [`app/sa-iam-monitor/`](file:///Users/jorgecalo/Documents/GitHub/google-cloud-cai-asset-change-notifications/app/sa-iam-monitor) | Specialized monitor for Service Account IAM policy changes. |
| [`tests/`](file:///Users/jorgecalo/Documents/GitHub/google-cloud-cai-asset-change-notifications/tests) | Unit test suite and realistic Crown Jewel CAI/Audit Log sample fixtures. |

---

## ✅ Prerequisites

- Terraform `>= 1.9` and the `gcloud` CLI.
- Cloud Asset Inventory (and optionally Security Command Center) activated in your Google Cloud organization.
- A Google Cloud project to host the notifier (a dedicated security project is recommended).
- A Slack workspace where you can install apps.

The identity that runs Terraform needs:

| Role | Scope | Why |
|---|---|---|
| `roles/cloudasset.owner` | Organization | Create the organization-level Cloud Asset Inventory feeds. |
| `roles/resourcemanager.organizationAdmin` | Organization | Grant `roles/logging.viewer` at org level when `enable_audit_log_lookup = true`. |
| `roles/securitycenter.notificationConfigEditor` | Organization | Optional: only required if `enable_scc_notification = true`. |
| `roles/owner` (or equivalent project admin roles) | Project | Enable APIs and manage Pub/Sub, IAM, service accounts, Cloud Run functions, Secret Manager, and Storage buckets. |
| `roles/cloudkms.cryptoKeyDecrypter` | KMS key | Decrypt the Slack bot token during Stage 2 `terraform apply` (granted via `decrypter_members` in Stage 1). |

---

## 🚀 Deployment

### 1. Create the Slack app

1. Create a Slack app at [api.slack.com/apps](https://api.slack.com/apps) and add the `chat:write` bot token scope.
2. Install it into your workspace and copy the **Bot User OAuth Token** (`xoxb-...`).
3. Invite the bot to your target channel with `/invite @your-app`.
4. Copy the channel ID from the channel details (using a channel ID like `C0123456789` is resilient to channel renames).

### 2. Stage 1: Create the Cloud KMS key

```bash
cd infra/kms
cp terraform.tfvars.example terraform.tfvars   # fill in project_id and encrypter/decrypter members
terraform init
terraform apply
```

The crypto key has `prevent_destroy = true` set so stored ciphertext cannot be accidentally rendered unrecoverable.

### 3. Encrypt the Slack bot token

Still inside `infra/kms`, run the generated `encrypt_command` output. This reads the token from stdin without echoing it or saving it in shell history:

```bash
read -rs SLACK_BOT_TOKEN && export SLACK_BOT_TOKEN
terraform output -raw encrypt_command | sh
unset SLACK_BOT_TOKEN
```

The output is a single line of base64 KMS ciphertext.

### 4. Stage 2: Deploy the notifier

```bash
cd ../   # infra/
cp terraform.tfvars.example terraform.tfvars
```

Fill in `infra/terraform.tfvars`:

- `org_id` and `project_id`.
- `kms_crypto_key_id` from Stage 1 output `crypto_key_id`.
- `slack_bot_token_ciphertext`: replace `REPLACE-WITH-KMS-CIPHERTEXT-OF-SLACK-BOT-TOKEN` with the base64 ciphertext from Step 3.
- `slack_channel`: your Slack channel ID or name.

> [!IMPORTANT]
> The Slack token is encrypted in your repository and `terraform.tfvars`, but Terraform stores the decrypted value in state when provisioning the Secret Manager version. Configure a remote `gcs` backend in [`infra/versions.tf`](file:///Users/jorgecalo/Documents/GitHub/google-cloud-cai-asset-change-notifications/infra/versions.tf) on a bucket with restricted access before running `terraform apply`.

Deploy Stage 2:

```bash
terraform init
terraform plan
terraform apply
```

### 5. Test end-to-end

Publish one of the sample Crown Jewel notifications to the Pub/Sub topic and verify it appears in Slack:

```bash
gcloud pubsub topics publish cai-asset-changes-topic \
  --project=PROJECT_ID \
  --message="$(cat tests/fixtures/firewall_open_ssh_console.json)"
```

---

## ⚙️ Configuration

Stage 2 variables are configured in `infra/terraform.tfvars` (defined in [`infra/variables.tf`](file:///Users/jorgecalo/Documents/GitHub/google-cloud-cai-asset-change-notifications/infra/variables.tf)):

<details>
<summary><b>All Stage 2 Terraform variables</b></summary>

| Variable | Default | Description |
|---|---|---|
| `org_id` | required | Numeric Google Cloud organization ID. |
| `project_id` | required | Project hosting the Pub/Sub topic, Cloud Run function, secret, and bucket. |
| `kms_crypto_key_id` | required | Output `crypto_key_id` from Stage 1 (`infra/kms`). |
| `slack_bot_token_ciphertext` | required | Base64 KMS ciphertext of the Slack bot token. |
| `region` | `europe-west1` | Region for the Cloud Run function, Eventarc trigger, and source bucket. |
| `slack_channel` | `security-gcp-alerts` | Slack channel ID (recommended) or channel name. |
| `monitored_asset_types` | Crown Jewels list | List of CAI asset types monitored for `RESOURCE` and `IAM_POLICY` changes. |
| `enable_iam_feed` | `true` | Create an organization-level CAI feed for `IAM_POLICY` changes on Crown Jewel assets. |
| `folder_id` | `""` | Optional numeric folder ID to also create a folder-scoped CAI feed. |
| `feed_condition_expression` | `""` | Optional CEL expression to filter the CAI resource feed. |
| `allowed_projects` | `[]` | Optional list of project IDs/names to notify on (empty = all projects in org). |
| `enable_audit_log_lookup` | `true` | Query Cloud Audit Logs (`entries:list`) to enrich `Who` and `How` (`Console`, `Terraform`, `gcloud CLI`). |
| `enable_scc_notification` | `false` | Also create an SCC v2 organization notification config streaming HIGH/CRITICAL findings to the topic. |
| `dedup_window_seconds` | `60` | Cooldown window in seconds to suppress duplicate notifications for identical diffs. |
| `topic_name` | `cai-asset-changes-topic` | Pub/Sub topic name. |
| `function_name` | `cai-slack-notifier` | Cloud Run function (2nd gen) name. |
| `function_runtime` | `python313` | Python runtime version. |
| `max_instance_count` | `3` | Maximum Cloud Run function instances. |
| `max_event_age_seconds` | `3600` | Drop events older than this threshold instead of retrying indefinitely. |

</details>

---

## 📈 Error Handling and Monitoring

| Error Type | Examples | Behavior |
|---|---|---|
| **Transient** | Network timeout, HTTP `429` or `5xx`, Slack `ratelimited` or `internal_error` | Logged as `WARNING` and raised so Eventarc retries delivery. |
| **Permanent** | `invalid_auth`, `channel_not_found`, `not_in_channel`, `invalid_blocks`, malformed JSON | Logged as `ERROR` and acknowledged so broken events do not loop forever. |
| **Stale Event** | Event older than `max_event_age_seconds` | Logged as `ERROR` and dropped. |

---

## 🧪 Development & Testing

Run the unit test suite from the repository root:

```bash
python3 -m unittest discover -s tests -v
```

Preview the generated Slack Block Kit JSON for any sample fixture without sending network requests:

```bash
python3 app/cai-asset-change-notifications/main.py tests/fixtures/firewall_open_ssh_console.json
python3 app/cai-asset-change-notifications/main.py tests/fixtures/compute_vm_external_ip_gcloud.json
python3 app/cai-asset-change-notifications/main.py tests/fixtures/secret_manager_iam_terraform.json
```

Validate Terraform formatting across both modules:

```bash
terraform -chdir=infra fmt -check -recursive
```

---

## 🔒 Security Considerations

- **No plaintext secrets in Git.** The Slack bot token is encrypted with Cloud KMS (`infra/kms`) and committed only as base64 ciphertext.
- **Protect Terraform state.** Terraform decrypts the KMS ciphertext during `apply` to populate `google_secret_manager_secret_version`. Always store state in a remote GCS backend with strict IAM access controls and encryption.
- **Internal-only function ingress.** The Cloud Run function is deployed with `ALLOW_INTERNAL_ONLY` ingress, and `roles/run.invoker` is granted exclusively to the dedicated `cainotifier` trigger service account (never `allUsers`).
- **Sensitive diff redaction.** Secret payload fields (`secretData`, `privateKeyData`, `payload`, `password`, `token`) are automatically redacted before constructing Slack messages, and all untrusted strings are escaped against Slack mrkdwn / HTML injection.

---

## 🩺 Troubleshooting

<details>
<summary><b>Common problems and fixes</b></summary>

| Symptom | Likely Cause | Fix |
|---|---|---|
| `Invalid value for variable` on `terraform plan` | `slack_bot_token_ciphertext` still contains the `REPLACE-...` placeholder. | Encrypt your token using Stage 1 `encrypt_command` and paste the base64 output. |
| `PERMISSION_DENIED` on `google_kms_secret` | The identity running Terraform is not allowed to decrypt with the KMS key. | Add your user/service account to `decrypter_members` in `infra/kms` and apply Stage 1. |
| CAI feed created, but no messages arrive in Pub/Sub | Cloud Asset Service Agent lacks publish rights on the topic. | Managed automatically by `google_pubsub_topic_iam_member.cai_publisher` in `infra/main.tf`. |
| Attribution shows `Unknown (Audit log not attached)` | Cloud Audit Log entry was not yet indexed or `cainotifier` lacks `roles/logging.viewer`. | Ensure `enable_audit_log_lookup = true` and `roles/logging.viewer` is granted on the project/organization. |
| Log shows `not_in_channel` | The Slack bot has not been invited to the destination channel. | Run `/invite @your-app` in the Slack channel. |

</details>
