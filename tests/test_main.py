"""Unit tests for the Google Cloud CAI & SCC Asset Change Notification functions.

Run from the repository root:
    python3 -m unittest discover -s tests
    # or with pytest:
    pytest
"""

import base64
import copy
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cai_main = _load_module(
    "cai_main", ROOT / "app" / "cai-asset-change-notifications" / "main.py"
)
cpu_main = _load_module(
    "cpu_main", ROOT / "app" / "monitor-cpu-machine-type" / "main.py"
)
principals_main = _load_module(
    "principals_main", ROOT / "app" / "monitor-principals" / "main.py"
)
sa_iam_main = _load_module(
    "sa_iam_main", ROOT / "app" / "sa-iam-monitor" / "main.py"
)


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def block_texts(blocks):
    return [b["text"]["text"] for b in blocks if "text" in b]


def all_text(blocks):
    return "\n".join(block_texts(blocks))


class TestCaiSlackNotifications(unittest.TestCase):
    def setUp(self):
        cai_main._recent_alerts_cache.clear()
        os.environ.pop("ALLOWED_PROJECTS", None)
        os.environ.pop("MONITORED_ASSET_TYPES", None)
        os.environ["ENABLE_AUDIT_LOG_LOOKUP"] = "false"

    def test_firewall_console_clickops_renders_all_required_fields(self):
        payload = load_fixture("firewall_open_ssh_console.json")
        blocks = cai_main.build_blocks(payload)
        text = all_text(blocks)

        # 1. Resource Name
        self.assertIn("`allow-prod-ssh-ingress`", text)
        # 2. Resource Type
        self.assertIn("`compute.googleapis.com/Firewall`", text)
        # 3. Project
        self.assertIn("`prod-networking-01`", text)
        # 4. Change (Diff of Cloud Asset Inventory)
        self.assertIn("sourceRanges", text)
        self.assertIn("0.0.0.0/0", text)
        self.assertIn("3389", text)
        # 5. Who did the change? User or service account?
        self.assertIn("`j.doe@example.com` *(User Account)*", text)
        # 6. How was the change executed? Console, Terraform or CLI?
        self.assertIn("Google Cloud Console (Web UI / ClickOps)", text)
        # Security highlights
        self.assertIn("Public Internet Ingress (`0.0.0.0/0`)", text)
        self.assertIn("Firewall Source IP Ranges Modified", text)
        self.assertIn("Firewall Allowed Port Ranges / Protocols Changed", text)
        self.assertIn("Manual Change Outside IaC", text)
        self.assertEqual(blocks[-1], {"type": "divider"})

    def test_firewall_destination_ips_port_ranges_and_logging_disabled(self):
        payload = load_fixture("firewall_open_ssh_console.json")
        payload["priorAsset"]["resource"]["data"]["destinationRanges"] = ["10.10.0.0/16"]
        payload["asset"]["resource"]["data"]["destinationRanges"] = ["10.10.0.0/16", "172.16.0.0/12"]
        payload["priorAsset"]["resource"]["data"]["logConfig"] = {"enable": True, "metadata": "INCLUDE_ALL_METADATA"}
        payload["asset"]["resource"]["data"]["logConfig"] = {"enable": False}

        blocks = cai_main.build_blocks(payload)
        text = all_text(blocks)

        self.assertIn("Firewall Destination IP Ranges Modified", text)
        self.assertIn("172.16.0.0/12", text)
        self.assertIn("Firewall Allowed Port Ranges / Protocols Changed", text)
        self.assertIn("`tcp:22` -> `tcp:22,3389`", text)
        self.assertIn("Firewall Rule Logging Disabled", text)
        self.assertIn("logConfig.enable", text)

    def test_compute_vm_gcloud_cli_and_impersonation(self):
        payload = load_fixture("compute_vm_external_ip_gcloud.json")
        blocks = cai_main.build_blocks(payload)
        text = all_text(blocks)

        self.assertIn("`prod-payments-db-01`", text)
        self.assertIn("`compute.googleapis.com/Instance`", text)
        self.assertIn("`prod-payments-01`", text)
        # Impersonated service account detection
        self.assertIn(
            "`sre-oncall@example.com` *(User impersonating Service Account `prod-compute-admin@prod-payments-01.iam.gserviceaccount.com`)*",
            text,
        )
        # gcloud CLI execution method detection
        self.assertIn("gcloud CLI (`gcloud compute instances add-access-config`)", text)
        # External IP and Machine Type change highlights
        self.assertIn("External Public IP Attached", text)
        self.assertIn("34.77.102.19", text)
        self.assertIn("`n2d-standard-4` -> `e2-standard-8`", text)

    def test_secret_manager_iam_terraform_execution(self):
        payload = load_fixture("secret_manager_iam_terraform.json")
        blocks = cai_main.build_blocks(payload)
        text = all_text(blocks)

        self.assertIn("stripe-live-api-key", text)
        self.assertIn("`secretmanager.googleapis.com/Secret`", text)
        self.assertIn("`prod-secrets-vault-01`", text)
        # Service account actor
        self.assertIn(
            "`terraform-ci@prod-automation.iam.gserviceaccount.com` *(Service Account)*",
            text,
        )
        # Terraform execution method
        self.assertIn("Terraform (Terraform/1.9.8)", text)
        # IAM Policy diff
        self.assertIn("roles/secretmanager.secretAccessor", text)
        self.assertIn("user:external-contractor@example.com", text)

    def test_iam_privilege_escalation_and_added_roles(self):
        payload = load_fixture("iam_privilege_escalation.json")
        blocks = cai_main.build_blocks(payload)
        text = all_text(blocks)

        self.assertIn("`prod-core-01`", text)
        self.assertIn("`cloudresourcemanager.googleapis.com/Project`", text)
        # Added roles detection
        self.assertIn("Added IAM Role(s)", text)
        self.assertIn("roles/bigquery.admin", text)
        self.assertIn("roles/iam.serviceAccountTokenCreator", text)
        # Per-principal privilege escalation detection (existing SA gained additional role)
        self.assertIn("IAM Privilege Escalation", text)
        self.assertIn("serviceAccount:app-worker@prod-core-01.iam.gserviceaccount.com", text)
        self.assertIn("roles/logging.logWriter", text)

    def test_database_ssl_disabled_and_network_ip_range_expanded(self):
        payload = load_fixture("cloudsql_ssl_and_network_expanded.json")
        blocks = cai_main.build_blocks(payload)
        text = all_text(blocks)

        self.assertIn("`prod-customer-orders-sql`", text)
        self.assertIn("`sqladmin.googleapis.com/Instance`", text)
        # SSL enforcement disabled
        self.assertIn("Database SSL Enforcement Disabled", text)
        self.assertIn("ALLOW_UNENCRYPTED_AND_ENCRYPTED", text)
        # Expanded network access IP range
        self.assertIn("Database Network Access IP Range Expanded", text)
        self.assertIn("198.51.100.0/24 (external-vendor-subnet)", text)

    def test_vpc_network_peering_and_routing_mode_change(self):
        payload = load_fixture("vpc_network_peering_and_routing.json")
        blocks = cai_main.build_blocks(payload)
        text = all_text(blocks)

        self.assertIn("`prod-vpc`", text)
        self.assertIn("`compute.googleapis.com/Network`", text)
        self.assertIn("`prod-networking-01`", text)
        self.assertIn("VPC Network Peering Added", text)
        self.assertIn("peer-external-partner-vpc", text)
        self.assertIn("projects/ext-partner-net/global/networks/partner-vpc", text)
        self.assertIn("exportCustomRoutes=True", text)
        self.assertIn("VPC Dynamic Routing Mode Changed", text)
        self.assertIn("`REGIONAL` -> `GLOBAL`", text)

    def test_vpc_subnetwork_flowlogs_private_access_and_cidr_modified(self):
        payload = load_fixture("vpc_subnetwork_flowlogs_disabled.json")
        blocks = cai_main.build_blocks(payload)
        text = all_text(blocks)

        self.assertIn("`prod-eu-west1-subnet`", text)
        self.assertIn("`compute.googleapis.com/Subnetwork`", text)
        self.assertIn("Private Google Access Disabled", text)
        self.assertIn("VPC Flow Logs Disabled", text)
        self.assertIn("Subnetwork IP CIDR Range Modified", text)
        self.assertIn("`10.10.0.0/24` -> `10.10.0.0/16`", text)

    def test_vpc_default_route_router_nat_and_vpn_tunnel_posture(self):
        route_payload = {
            "priorAssetState": "DOES_NOT_EXIST",
            "asset": {
                "name": "//compute.googleapis.com/projects/prod-networking-01/global/routes/default-internet-egress",
                "assetType": "compute.googleapis.com/Route",
                "resource": {
                    "data": {
                        "name": "default-internet-egress",
                        "destRange": "0.0.0.0/0",
                        "nextHopGateway": "projects/prod-networking-01/global/gateways/default-internet-gateway",
                    }
                },
            },
        }
        route_text = all_text(cai_main.build_blocks(route_payload))
        self.assertIn("Default Internet / Catch-All Route (`0.0.0.0/0`) Configured", route_text)
        self.assertIn("default-internet-gateway", route_text)

        vpn_payload = {
            "priorAssetState": "DOES_NOT_EXIST",
            "asset": {
                "name": "//compute.googleapis.com/projects/prod-networking-01/regions/europe-west1/vpnTunnels/partner-vpn-01",
                "assetType": "compute.googleapis.com/VpnTunnel",
                "resource": {
                    "data": {
                        "name": "partner-vpn-01",
                        "peerIp": "203.0.113.250",
                    }
                },
            },
        }
        vpn_text = all_text(cai_main.build_blocks(vpn_payload))
        self.assertIn("Hybrid Network Connectivity Created", vpn_text)
        self.assertIn("peerIp=203.0.113.250", vpn_text)

    def test_iam_service_account_key_created(self):
        payload = load_fixture("iam_service_account_key_created.json")
        blocks = cai_main.build_blocks(payload)
        text = all_text(blocks)

        self.assertIn("`iam.googleapis.com/ServiceAccountKey`", text)
        self.assertIn("`prod-payments-01`", text)
        self.assertIn("CREATED", text)
        self.assertIn("User-Managed Service Account Key Created", text)
        self.assertIn("prod-payments-sa@prod-payments-01.iam.gserviceaccount.com", text)
        self.assertIn("gcloud CLI (`gcloud iam service-accounts keys create`)", text)

    def test_iam_custom_role_permissions_expanded(self):
        payload = load_fixture("iam_custom_role_permissions_expanded.json")
        blocks = cai_main.build_blocks(payload)
        text = all_text(blocks)

        self.assertIn("`iam.googleapis.com/Role`", text)
        self.assertIn("customSupportRole", text)
        self.assertIn("IAM Custom Role Permissions Expanded", text)
        self.assertIn("High-Risk Privilege Escalation Permission(s) Added", text)
        self.assertIn("iam.serviceAccounts.actAs", text)
        self.assertIn("iam.serviceAccounts.getAccessToken", text)
        self.assertIn("secretmanager.versions.access", text)

    def test_iam_workload_identity_pool_provider_unrestricted(self):
        wif_payload = {
            "priorAssetState": "PRESENT",
            "asset": {
                "name": "//iam.googleapis.com/projects/112233445566/locations/global/workloadIdentityPools/github-pool/providers/github-oidc",
                "assetType": "iam.googleapis.com/WorkloadIdentityPoolProvider",
                "resource": {
                    "data": {
                        "name": "github-oidc",
                        "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
                        "attributeCondition": "",
                    }
                },
            },
            "priorAsset": {
                "name": "//iam.googleapis.com/projects/112233445566/locations/global/workloadIdentityPools/github-pool/providers/github-oidc",
                "assetType": "iam.googleapis.com/WorkloadIdentityPoolProvider",
                "resource": {
                    "data": {
                        "name": "github-oidc",
                        "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
                        "attributeCondition": "assertion.repository_owner == 'my-org'",
                    }
                },
            },
        }
        wif_text = all_text(cai_main.build_blocks(wif_payload))
        self.assertIn("Workload Identity Federation Trust Modified", wif_text)
        self.assertIn("Workload Identity Provider Attribute Condition Modified or Missing", wif_text)
        self.assertIn("NONE (unrestricted)", wif_text)

    def test_org_policy_constraint_weakened_and_v1_org_policy(self):
        payload = load_fixture("org_policy_constraint_weakened.json")
        blocks = cai_main.build_blocks(payload)
        text = all_text(blocks)

        self.assertIn("`orgpolicy.googleapis.com/Policy`", text)
        self.assertIn("iam.disableServiceAccountKeyCreation", text)
        self.assertIn("Organization Policy Constraint Enforcement Disabled", text)
        self.assertIn("enforce: true -> false", text)
        self.assertIn("Organization Policy Parent Inheritance Overridden", text)

        # Also test v1 CAI ORG_POLICY feed structure (asset.orgPolicy list)
        v1_org_policy_payload = {
            "priorAssetState": "PRESENT",
            "asset": {
                "name": "//cloudresourcemanager.googleapis.com/organizations/123456789012",
                "assetType": "cloudresourcemanager.googleapis.com/Organization",
                "orgPolicy": [
                    {
                        "constraint": "constraints/iam.allowedPolicyMemberDomains",
                        "listPolicy": {
                            "allValues": "ALLOW",
                        },
                    }
                ],
            },
            "priorAsset": {
                "name": "//cloudresourcemanager.googleapis.com/organizations/123456789012",
                "assetType": "cloudresourcemanager.googleapis.com/Organization",
                "orgPolicy": [
                    {
                        "constraint": "constraints/iam.allowedPolicyMemberDomains",
                        "listPolicy": {
                            "allowedValues": ["C0123abc"],
                        },
                    }
                ],
            },
        }
        v1_text = all_text(cai_main.build_blocks(v1_org_policy_payload))
        self.assertIn("Organization Policy Constraint Set to Allow All", v1_text)
        self.assertIn("iam.allowedPolicyMemberDomains", v1_text)
        self.assertIn("organizations/123456789012", v1_text)

    def test_gke_cluster_security_posture_weakened(self):
        payload = load_fixture("gke_cluster_security_posture_weakened.json")
        blocks = cai_main.build_blocks(payload)
        text = all_text(blocks)

        self.assertIn("`prod-payments-gke`", text)
        self.assertIn("`container.googleapis.com/Cluster`", text)
        self.assertIn("Confidential GKE Nodes Disabled", text)
        self.assertIn("GKE Boot Disk Cloud KMS Key Removed", text)
        self.assertIn("GKE Default Compute Service Account Used", text)
        self.assertIn("Broad GKE Node Access Scope", text)
        self.assertIn("GKE Node Secure Boot Disabled", text)
        self.assertIn("GKE Node Integrity Monitoring Disabled", text)
        self.assertIn("GKE Application-Layer Secret Encryption Disabled", text)
        self.assertIn("GKE Security Posture Disabled", text)
        self.assertIn("GKE Workload Vulnerability Scanning Disabled", text)
        self.assertIn("GKE Security Bulletin Notifications Disabled", text)
        self.assertIn("GKE Private Nodes Disabled", text)
        self.assertIn("GKE Public Control Plane Endpoint Enabled", text)
        self.assertIn("GKE Control Plane Open to the Internet", text)
        self.assertIn("GKE Network Policy Disabled", text)
        self.assertIn("GKE Service Mesh Certificates Disabled", text)
        self.assertIn("GKE Binary Authorization Disabled", text)
        self.assertIn("GKE Legacy Client Certificate Issued", text)
        self.assertIn("GKE Google Groups for RBAC Disabled", text)
        self.assertIn("GKE Legacy ABAC Authorization Enabled", text)
        self.assertIn("GKE Secret Manager Add-on Disabled", text)
        self.assertIn("GKE Shielded Nodes Disabled", text)
        self.assertIn("GKE Workload Identity Disabled", text)

    def test_cloudrun_auth_ingress_and_binauthz_weakened(self):
        payload = load_fixture("cloudrun_auth_ingress_and_binauthz_weakened.json")
        blocks = cai_main.build_blocks(payload)
        text = all_text(blocks)

        self.assertIn("`checkout-api`", text)
        self.assertIn("`run.googleapis.com/Service`", text)
        self.assertIn("Cloud Run Unauthenticated Access Enabled", text)
        self.assertIn("Cloud Run Ingress Exposed to Public Internet", text)
        self.assertIn("Cloud Run VPC Egress Weakened", text)
        self.assertIn("Cloud Run Cloud KMS Key (CMEK) Removed", text)
        self.assertIn("Cloud Run Threat Detection Disabled", text)
        self.assertIn("Cloud Run Service Account Changed", text)
        self.assertIn("Cloud Run Using Default Compute Service Account", text)
        self.assertIn("Cloud Run Binary Authorization Disabled", text)
        self.assertIn("Cloud Run Binary Authorization Breakglass Used", text)
        self.assertIn("hotfix-emergency-deploy-2026", text)
        self.assertIn("Public IAM Access Granted", text)

        # Also test standalone Binary Authorization Policy change
        binauth_policy_payload = {
            "priorAssetState": "PRESENT",
            "asset": {
                "name": "//binaryauthorization.googleapis.com/projects/my-crown-jewel-prod/policy",
                "assetType": "binaryauthorization.googleapis.com/Policy",
                "resource": {
                    "data": {
                        "globalPolicyEvaluationMode": "DISABLE",
                        "defaultAdmissionRule": {
                            "evaluationMode": "ALWAYS_ALLOW",
                            "enforcementMode": "DRYRUN_AUDIT_LOG_ONLY",
                        },
                    }
                },
            },
            "priorAsset": {
                "name": "//binaryauthorization.googleapis.com/projects/my-crown-jewel-prod/policy",
                "assetType": "binaryauthorization.googleapis.com/Policy",
                "resource": {
                    "data": {
                        "globalPolicyEvaluationMode": "ENABLE",
                        "defaultAdmissionRule": {
                            "evaluationMode": "REQUIRE_ATTESTATION",
                            "enforcementMode": "ENFORCED_BLOCK_AND_AUDIT_LOG",
                        },
                    }
                },
            },
        }
        ba_text = all_text(cai_main.build_blocks(binauth_policy_payload))
        self.assertIn("Binary Authorization Policy Set to ALWAYS_ALLOW", ba_text)
        self.assertIn("Binary Authorization Policy Weakened to Dry-Run", ba_text)
        self.assertIn("Binary Authorization Global Policy Disabled", ba_text)

    def test_no_placeholders_left_in_any_fixture(self):
        for fname in (
            "firewall_open_ssh_console.json",
            "compute_vm_external_ip_gcloud.json",
            "secret_manager_iam_terraform.json",
            "iam_privilege_escalation.json",
            "cloudsql_ssl_and_network_expanded.json",
            "vpc_network_peering_and_routing.json",
            "vpc_subnetwork_flowlogs_disabled.json",
            "iam_service_account_key_created.json",
            "iam_custom_role_permissions_expanded.json",
            "org_policy_constraint_weakened.json",
            "gke_cluster_security_posture_weakened.json",
            "cloudrun_auth_ingress_and_binauthz_weakened.json",
        ):
            payload = load_fixture(fname)
            dumped = json.dumps(cai_main.build_blocks(payload))
            for key in cai_main.PLACEHOLDER_KEYS:
                self.assertNotIn(f"<{key}>", dumped)

    def test_scc_v2_finding_payload_compatibility(self):
        scc_payload = {
            "notificationConfigName": "organizations/123456789012/locations/global/notificationConfigs/cai-scc",
            "finding": {
                "name": "organizations/123456789012/sources/999/locations/global/findings/abc123",
                "state": "ACTIVE",
                "severity": "CRITICAL",
                "category": "OPEN_FIREWALL",
                "eventTime": "2026-09-27T02:00:00Z",
                "description": "Firewall rule allows public SSH access from 0.0.0.0/0.",
                "nextSteps": "Restrict sourceRanges to internal corporate ranges.",
            },
            "resource": {
                "name": "//compute.googleapis.com/projects/prod-networking-01/global/firewalls/allow-ssh",
                "displayName": "allow-ssh",
                "type": "compute.googleapis.com/Firewall",
                "projectDisplayName": "prod-networking-01",
                "location": "global",
            },
        }
        blocks = cai_main.build_blocks(scc_payload)
        text = all_text(blocks)
        self.assertIn("OPEN_FIREWALL", text)
        self.assertIn("`allow-ssh`", text)
        self.assertIn("`prod-networking-01`", text)
        self.assertIn("Restrict sourceRanges", text)

    def test_sensitive_secret_data_is_redacted_in_diff(self):
        old_data = {"name": "my-secret", "secretData": "old-super-secret-value"}
        new_data = {"name": "my-secret", "secretData": "new-super-secret-value"}
        diff_lines = cai_main.diff_dicts(old_data, new_data)
        joined = "\n".join(diff_lines)
        self.assertIn("[REDACTED SECRET DATA CHANGED]", joined)
        self.assertNotIn("old-super-secret-value", joined)
        self.assertNotIn("new-super-secret-value", joined)

    def test_slack_control_characters_are_escaped(self):
        payload = load_fixture("firewall_open_ssh_console.json")
        payload["asset"]["resource"]["data"]["description"] = "Rule <script>&alert(1)</script>"
        text = all_text(cai_main.build_blocks(payload))
        self.assertIn("&lt;script&gt;&amp;alert(1)&lt;/script&gt;", text)
        self.assertNotIn("<script>", text)

    def test_project_allowlist_and_deduplication(self):
        payload = load_fixture("firewall_open_ssh_console.json")
        os.environ["ALLOWED_PROJECTS"] = "other-project"
        self.assertFalse(cai_main.should_notify(payload))

        os.environ["ALLOWED_PROJECTS"] = "prod-networking-01"
        self.assertTrue(cai_main.should_notify(payload))
        # Second immediate call with identical diff is deduplicated
        self.assertFalse(cai_main.should_notify(payload))


class TestOtherMonitorFunctions(unittest.TestCase):
    def test_cpu_machine_type_handles_missing_optional_fields_and_escapes_html(self):
        event_payload = {
            "asset": {
                "name": "//compute.googleapis.com/projects/prod-proj/zones/europe-west1-b/instances/vm-<script>",
                "resource": {
                    "data": {
                        "name": "vm-<script>",
                        "status": "RUNNING",
                        "machineType": "zones/europe-west1-b/machineTypes/e2-medium",
                        # Intentionally omit confidentialInstanceConfig, shieldedInstanceConfig, cpuPlatform
                    }
                },
            }
        }
        message, title = cpu_main.check_conditions(event_payload)
        self.assertIsNotNone(message)
        self.assertIn("vm-&lt;script&gt;", title)
        self.assertIn("<b>e2-medium</b>", message)
        self.assertNotIn("<script>", message)

    def test_monitor_principals_does_not_exist_state_no_unbound_local_error(self):
        event_payload = {
            "priorAssetState": "DOES_NOT_EXIST",
            "asset": {
                "name": "//cloudresourcemanager.googleapis.com/projects/my-crown-jewel-proj",
                "iamPolicy": {
                    "bindings": [
                        {
                            "role": "roles/owner",
                            "members": ["user:alice@example.com"],
                        }
                    ]
                },
            },
        }
        message, title = principals_main.create_message(event_payload)
        self.assertIsNotNone(message)
        self.assertIn("roles/owner", message)
        self.assertIn("user:alice@example.com", message)

    def test_sa_iam_monitor_handles_empty_bindings_and_escapes_html(self):
        event_payload = {
            "priorAssetState": "PRESENT",
            "asset": {
                "name": "//iam.googleapis.com/projects/my-proj/serviceAccounts/sa@my-proj.iam.gserviceaccount.com",
                "iamPolicy": {
                    "bindings": [
                        {
                            "role": "roles/iam.serviceAccountTokenCreator",
                            "members": ["user:bob<img src=x>@example.com"],
                        }
                    ]
                },
            },
            "priorAsset": {
                "name": "//iam.googleapis.com/projects/my-proj/serviceAccounts/sa@my-proj.iam.gserviceaccount.com",
                "iamPolicy": {},  # No bindings key on priorAsset
            },
        }
        message, title = sa_iam_main.create_message(event_payload)
        self.assertIsNotNone(message)
        self.assertIn("user:bob&lt;img src=x&gt;@example.com", message)
        self.assertNotIn("<img", message)


if __name__ == "__main__":
    unittest.main()
