"""Google Cloud Asset Inventory (CAI) & SCC Crown Jewel change notifications to Slack.

Cloud Run function (2nd gen) triggered by Eventarc when Cloud Asset Inventory
(or Security Command Center) publishes an asset change or finding notification
to the Pub/Sub topic. The function computes the CAI before/after diff,
attributes the change (Who: User vs Service Account, and How: Console,
Terraform, or gcloud CLI via Cloud Audit Logs), formats the alert with a Slack
Block Kit template, and posts it via chat.postMessage.

Runtime: Python 3.13. Entry point: send_slack_chat_notification
(Also exports aliases `asset_inventory_to_slack` and `filter_rule` for compatibility.)

Environment variables:
  SLACK_BOT_TOKEN           Slack bot token (xoxb-...). Injected from Secret Manager.
  SLACK_CHANNEL             Channel ID (recommended) or name to post to.
  GCP_PROJECT               Optional project ID for Secret Manager / Cloud Logging fallback.
  ALLOWED_PROJECTS          Optional comma-separated list of project IDs or
                            display names. When set, other projects are skipped.
  MONITORED_ASSET_TYPES     Optional comma-separated list of CAI asset types to
                            alert on. Empty means all asset types in the feed.
  ENABLE_AUDIT_LOG_LOOKUP   When "true" (default), queries Cloud Audit Logs
                            (entries:list) to enrich actor & execution method
                            (Console, Terraform, gcloud CLI) if not already
                            embedded in the payload.
  DEDUP_WINDOW_SECONDS      Cooldown window in seconds for identical asset
                            change digests (default: 60).
  MAX_EVENT_AGE_SECONDS     Events older than this are dropped instead of being
                            retried forever (default: 3600).
"""

import base64
import copy
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

try:
    import requests
except ImportError:
    # Fallback shim so local CLI dry-runs work even without pip packages installed
    class _UrllibResponse:
        def __init__(self, status_code, body_bytes):
            self.status_code = status_code
            self._body = body_bytes

        def json(self):
            return json.loads(self._body.decode("utf-8"))

    class _UrllibRequestsShim:
        class RequestException(Exception):
            pass

        class ConnectionError(RequestException):
            pass

        @staticmethod
        def get(url, headers=None, timeout=10):
            req = urllib.request.Request(url, headers=headers or {}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return _UrllibResponse(resp.status, resp.read())
            except urllib.error.HTTPError as exc:
                return _UrllibResponse(exc.code, exc.read())
            except Exception as exc:
                raise _UrllibRequestsShim.RequestException(str(exc)) from exc

        @staticmethod
        def post(url, headers=None, data=None, json_data=None, timeout=10, **kwargs):
            if json_data is None and "json" in kwargs:
                json_data = kwargs["json"]
            if json_data is not None and data is None:
                data = json.dumps(json_data)
            payload = data.encode("utf-8") if isinstance(data, str) else data
            req = urllib.request.Request(url, data=payload, headers=headers or {}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return _UrllibResponse(resp.status, resp.read())
            except urllib.error.HTTPError as exc:
                return _UrllibResponse(exc.code, exc.read())
            except Exception as exc:
                raise _UrllibRequestsShim.RequestException(str(exc)) from exc

    requests = _UrllibRequestsShim()

try:
    import functions_framework
except ImportError:  # Allows local dry run without the framework installed.
    functions_framework = None

try:
    from google.cloud import secretmanager
except ImportError:
    secretmanager = None

SLACK_API_URL = "https://slack.com/api/chat.postMessage"
CLOUD_LOGGING_ENTRIES_URL = "https://logging.googleapis.com/v2/entries:list"
METADATA_TOKEN_URL = (
    "http://metadata.google.internal/computeMetadata/v1/"
    "instance/service-accounts/default/token"
)
CONSOLE_ASSET_URL = "https://console.cloud.google.com/security/command-center/assets"
CONSOLE_FINDINGS_URL = "https://console.cloud.google.com/security/command-center/findingsv2"
CONSOLE_LOGS_URL = "https://console.cloud.google.com/logs/query"

SLACK_SECTION_TEXT_LIMIT = 3000
SLACK_TIMEOUT_SECONDS = 10
LOGGING_TIMEOUT_SECONDS = 5
TEMPLATE_PATH = Path(__file__).parent / "block_templates" / "asset-change-detail.json"

PLACEHOLDER_KEYS = (
    "ALERT_HEADER",
    "WEB_LINK",
    "SUBJECT",
    "RESOURCE_NAME",
    "RESOURCE_TYPE",
    "PROJECT_ID",
    "LOCATION",
    "CHANGE_ACTION",
    "ACTION_EMOJI",
    "TIMESTAMP",
    "ATTRIBUTION_DETAILS",
    "SECURITY_HIGHLIGHTS",
    "CHANGE_DIFF",
    "RECOMMENDATION",
)

ACTION_EMOJI_MAP = {
    "CREATED": ":new:",
    "MODIFIED": ":pencil2:",
    "DELETED": ":wastebasket:",
    "IAM_POLICY_UPDATED": ":key:",
    "SCC_FINDING": ":rotating_light:",
}

# Noisy system-generated fields ignored when computing CAI diffs
IGNORED_DIFF_KEYS = {
    "etag",
    "fingerprint",
    "labelFingerprint",
    "metadataFingerprint",
    "selfLink",
    "selfLinkWithId",
    "id",
    "creationTimestamp",
    "kind",
    "satisfiesPzs",
    "satisfiesPzi",
}

# Sensitive keys whose values must never be printed in Slack diffs
REDACTED_DIFF_KEYS = {
    "secretData",
    "payload",
    "privateKeyData",
    "publicKeyData",
    "rawKey",
    "sha256",
    "password",
    "token",
    "secret",
}

PRIVILEGED_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.workloadIdentityPoolAdmin",
    "roles/iam.workloadIdentityUser",
    "roles/secretmanager.admin",
    "roles/secretmanager.secretAccessor",
    "roles/cloudkms.admin",
    "roles/cloudkms.cryptoKeyDecrypter",
    "roles/cloudkms.cryptoKeyEncrypterDecrypter",
    "roles/compute.networkAdmin",
    "roles/compute.securityAdmin",
    "roles/compute.orgFirewallPolicyAdmin",
    "roles/compute.orgSecurityPolicyAdmin",
    "roles/compute.xpnAdmin",
    "roles/orgpolicy.policyAdmin",
    "roles/resourcemanager.organizationAdmin",
    "roles/resourcemanager.folderIamAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/bigquery.admin",
    "roles/bigquery.dataOwner",
    "roles/bigquery.dataEditor",
    "roles/cloudsql.admin",
    "roles/cloudsql.client",
    "roles/storage.admin",
    "roles/storage.objectAdmin",
    "roles/container.admin",
    "roles/container.clusterAdmin",
    "roles/container.developer",
    "roles/gkehub.admin",
    "roles/run.admin",
    "roles/binaryauthorization.policyAdmin",
    "roles/binaryauthorization.attestorsAdmin",
}

# Permissions on custom IAM roles that enable privilege escalation or secret/token access
HIGH_RISK_IAM_PERMISSIONS = {
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
    "iam.serviceAccounts.actAs",
    "iam.serviceAccountKeys.create",
    "iam.roles.update",
    "resourcemanager.projects.setIamPolicy",
    "resourcemanager.folders.setIamPolicy",
    "resourcemanager.organizations.setIamPolicy",
    "deploymentmanager.deployments.create",
    "secretmanager.versions.access",
    "container.clusters.update",
    "container.secrets.get",
    "run.services.setIamPolicy",
    "binaryauthorization.policies.update",
}

# Slack API errors worth retrying. Everything else is treated as permanent.
TRANSIENT_SLACK_ERRORS = {
    "ratelimited",
    "internal_error",
    "fatal_error",
    "service_unavailable",
    "request_timeout",
}

_template_cache = None
_recent_alerts_cache = {}
_secret_client = None


class TransientError(Exception):
    """Raised to make Eventarc redeliver the event."""


class PermanentError(Exception):
    """The event can never succeed. It is logged and acknowledged."""


def log(severity, message, **fields):
    """Write a structured log line that Cloud Logging parses from stdout."""
    print(json.dumps({"severity": severity, "message": message, **fields}), flush=True)


# --------------------------------------------------------------------------
# Secret Resolution (Env Var + Secret Manager compatibility)
# --------------------------------------------------------------------------

def get_secret(secret_id=None, version_id="latest", project_id=None):
    """Retrieve a secret from environment variables or Google Cloud Secret Manager.

    Prefers direct environment injection (Cloud Run functions `secret_environment_variables`).
    Falls back to Secret Manager API if a `projects/.../secrets/...` path or
    `GCP_PROJECT` + `secret_id` is configured.
    """
    env_token = os.environ.get("SLACK_BOT_TOKEN", "").strip()
    if env_token and not env_token.startswith("projects/"):
        return env_token

    if secretmanager is None:
        raise PermanentError(
            "SLACK_BOT_TOKEN is not set in environment and google-cloud-secret-manager is not installed."
        )

    global _secret_client
    if _secret_client is None:
        _secret_client = secretmanager.SecretManagerServiceClient()

    if env_token.startswith("projects/"):
        name = env_token
        if "/versions/" not in name:
            name = f"{name}/versions/{version_id}"
    else:
        secret_id = secret_id or os.environ.get("SECRET_ID", "cainotifier-slack-bot-token")
        project_id = (
            project_id
            or os.environ.get("GCP_PROJECT")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
        )
        if not project_id:
            raise PermanentError(
                "SLACK_BOT_TOKEN or GCP_PROJECT environment variable must be configured."
            )
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"

    request = secretmanager.AccessSecretVersionRequest(name=name)
    return _secret_client.access_secret_version(request=request).payload.data.decode("utf-8").strip()


# --------------------------------------------------------------------------
# Parsing & Filtering
# --------------------------------------------------------------------------

def parse_pubsub_message(event_data):
    """Return the decoded CAI or SCC notification dict from an Eventarc or Gen 1 Pub/Sub event."""
    try:
        if hasattr(event_data, "data") and isinstance(event_data.data, dict):
            event_data = event_data.data
        if not isinstance(event_data, dict):
            raise TypeError("Event payload must be a dict or CloudEvent")

        if "message" in event_data and isinstance(event_data["message"], dict):
            encoded = event_data["message"]["data"]
        elif "data" in event_data:
            encoded = event_data["data"]
        else:
            raise KeyError("Missing 'message.data' or 'data' in Pub/Sub event")

        if isinstance(encoded, bytes):
            raw_json = base64.b64decode(encoded).decode("utf-8")
        else:
            raw_json = base64.b64decode(str(encoded)).decode("utf-8")
        return json.loads(raw_json)
    except (KeyError, TypeError, ValueError) as exc:
        raise PermanentError(f"Cannot decode Pub/Sub message: {exc}") from exc


def event_age_seconds(event_time, now=None):
    """Age of an RFC 3339 timestamp in seconds, or None when unparsable."""
    if not event_time:
        return None
    try:
        ts = datetime.fromisoformat(str(event_time).replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return (now - ts).total_seconds()


def allowed_projects():
    raw = os.environ.get("ALLOWED_PROJECTS", "")
    return {p.strip() for p in raw.split(",") if p.strip()}


def monitored_asset_types():
    raw = os.environ.get("MONITORED_ASSET_TYPES", "")
    return {t.strip() for t in raw.split(",") if t.strip()}


def dedup_window_seconds():
    return int(os.environ.get("DEDUP_WINDOW_SECONDS", "60"))


def get_data(message_json):
    """Extract primary resource data dictionary from a CAI message (with priorAsset fallback)."""
    if not isinstance(message_json, dict):
        return {}
    asset_data = ((message_json.get("asset") or {}).get("resource") or {}).get("data")
    if isinstance(asset_data, dict):
        return asset_data
    prior_data = ((message_json.get("priorAsset") or {}).get("resource") or {}).get("data")
    if isinstance(prior_data, dict):
        return prior_data
    return {}


def json_extract(obj, key):
    """Recursively fetch values for `key` from nested JSON structures."""
    arr = []

    def _extract(current, results, target_key):
        if isinstance(current, dict):
            for k, v in current.items():
                if k == target_key and not isinstance(v, (dict, list)):
                    results.append(v)
                elif isinstance(v, (dict, list)):
                    if k == target_key:
                        results.append(v)
                    _extract(v, results, target_key)
        elif isinstance(current, list):
            for item in current:
                _extract(item, results, target_key)
        return results

    return _extract(obj, arr, key)


def extract_project_identifiers(notification):
    """Return (primary_project_display, set_of_all_project_identifiers)."""
    ids = set()
    primary = None

    # 1. Check CAI asset / priorAsset structure
    asset = notification.get("asset") or notification.get("priorAsset") or {}
    asset_name = asset.get("name") or ""
    if "/projects/" in asset_name:
        proj_seg = asset_name.split("/projects/", 1)[1].split("/", 1)[0]
        if proj_seg:
            ids.add(proj_seg)
            primary = proj_seg

    resource_parent = (asset.get("resource") or {}).get("parent") or ""
    if "/projects/" in resource_parent:
        parent_proj = resource_parent.split("/projects/", 1)[1].split("/", 1)[0]
        if parent_proj:
            ids.add(parent_proj)
            primary = primary or parent_proj

    for ancestor in asset.get("ancestors") or []:
        if isinstance(ancestor, str) and ancestor.startswith("projects/"):
            anc_id = ancestor.split("/", 1)[1]
            ids.add(ancestor)
            ids.add(anc_id)
            primary = primary or anc_id

    # Fallback for organization- or folder-scoped assets (e.g. Org Policies)
    if not primary:
        if "/organizations/" in asset_name:
            org_seg = asset_name.split("/organizations/", 1)[1].split("/", 1)[0]
            if org_seg:
                primary = f"organizations/{org_seg}"
                ids.add(primary)
                ids.add(org_seg)
        elif "/folders/" in asset_name:
            folder_seg = asset_name.split("/folders/", 1)[1].split("/", 1)[0]
            if folder_seg:
                primary = f"folders/{folder_seg}"
                ids.add(primary)
                ids.add(folder_seg)

    # 2. Check SCC notification resource structure
    scc_res = notification.get("resource") or {}
    gcp_meta = scc_res.get("gcpMetadata") or {}
    for candidate in (
        scc_res.get("projectDisplayName"),
        gcp_meta.get("projectDisplayName"),
        scc_res.get("project"),
        gcp_meta.get("project"),
    ):
        if candidate:
            short = str(candidate).rsplit("/", 1)[-1]
            ids.add(str(candidate))
            ids.add(short)
            if not primary or primary.isdigit():
                primary = short

    return (primary or "n/a"), ids


def extract_location(notification):
    """Extract region/zone/location of the asset."""
    asset = notification.get("asset") or notification.get("priorAsset") or {}
    resource = asset.get("resource") or {}
    if resource.get("location"):
        return str(resource["location"])

    asset_name = asset.get("name") or ""
    for marker in ("/zones/", "/regions/", "/locations/"):
        if marker in asset_name:
            loc = asset_name.split(marker, 1)[1].split("/", 1)[0]
            if loc:
                return loc

    scc_res = notification.get("resource") or {}
    if scc_res.get("location"):
        return str(scc_res["location"])

    return "global"


def determine_change_action(notification):
    """Determine whether the event represents CREATED, MODIFIED, DELETED, IAM_POLICY_UPDATED, or SCC_FINDING."""
    if "finding" in notification and "asset" not in notification:
        return "SCC_FINDING"

    if notification.get("deleted") is True or notification.get("priorAssetState") == "DELETED":
        return "DELETED"

    prior_state = notification.get("priorAssetState") or "PRESENT"
    asset = notification.get("asset") or {}
    prior_asset = notification.get("priorAsset") or {}

    has_iam = bool(asset.get("iamPolicy") or prior_asset.get("iamPolicy"))
    has_res = bool((asset.get("resource") or {}).get("data") or (prior_asset.get("resource") or {}).get("data"))

    if prior_state == "DOES_NOT_EXIST":
        return "CREATED"
    if has_iam and not has_res:
        return "IAM_POLICY_UPDATED"
    return "MODIFIED"


# --------------------------------------------------------------------------
# Cloud Audit Logs Attribution (Who & How: Console vs Terraform vs CLI)
# --------------------------------------------------------------------------

def classify_execution_method(user_agent, explicit_method=None):
    """Classify how the change was executed based on callerSuppliedUserAgent."""
    if explicit_method:
        norm = str(explicit_method).strip()
        low = norm.lower()
        if "terraform" in low:
            return "Terraform (IaC) :terraform:", False
        if "console" in low or "ui" in low or "web" in low:
            return "Google Cloud Console (Web UI) :warning:", True
        if "gcloud" in low or "cli" in low:
            return f"gcloud CLI ({norm}) :warning:", True
        return norm, False

    if not user_agent:
        return "Unknown (Audit log not attached)", False

    ua = str(user_agent).strip()
    ua_lower = ua.lower()

    # 1. Terraform
    if "terraform" in ua_lower:
        tf_ver = None
        for token in ua.split():
            if token.lower().startswith("terraform/"):
                tf_ver = token
                break
        label = f"Terraform ({tf_ver})" if tf_ver else "Terraform (IaC)"
        return label, False

    # 2. Pulumi / Crossplane / Ansible / Deployment Manager
    for iac_tool in ("pulumi", "crossplane", "ansible", "google-cloud-deployment-manager"):
        if iac_tool in ua_lower:
            return f"{iac_tool.title()} (IaC)", False

    # 3. Google Cloud CLI (gcloud)
    if "google-cloud-sdk" in ua_lower or "gcloud/" in ua_lower:
        cmd = None
        for token in ua.split():
            if token.startswith("command/"):
                cmd = token.replace("command/", "").replace(".", " ")
                break
        if cmd:
            return f"gcloud CLI (`{cmd}`) :warning:", True
        return "gcloud CLI :warning:", True

    # 4. Google Cloud Console (Browser / Pantheon / CloudConsole)
    if (
        "mozilla/" in ua_lower
        or "cloudconsole" in ua_lower
        or "pantheon" in ua_lower
        or "console.cloud.google.com" in ua_lower
    ):
        return "Google Cloud Console (Web UI / ClickOps) :warning:", True

    # 5. Direct API / Client SDK / curl
    if any(k in ua_lower for k in ("google-api-", "grpc-", "python-requests", "curl/", "go-http-client")):
        return f"API / SDK (`{ua[:60]}`)", True

    return f"Custom Client (`{ua[:60]}`)", False


def classify_principal(principal_email, delegation_chain=None):
    """Classify whether the actor is a User, Service Account, or Impersonated SA."""
    if not principal_email:
        return "Unknown principal", "UNKNOWN"

    email = str(principal_email).strip()
    if email.startswith("user:"):
        email = email.split(":", 1)[1]
    elif email.startswith("serviceAccount:"):
        email = email.split(":", 1)[1]

    delegator = None
    if isinstance(delegation_chain, list):
        for item in delegation_chain:
            if isinstance(item, dict):
                first_party = item.get("firstPartyPrincipal") or {}
                if first_party.get("principalEmail"):
                    delegator = first_party["principalEmail"]
                    break

    if email.endswith(".gserviceaccount.com"):
        if delegator and not delegator.endswith(".gserviceaccount.com"):
            return (
                f"`{delegator}` *(User impersonating Service Account `{email}`)*",
                "IMPERSONATED_SA",
            )
        return f"`{email}` *(Service Account)*", "SERVICE_ACCOUNT"

    if email.startswith("principal://") or email.startswith("principalSet://"):
        return f"`{email}` *(Workload Identity / Federated)*", "WORKLOAD_IDENTITY"

    if "@" in email:
        return f"`{email}` *(User Account)*", "USER"

    return f"`{email}`", "OTHER"


def _fetch_metadata_access_token(session=requests):
    """Fetch an OAuth2 access token from the GCP Metadata Server when running in Cloud Run."""
    try:
        resp = session.get(
            METADATA_TOKEN_URL,
            headers={"Metadata-Flavor": "Google"},
            timeout=2,
        )
        if resp.status_code == 200:
            return (resp.json() or {}).get("access_token")
    except Exception:
        return None
    return None


def lookup_cloud_audit_log(project_id, resource_name, event_timestamp, session=requests):
    """Query Cloud Logging API for the most recent Admin Activity / Data Access Audit Log."""
    if os.environ.get("ENABLE_AUDIT_LOG_LOOKUP", "true").lower() not in ("1", "true", "yes"):
        return None
    if not project_id or project_id == "n/a":
        return None

    token = os.environ.get("GCP_ACCESS_TOKEN") or _fetch_metadata_access_token(session=session)
    if not token:
        return None

    short_name = (resource_name or "").rsplit("/", 1)[-1]
    if not short_name:
        return None

    # Build time window around event_timestamp
    time_filter = ""
    if event_timestamp and event_timestamp != "n/a":
        try:
            ts = datetime.fromisoformat(str(event_timestamp).replace("Z", "+00:00"))
            start_ts = (ts - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
            end_ts = (ts + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            time_filter = f' AND timestamp>="{start_ts}" AND timestamp<="{end_ts}"'
        except ValueError:
            pass

    log_filter = (
        f'protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog" '
        f'AND protoPayload.resourceName:"{short_name}"{time_filter}'
    )

    try:
        resp = session.post(
            CLOUD_LOGGING_ENTRIES_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            data=json.dumps({
                "resourceNames": [f"projects/{project_id}"],
                "filter": log_filter,
                "orderBy": "timestamp desc",
                "pageSize": 1,
            }),
            timeout=LOGGING_TIMEOUT_SECONDS,
        )
        if resp.status_code != 200:
            return None
        entries = (resp.json() or {}).get("entries") or []
        if entries and isinstance(entries[0], dict):
            return entries[0].get("protoPayload")
    except Exception as exc:
        log("WARNING", f"Cloud Audit Log lookup failed: {exc}")
    return None


def extract_attribution(notification, project_id, resource_name, timestamp, session=requests):
    """Extract Actor (Who) and Execution Method (How: Console, Terraform, CLI) from payload or Cloud Audit Logs."""
    audit = (
        notification.get("auditLog")
        or notification.get("protoPayload")
        or (notification.get("asset") or {}).get("auditLog")
        or ((notification.get("finding") or {}).get("sourceProperties") or {}).get("auditLog")
    )

    if not isinstance(audit, dict):
        audit = lookup_cloud_audit_log(project_id, resource_name, timestamp, session=session) or {}

    auth_info = audit.get("authenticationInfo") or {}
    req_meta = audit.get("requestMetadata") or {}

    principal_email = (
        auth_info.get("principalEmail")
        or notification.get("actor")
        or notification.get("principalEmail")
    )
    delegation_chain = auth_info.get("serviceAccountDelegationInfo")
    user_agent = req_meta.get("callerSuppliedUserAgent") or notification.get("userAgent")
    explicit_tool = notification.get("executionMethod")
    caller_ip = req_meta.get("callerIp") or notification.get("callerIp")
    method_name = audit.get("methodName") or notification.get("methodName")

    actor_display, actor_type = classify_principal(principal_email, delegation_chain)
    exec_display, is_manual_clickops = classify_execution_method(user_agent, explicit_tool)

    return {
        "principal_email": principal_email,
        "actor_display": actor_display,
        "actor_type": actor_type,
        "execution_display": exec_display,
        "is_manual_clickops": is_manual_clickops,
        "caller_ip": caller_ip,
        "method_name": method_name,
        "user_agent": user_agent,
    }


# --------------------------------------------------------------------------
# Cloud Asset Inventory (CAI) Diff Engine (Resource Data + IAM Policy)
# --------------------------------------------------------------------------

def _format_scalar(val):
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, str):
        return f'"{val}"' if len(val) <= 80 else f'"{val[:77]}..."'
    dumped = json.dumps(val, ensure_ascii=False)
    return dumped if len(dumped) <= 100 else dumped[:97] + "..."


def diff_dicts(old_dict, new_dict, path="", max_lines=18):
    """Compute a concise list of human-readable diff lines between two nested dicts."""
    lines = []
    old_dict = old_dict if isinstance(old_dict, dict) else {}
    new_dict = new_dict if isinstance(new_dict, dict) else {}

    all_keys = sorted(set(old_dict.keys()) | set(new_dict.keys()))
    for key in all_keys:
        if key in IGNORED_DIFF_KEYS:
            continue
        full_key = f"{path}.{key}" if path else key

        if key in REDACTED_DIFF_KEYS:
            if old_dict.get(key) != new_dict.get(key):
                lines.append(f"~ {full_key}: [REDACTED SECRET DATA CHANGED]")
            continue

        in_old = key in old_dict
        in_new = key in new_dict
        old_val = old_dict.get(key)
        new_val = new_dict.get(key)

        if not in_old and in_new:
            lines.append(f"+ {full_key}: {_format_scalar(new_val)}")
        elif in_old and not in_new:
            lines.append(f"- {full_key}: {_format_scalar(old_val)}")
        elif old_val != new_val:
            if isinstance(old_val, dict) and isinstance(new_val, dict):
                lines.extend(diff_dicts(old_val, new_val, path=full_key, max_lines=max_lines))
            elif isinstance(old_val, list) and isinstance(new_val, list):
                # Check if list of scalar items
                if all(isinstance(x, (str, int, float, bool)) for x in old_val + new_val):
                    added = [x for x in new_val if x not in old_val]
                    removed = [x for x in old_val if x not in new_val]
                    if added:
                        lines.append(f"+ {full_key}: added {_format_scalar(added)}")
                    if removed:
                        lines.append(f"- {full_key}: removed {_format_scalar(removed)}")
                    if not added and not removed:
                        lines.append(
                            f"~ {full_key}: {_format_scalar(old_val)} -> {_format_scalar(new_val)}"
                        )
                elif all(isinstance(x, dict) for x in old_val + new_val) and (
                    key in ("authorizedNetworks", "access", "peerings", "nats", "bgpPeers", "secondaryIpRanges", "rules")
                ):
                    added = [x for x in new_val if x not in old_val]
                    removed = [x for x in old_val if x not in new_val]
                    if added:
                        lines.append(f"+ {full_key}: added {_format_scalar(added)}")
                    if removed:
                        lines.append(f"- {full_key}: removed {_format_scalar(removed)}")
                    if not added and not removed:
                        lines.append(
                            f"~ {full_key}: {_format_scalar(old_val)} -> {_format_scalar(new_val)}"
                        )
                else:
                    lines.append(
                        f"~ {full_key}: {_format_scalar(old_val)} -> {_format_scalar(new_val)}"
                    )
            else:
                lines.append(
                    f"~ {full_key}: {_format_scalar(old_val)} -> {_format_scalar(new_val)}"
                )

        if len(lines) >= max_lines:
            break

    return lines[:max_lines]


def _normalize_bindings(bindings):
    """Aggregate members by role from an IAM policy bindings list."""
    role_map = {}
    if not isinstance(bindings, list):
        return role_map
    for b in bindings:
        if not isinstance(b, dict) or "role" not in b:
            continue
        role = b["role"]
        members = b.get("members") or []
        condition = b.get("condition")
        role_key = f"{role} [condition: {condition.get('title')}]" if isinstance(condition, dict) and condition.get("title") else role
        role_map.setdefault(role_key, set()).update(str(m) for m in members)
    return role_map


def _normalize_principal_roles(bindings):
    """Aggregate roles by principal (user / serviceAccount / group) from IAM bindings."""
    principal_map = {}
    for role, members in _normalize_bindings(bindings).items():
        for member in members:
            principal_map.setdefault(member, set()).add(role)
    return principal_map


def diff_iam_policies(old_iam, new_iam):
    """Compute human-readable diff lines between priorAsset.iamPolicy and asset.iamPolicy."""
    old_bindings = (old_iam or {}).get("bindings") or []
    new_bindings = (new_iam or {}).get("bindings") or []
    old_map = _normalize_bindings(old_bindings)
    new_map = _normalize_bindings(new_bindings)
    lines = []

    all_roles = sorted(set(old_map.keys()) | set(new_map.keys()))
    for role in all_roles:
        old_members = old_map.get(role, set())
        new_members = new_map.get(role, set())
        if not old_members and new_members:
            lines.append(f"+ IAM Role Added: {role} -> {sorted(new_members)}")
        elif old_members and not new_members:
            lines.append(f"- IAM Role Removed: {role} (was {sorted(old_members)})")
        elif old_members != new_members:
            added = sorted(new_members - old_members)
            removed = sorted(old_members - new_members)
            if added:
                lines.append(f"+ IAM Binding ({role}): added {added}")
            if removed:
                lines.append(f"- IAM Binding ({role}): removed {removed}")

    # Highlight per-principal privilege escalation when an existing principal gains additional roles
    old_principals = _normalize_principal_roles(old_bindings)
    new_principals = _normalize_principal_roles(new_bindings)
    for principal in sorted(new_principals.keys()):
        prior_roles = old_principals.get(principal, set())
        gained_roles = sorted(new_principals[principal] - prior_roles)
        if prior_roles and gained_roles:
            lines.append(
                f"~ Privilege Escalation ({principal}): gained {gained_roles} (existing: {sorted(prior_roles)})"
            )

    return lines


def diff_org_policies(old_policies, new_policies):
    """Compute human-readable diff lines between priorAsset.orgPolicy and asset.orgPolicy lists."""
    old_map = {
        p.get("constraint"): p
        for p in (old_policies or [])
        if isinstance(p, dict) and p.get("constraint")
    }
    new_map = {
        p.get("constraint"): p
        for p in (new_policies or [])
        if isinstance(p, dict) and p.get("constraint")
    }
    lines = []
    for constraint in sorted(set(old_map.keys()) | set(new_map.keys())):
        old_p = old_map.get(constraint)
        new_p = new_map.get(constraint)
        if not old_p and new_p:
            lines.extend(diff_dicts({}, new_p, path=f"orgPolicy[{constraint}]", max_lines=10))
        elif old_p and not new_p:
            lines.extend(diff_dicts(old_p, {}, path=f"orgPolicy[{constraint}]", max_lines=10))
        elif old_p != new_p:
            lines.extend(diff_dicts(old_p, new_p, path=f"orgPolicy[{constraint}]", max_lines=10))
    return lines


def compute_asset_diff(notification):
    """Build the formatted CAI diff block for resource data, IAM policy, and/or Org Policy changes."""
    if "finding" in notification and "asset" not in notification:
        finding = notification.get("finding") or {}
        props = finding.get("sourceProperties") or {}
        explanation = props.get("Explanation") or finding.get("description")
        if explanation:
            return f"```{truncate(str(explanation), 1200)}```"
        return None

    asset = notification.get("asset") or {}
    prior_asset = notification.get("priorAsset") or {}
    action = determine_change_action(notification)

    current_data = (asset.get("resource") or {}).get("data") or {}
    prior_data = (prior_asset.get("resource") or {}).get("data") or {}
    current_iam = asset.get("iamPolicy") or {}
    prior_iam = prior_asset.get("iamPolicy") or {}
    current_org_pol = asset.get("orgPolicy") or []
    prior_org_pol = prior_asset.get("orgPolicy") or []

    diff_lines = []

    if action == "CREATED":
        if current_data:
            diff_lines.extend(diff_dicts({}, current_data, max_lines=14))
        if current_iam:
            diff_lines.extend(diff_iam_policies({}, current_iam))
        if current_org_pol:
            diff_lines.extend(diff_org_policies([], current_org_pol))
    elif action == "DELETED":
        if prior_data:
            diff_lines.extend(diff_dicts(prior_data, {}, max_lines=14))
        elif current_data:
            diff_lines.extend(diff_dicts(current_data, {}, max_lines=14))
        if prior_iam:
            diff_lines.extend(diff_iam_policies(prior_iam, {}))
        if prior_org_pol:
            diff_lines.extend(diff_org_policies(prior_org_pol, []))
    else:
        if current_data or prior_data:
            diff_lines.extend(diff_dicts(prior_data, current_data, max_lines=14))
        if current_iam or prior_iam:
            diff_lines.extend(diff_iam_policies(prior_iam, current_iam))
        if current_org_pol or prior_org_pol:
            diff_lines.extend(diff_org_policies(prior_org_pol, current_org_pol))

    if not diff_lines:
        return "`No structural attribute or IAM binding diff detected (metadata-only update).`"

    joined = "\n".join(diff_lines)
    return f"```diff\n{truncate(escape_mrkdwn(joined), 1800)}\n```"


# --------------------------------------------------------------------------
# Crown Jewel Security Posture Analysis
# --------------------------------------------------------------------------

def analyze_security_posture(notification, attribution):
    """Identify high-priority security signals and remediation guidance for Crown Jewel changes."""
    highlights = []
    recommendations = []

    asset = notification.get("asset") or notification.get("priorAsset") or {}
    asset_type = asset.get("assetType") or (notification.get("resource") or {}).get("type") or ""
    action = determine_change_action(notification)
    current_data = (asset.get("resource") or {}).get("data") or {}
    prior_data = ((notification.get("priorAsset") or {}).get("resource") or {}).get("data") or {}

    # 1. Check ClickOps / Manual execution outside Terraform
    if attribution.get("is_manual_clickops"):
        highlights.append(
            f":warning: *Manual Change Outside IaC (ClickOps / CLI)*: Executed via {attribution['execution_display']} by {attribution['actor_display']}."
        )
        recommendations.append(
            "Verify whether this manual change was authorized under an emergency break-glass procedure and reconcile it into Terraform to prevent state drift."
        )

    # 2. Firewall rules: check source/destination IPs, port ranges/protocols, and logging changes
    if "Firewall" in asset_type and action != "DELETED":
        def _fmt_ports(rules_list):
            if not isinstance(rules_list, list):
                return ""
            return ", ".join(
                f"{a.get('IPProtocol', 'all')}:{','.join(a.get('ports', ['all']))}"
                for a in rules_list if isinstance(a, dict)
            )

        source_ranges = current_data.get("sourceRanges") or []
        prior_source_ranges = prior_data.get("sourceRanges") or []
        dest_ranges = current_data.get("destinationRanges") or []
        prior_dest_ranges = prior_data.get("destinationRanges") or []

        curr_allowed = _fmt_ports(current_data.get("allowed") or [])
        prior_allowed = _fmt_ports(prior_data.get("allowed") or [])
        curr_denied = _fmt_ports(current_data.get("denied") or [])
        prior_denied = _fmt_ports(prior_data.get("denied") or [])

        # 2a. Source IP ranges (0.0.0.0/0 public ingress + added/removed CIDRs)
        if "0.0.0.0/0" in source_ranges or "::/0" in source_ranges:
            ports_summary = curr_allowed or "all traffic"
            highlights.append(
                f":rotating_light: *Public Internet Ingress (`0.0.0.0/0`)*: Firewall rule exposes `{escape_mrkdwn(ports_summary)}` to the public internet."
            )
            recommendations.append(
                "Restrict `sourceRanges` to trusted corporate CIDRs, Identity-Aware Proxy (`35.235.240.0/20`), or internal VPC ranges."
            )
        if set(source_ranges) != set(prior_source_ranges) and (source_ranges or prior_source_ranges):
            added_src = sorted(set(source_ranges) - set(prior_source_ranges))
            removed_src = sorted(set(prior_source_ranges) - set(source_ranges))
            parts = []
            if added_src:
                parts.append(f"added `{escape_mrkdwn(', '.join(added_src))}`")
            if removed_src:
                parts.append(f"removed `{escape_mrkdwn(', '.join(removed_src))}`")
            highlights.append(
                f":warning: *Firewall Source IP Ranges Modified*: {', '.join(parts)}."
            )

        # 2b. Destination IP ranges (added/removed CIDRs)
        if set(dest_ranges) != set(prior_dest_ranges) and (dest_ranges or prior_dest_ranges):
            added_dst = sorted(set(dest_ranges) - set(prior_dest_ranges))
            removed_dst = sorted(set(prior_dest_ranges) - set(dest_ranges))
            parts = []
            if added_dst:
                parts.append(f"added `{escape_mrkdwn(', '.join(added_dst))}`")
            if removed_dst:
                parts.append(f"removed `{escape_mrkdwn(', '.join(removed_dst))}`")
            highlights.append(
                f":warning: *Firewall Destination IP Ranges Modified*: {', '.join(parts)}."
            )

        # 2c. Port ranges & protocols (allowed / denied)
        if curr_allowed != prior_allowed and (curr_allowed or prior_allowed):
            highlights.append(
                f":warning: *Firewall Allowed Port Ranges / Protocols Changed*: `{escape_mrkdwn(prior_allowed or 'none')}` -> `{escape_mrkdwn(curr_allowed or 'none')}`."
            )
        if curr_denied != prior_denied and (curr_denied or prior_denied):
            highlights.append(
                f":warning: *Firewall Denied Port Ranges / Protocols Changed*: `{escape_mrkdwn(prior_denied or 'none')}` -> `{escape_mrkdwn(curr_denied or 'none')}`."
            )

        # 2d. Firewall Rule Logging (logConfig.enable / logConfig.metadata)
        log_cfg = current_data.get("logConfig") or {}
        prior_log_cfg = prior_data.get("logConfig") or {}
        if prior_log_cfg.get("enable") is True and log_cfg.get("enable") is False:
            highlights.append(
                ":rotating_light: *Firewall Rule Logging Disabled*: `logConfig.enable` was turned off (`true -> false`), blinding network traffic audit logs for this rule."
            )
            recommendations.append(
                "Re-enable Firewall Rules Logging (`logConfig.enable = true`) to maintain visibility into allowed/denied connections."
            )
        elif log_cfg != prior_log_cfg and (log_cfg or prior_log_cfg):
            highlights.append(
                f":information_source: *Firewall Logging Configuration Changed*: `logConfig` updated (`enable={log_cfg.get('enable')}`, `metadata={escape_mrkdwn(str(log_cfg.get('metadata', 'n/a')))}`)."
            )

    # 3. Compute Instance: check external IP (ONE_TO_ONE_NAT), machineType, Shielded VM, Confidential Compute
    if "compute.googleapis.com/Instance" in asset_type and action != "DELETED":
        nat_types = json_extract(current_data.get("networkInterfaces") or [], "type")
        if "ONE_TO_ONE_NAT" in nat_types:
            nat_ips = json_extract(current_data.get("networkInterfaces") or [], "natIP")
            ip_label = f" (`{nat_ips[0]}`)" if nat_ips else ""
            highlights.append(
                f":rotating_light: *External Public IP Attached*: VM instance has `ONE_TO_ONE_NAT` external IP{ip_label}."
            )
            recommendations.append(
                "Remove the external IP (`accessConfigs`) from the VM and use Cloud NAT for egress and IAP TCP forwarding for SSH/RDP."
            )

        shielded = current_data.get("shieldedInstanceConfig") or {}
        if shielded and (
            shielded.get("enableSecureBoot") is False
            or shielded.get("enableVtpm") is False
            or shielded.get("enableIntegrityMonitoring") is False
        ):
            highlights.append(
                ":shield: *Shielded VM Controls Disabled*: One or more Shielded VM protections (`enableSecureBoot`, `enableVtpm`, `enableIntegrityMonitoring`) are disabled."
            )

        old_mt = (prior_data.get("machineType") or "").rsplit("/", 1)[-1]
        new_mt = (current_data.get("machineType") or "").rsplit("/", 1)[-1]
        if old_mt and new_mt and old_mt != new_mt:
            highlights.append(
                f":computer: *Machine Type Changed*: `{escape_mrkdwn(old_mt)}` -> `{escape_mrkdwn(new_mt)}`."
            )

    # 4. VPC Network, Subnetwork, Route, Router & Hybrid Connectivity
    if asset_type == "compute.googleapis.com/Network" and action != "DELETED":
        curr_peerings = {
            p.get("name"): p
            for p in (current_data.get("peerings") or [])
            if isinstance(p, dict) and p.get("name")
        }
        prior_peerings = {
            p.get("name"): p
            for p in (prior_data.get("peerings") or [])
            if isinstance(p, dict) and p.get("name")
        }
        added_peer_names = sorted(set(curr_peerings.keys()) - set(prior_peerings.keys()))
        removed_peer_names = sorted(set(prior_peerings.keys()) - set(curr_peerings.keys()))

        for p_name in added_peer_names:
            p = curr_peerings[p_name]
            peer_net = p.get("network") or "unknown"
            if "/projects/" in peer_net:
                peer_net = "projects/" + peer_net.split("/projects/", 1)[1]
            exp_routes = bool(p.get("exportCustomRoutes"))
            imp_routes = bool(p.get("importCustomRoutes"))
            highlights.append(
                f":rotating_light: *VPC Network Peering Added*: Peering `{escape_mrkdwn(p_name)}` connected to `{escape_mrkdwn(peer_net)}` (`exportCustomRoutes={exp_routes}`, `importCustomRoutes={imp_routes}`)."
            )
            recommendations.append(
                "Verify the peer VPC network belongs to a trusted project/organization and review custom route import/export settings to prevent unintended lateral network access."
            )

        for p_name in sorted(set(curr_peerings.keys()) & set(prior_peerings.keys())):
            curr_p = curr_peerings[p_name]
            prior_p = prior_peerings[p_name]
            if (
                (curr_p.get("exportCustomRoutes") is True and prior_p.get("exportCustomRoutes") is not True)
                or (curr_p.get("importCustomRoutes") is True and prior_p.get("importCustomRoutes") is not True)
            ):
                highlights.append(
                    f":warning: *VPC Peering Custom Route Exchange Enabled*: Peering `{escape_mrkdwn(p_name)}` enabled custom route exchange (`exportCustomRoutes={bool(curr_p.get('exportCustomRoutes'))}`, `importCustomRoutes={bool(curr_p.get('importCustomRoutes'))}`)."
                )

        if removed_peer_names:
            highlights.append(
                f":warning: *VPC Network Peering Removed*: Peering `{escape_mrkdwn(', '.join(removed_peer_names))}` was disconnected."
            )

        old_rm = (prior_data.get("routingConfig") or {}).get("routingMode")
        new_rm = (current_data.get("routingConfig") or {}).get("routingMode")
        if old_rm and new_rm and old_rm != new_rm:
            highlights.append(
                f":warning: *VPC Dynamic Routing Mode Changed*: `{escape_mrkdwn(str(old_rm))}` -> `{escape_mrkdwn(str(new_rm))}`."
            )

        if current_data.get("autoCreateSubnetworks") is True and prior_data.get("autoCreateSubnetworks") is not True:
            highlights.append(
                ":warning: *Auto-Mode VPC Subnetworks Enabled*: `autoCreateSubnetworks` is enabled on this VPC network."
            )

    if "Subnetwork" in asset_type and action != "DELETED":
        if prior_data.get("privateIpGoogleAccess") is True and current_data.get("privateIpGoogleAccess") is False:
            highlights.append(
                ":warning: *Private Google Access Disabled*: `privateIpGoogleAccess` was turned off on this subnetwork."
            )
        curr_flow_cfg = current_data.get("logConfig") or {}
        prior_flow_cfg = prior_data.get("logConfig") or {}
        if (
            (prior_data.get("enableFlowLogs") is True and current_data.get("enableFlowLogs") is False)
            or (prior_flow_cfg.get("enable") is True and curr_flow_cfg.get("enable") is False)
        ):
            highlights.append(
                ":warning: *VPC Flow Logs Disabled*: `enableFlowLogs` was turned off on this subnetwork."
            )
            recommendations.append(
                "Re-enable VPC Flow Logs on critical subnetworks to preserve network forensics and anomaly detection visibility."
            )
        old_cidr = prior_data.get("ipCidrRange")
        new_cidr = current_data.get("ipCidrRange")
        if old_cidr and new_cidr and old_cidr != new_cidr:
            highlights.append(
                f":warning: *Subnetwork IP CIDR Range Modified*: `{escape_mrkdwn(str(old_cidr))}` -> `{escape_mrkdwn(str(new_cidr))}`."
            )

    if asset_type == "compute.googleapis.com/Route" and action != "DELETED":
        dest_range = current_data.get("destRange") or ""
        next_hop = (
            current_data.get("nextHopGateway")
            or current_data.get("nextHopIp")
            or current_data.get("nextHopInstance")
            or current_data.get("nextHopVpnTunnel")
            or current_data.get("nextHopIlb")
            or "unspecified"
        )
        next_hop_short = str(next_hop).rsplit("/", 1)[-1] if "/" in str(next_hop) else str(next_hop)
        if dest_range in ("0.0.0.0/0", "::/0"):
            highlights.append(
                f":rotating_light: *Default Internet / Catch-All Route (`{escape_mrkdwn(dest_range)}`) Configured*: Route directs `{escape_mrkdwn(dest_range)}` traffic via `{escape_mrkdwn(next_hop_short)}`."
            )
            recommendations.append(
                "Verify this default route does not bypass Cloud NGFW, Secure Web Proxy, or VPC Service Controls egress inspection."
            )
        elif action == "CREATED" or prior_data.get("destRange") != dest_range:
            highlights.append(
                f":warning: *VPC Custom Route {action.title()}*: Route for `{escape_mrkdwn(dest_range or 'n/a')}` via `{escape_mrkdwn(next_hop_short)}` was {action.lower()}."
            )

    if asset_type == "compute.googleapis.com/Router" and action != "DELETED":
        if (current_data.get("nats") or []) != (prior_data.get("nats") or []):
            highlights.append(
                ":warning: *Cloud Router NAT Configuration Modified*: Cloud NAT gateway rules or logging settings were updated on this router."
            )
        if (current_data.get("bgpPeers") or []) != (prior_data.get("bgpPeers") or []):
            highlights.append(
                ":warning: *Cloud Router BGP Peers Modified*: Dynamic BGP peering sessions were updated on this Cloud Router."
            )

    if asset_type in ("compute.googleapis.com/VpnTunnel", "compute.googleapis.com/InterconnectAttachment"):
        peer_ip = current_data.get("peerIp") or prior_data.get("peerIp")
        peer_suffix = f" (`peerIp={escape_mrkdwn(str(peer_ip))}`)" if peer_ip else ""
        highlights.append(
            f":rotating_light: *Hybrid Network Connectivity {action.title()}*: `{escape_mrkdwn(asset_type)}` was {action.lower()}{peer_suffix}."
        )
        recommendations.append(
            "Confirm that hybrid VPN or Interconnect changes are authorized and that ingress/egress routes are restricted by firewall policies."
        )

    # 5. Secret Manager & Cloud KMS Crown Jewels
    if "secretmanager.googleapis.com" in asset_type or "cloudkms.googleapis.com" in asset_type:
        highlights.append(
            f":lock: *Crown Jewel Secret / Crypto Asset {action.title()}*: Sensitive cryptographic or secret resource was {action.lower()}."
        )
        if not recommendations:
            recommendations.append(
                "Confirm the secret or key change aligns with your change-management ticket and verify IAM accessor bindings follow least privilege."
            )

    # 6. Database & Data Sources: Cloud SQL & BigQuery configuration changes
    if "sqladmin.googleapis.com/Instance" in asset_type and action != "DELETED":
        ip_cfg = (current_data.get("settings") or {}).get("ipConfiguration") or {}
        prior_ip_cfg = (prior_data.get("settings") or {}).get("ipConfiguration") or {}

        # Check SSL enforcement disabled or sslMode downgraded
        curr_ssl = ip_cfg.get("requireSsl")
        prior_ssl = prior_ip_cfg.get("requireSsl")
        curr_ssl_mode = ip_cfg.get("sslMode")
        prior_ssl_mode = prior_ip_cfg.get("sslMode")
        if (
            curr_ssl is False
            or (prior_ssl is True and curr_ssl is not True)
            or curr_ssl_mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
        ):
            ssl_detail = (
                f"`sslMode: {prior_ssl_mode or 'ENCRYPTED_ONLY'} -> {curr_ssl_mode}`"
                if curr_ssl_mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
                else "`requireSsl: false`"
            )
            highlights.append(
                f":rotating_light: *Database SSL Enforcement Disabled*: Unencrypted connections are permitted on this Cloud SQL instance ({ssl_detail})."
            )
            recommendations.append(
                "Re-enable SSL enforcement (`requireSsl = true` and `sslMode = ENCRYPTED_ONLY` or `TRUSTED_CLIENT_CERTIFICATE_REQUIRED`) on the Cloud SQL instance."
            )

        # Check expanded network access IP ranges (authorizedNetworks) & public IPv4
        auth_nets = ip_cfg.get("authorizedNetworks") or []
        prior_auth_nets = prior_ip_cfg.get("authorizedNetworks") or []
        curr_cidrs = {
            n.get("value"): n.get("name") or "unnamed"
            for n in auth_nets if isinstance(n, dict) and n.get("value")
        }
        prior_cidrs = {
            n.get("value"): n.get("name") or "unnamed"
            for n in prior_auth_nets if isinstance(n, dict) and n.get("value")
        }
        added_cidrs = [
            f"{cidr} ({curr_cidrs[cidr]})" if curr_cidrs[cidr] != "unnamed" else cidr
            for cidr in sorted(set(curr_cidrs.keys()) - set(prior_cidrs.keys()))
        ]

        if "0.0.0.0/0" in curr_cidrs or "::/0" in curr_cidrs:
            highlights.append(
                ":rotating_light: *Database Open to Public Internet (`0.0.0.0/0`)*: Cloud SQL `authorizedNetworks` allows connections from any IP address."
            )
            recommendations.append(
                "Remove `0.0.0.0/0` from Cloud SQL `authorizedNetworks`, disable public IP (`ipv4Enabled = false`), and connect via Private Services Access or Cloud SQL Auth Proxy."
            )
        elif added_cidrs:
            highlights.append(
                f":warning: *Database Network Access IP Range Expanded*: Added authorized network CIDR(s) `{escape_mrkdwn(', '.join(added_cidrs))}` to Cloud SQL instance."
            )
            if not recommendations:
                recommendations.append(
                    "Verify that the newly added `authorizedNetworks` CIDR range belongs to an approved corporate or partner network, or migrate to Private IP with Cloud SQL Auth Proxy."
                )

        if ip_cfg.get("ipv4Enabled") is True and prior_ip_cfg.get("ipv4Enabled") is False:
            highlights.append(
                ":warning: *Database Public IPv4 Enabled*: `ipv4Enabled` was enabled on this Cloud SQL instance."
            )

    if "bigquery.googleapis.com" in asset_type and action != "DELETED":
        access_entries = current_data.get("access") or []
        prior_access = prior_data.get("access") or []
        if any(
            isinstance(a, dict)
            and (a.get("iamMember") in ("allUsers", "allAuthenticatedUsers") or a.get("specialGroup") in ("allUsers", "allAuthenticatedUsers"))
            for a in access_entries
        ):
            highlights.append(
                ":rotating_light: *BigQuery Dataset Publicly Accessible*: Dataset `access` ACL grants access to `allUsers` or `allAuthenticatedUsers`!"
            )
            recommendations.append(
                "Immediately remove `allUsers` / `allAuthenticatedUsers` from the BigQuery dataset access list."
            )
        else:
            added_access = [a for a in access_entries if isinstance(a, dict) and a not in prior_access]
            if prior_access and added_access:
                highlights.append(
                    f":warning: *BigQuery Dataset Access Expanded*: Added `{len(added_access)}` new access binding(s) to BigQuery dataset ACL."
                )

    # 7. Custom IAM Role permission expansion, Service Account Key creation & Workload Identity Federation
    if asset_type == "iam.googleapis.com/Role" and action != "DELETED":
        curr_perms = set(current_data.get("includedPermissions") or [])
        prior_perms = set(prior_data.get("includedPermissions") or [])
        added_perms = sorted(curr_perms - prior_perms)
        if added_perms:
            preview = ", ".join(added_perms[:6]) + (f" (+{len(added_perms) - 6} more)" if len(added_perms) > 6 else "")
            highlights.append(
                f":key: *IAM Custom Role Permissions Expanded*: Added `{len(added_perms)}` permission(s) (`{escape_mrkdwn(preview)}`) to custom role."
            )
            risky_added = sorted(set(added_perms) & HIGH_RISK_IAM_PERMISSIONS)
            if risky_added:
                highlights.append(
                    f":rotating_light: *High-Risk Privilege Escalation Permission(s) Added*: Custom role granted `{escape_mrkdwn(', '.join(risky_added))}`."
                )
            recommendations.append(
                "Review the newly added permissions on this custom IAM role to ensure they do not introduce privilege escalation paths (such as `iam.serviceAccounts.getAccessToken` or `iam.roles.update`)."
            )

    if asset_type == "iam.googleapis.com/ServiceAccountKey" and action == "CREATED":
        asset_full_name = asset.get("name") or ""
        sa_email = (
            asset_full_name.split("/serviceAccounts/", 1)[1].split("/", 1)[0]
            if "/serviceAccounts/" in asset_full_name
            else ""
        )
        sa_label = f" (`{escape_mrkdwn(sa_email)}`)" if sa_email else ""
        highlights.append(
            f":key: *User-Managed Service Account Key Created*: A new persistent key was created for a Service Account{sa_label}."
        )
        recommendations.append(
            "Prefer Workload Identity Federation or short-lived service account impersonation tokens over long-lived exported Service Account keys."
        )

    if "WorkloadIdentityPool" in asset_type and action != "DELETED":
        issuer_uri = (
            (current_data.get("oidc") or {}).get("issuerUri")
            or (current_data.get("aws") or {}).get("accountId")
            or ""
        )
        issuer_label = f" (`issuer={escape_mrkdwn(str(issuer_uri))}`)" if issuer_uri else ""
        highlights.append(
            f":key: *Workload Identity Federation Trust {action.title()}*: `{escape_mrkdwn(asset_type)}` configuration was {action.lower()}{issuer_label}."
        )
        if "WorkloadIdentityPoolProvider" in asset_type:
            attr_cond = (current_data.get("attributeCondition") or "").strip()
            prior_cond = (prior_data.get("attributeCondition") or "").strip()
            if not attr_cond or (prior_cond and attr_cond != prior_cond):
                highlights.append(
                    f":rotating_light: *Workload Identity Provider Attribute Condition Modified or Missing*: `attributeCondition` is `{escape_mrkdwn(attr_cond or 'NONE (unrestricted)')}`."
                )
                recommendations.append(
                    "Enforce a strict `attributeCondition` on Workload Identity Pool Providers (for example restricting `attribute.repository` or `assertion.sub`) to prevent unauthorized external identities from federating."
                )

    # 7b. Organization Policy Constraints (v2 orgpolicy.googleapis.com/* and v1 CAI asset.orgPolicy)
    if asset_type == "orgpolicy.googleapis.com/Policy":
        constraint_name = (
            current_data.get("name")
            or prior_data.get("name")
            or asset.get("name")
            or "policy"
        ).rsplit("/", 1)[-1]
        spec = current_data.get("spec") or {}
        prior_spec = prior_data.get("spec") or {}
        rules = spec.get("rules") or []
        prior_rules = prior_spec.get("rules") or []

        enforced_disabled = any(isinstance(r, dict) and r.get("enforce") is False for r in rules)
        was_enforced = any(isinstance(r, dict) and r.get("enforce") is True for r in prior_rules)
        is_reset = spec.get("reset") is True

        if action == "DELETED" or enforced_disabled or is_reset:
            detail = (
                "reset=true"
                if is_reset
                else ("policy deleted" if action == "DELETED" else ("enforce: true -> false" if was_enforced else "enforce=false"))
            )
            highlights.append(
                f":rotating_light: *Organization Policy Constraint Enforcement Disabled*: Constraint `{escape_mrkdwn(constraint_name)}` was weakened (`{detail}`)."
            )
            recommendations.append(
                "Verify whether relaxing or overriding this Organization Policy constraint was approved by Security Governance, and restore enforcement (`enforce = true` / `inheritFromParent = true`) to prevent security posture drift."
            )

        if any(isinstance(r, dict) and r.get("allowAll") is True for r in rules):
            highlights.append(
                f":rotating_light: *Organization Policy Constraint Set to Allow All*: Constraint `{escape_mrkdwn(constraint_name)}` now allows all values (`allowAll=true`)."
            )
            if not recommendations:
                recommendations.append(
                    "Replace `allowAll = true` on this Organization Policy constraint with an explicit allowlist of approved values (`values.allowedValues`)."
                )

        curr_allowed_vals = [
            str(v)
            for r in rules if isinstance(r, dict)
            for v in ((r.get("values") or {}).get("allowedValues") or [])
        ]
        prior_allowed_vals = [
            str(v)
            for r in prior_rules if isinstance(r, dict)
            for v in ((r.get("values") or {}).get("allowedValues") or [])
        ]
        added_allowed_vals = sorted(set(curr_allowed_vals) - set(prior_allowed_vals))
        if added_allowed_vals:
            highlights.append(
                f":warning: *Organization Policy Allowed Values Expanded*: Constraint `{escape_mrkdwn(constraint_name)}` added allowed value(s) `{escape_mrkdwn(', '.join(added_allowed_vals))}`."
            )
            if not recommendations:
                recommendations.append(
                    "Verify that the newly permitted values in this Organization Policy constraint (such as external domains or VM instances) are authorized."
                )

        if prior_spec.get("inheritFromParent") is True and spec.get("inheritFromParent") is False:
            highlights.append(
                f":warning: *Organization Policy Parent Inheritance Overridden*: Constraint `{escape_mrkdwn(constraint_name)}` disabled `inheritFromParent` (`true -> false`)."
            )

    if asset_type == "orgpolicy.googleapis.com/CustomConstraint":
        cc_name = (current_data.get("name") or prior_data.get("name") or asset.get("name") or "customConstraint").rsplit("/", 1)[-1]
        act_type = current_data.get("actionType") or prior_data.get("actionType") or "n/a"
        highlights.append(
            f":shield: *Organization Policy Custom Constraint {action.title()}*: Custom constraint `{escape_mrkdwn(cc_name)}` (`actionType={escape_mrkdwn(str(act_type))}`) was {action.lower()}."
        )

    current_org_pol = asset.get("orgPolicy") or []
    prior_org_pol = ((notification.get("priorAsset") or {}).get("orgPolicy")) or []
    if current_org_pol or prior_org_pol:
        prior_pol_map = {
            p.get("constraint"): p
            for p in prior_org_pol if isinstance(p, dict) and p.get("constraint")
        }
        for pol in current_org_pol:
            if not isinstance(pol, dict) or not pol.get("constraint"):
                continue
            c_name = str(pol["constraint"]).replace("constraints/", "")
            prior_pol = prior_pol_map.get(pol["constraint"]) or {}
            bool_pol = pol.get("booleanPolicy") or {}
            prior_bool_pol = prior_pol.get("booleanPolicy") or {}
            list_pol = pol.get("listPolicy") or {}
            prior_list_pol = prior_pol.get("listPolicy") or {}

            if (bool_pol and not bool_pol.get("enforced") and prior_bool_pol.get("enforced") is True) or pol.get("restoreDefault"):
                highlights.append(
                    f":rotating_light: *Organization Policy Constraint Enforcement Disabled*: Constraint `{escape_mrkdwn(c_name)}` enforcement was disabled."
                )
            if list_pol.get("allValues") == "ALLOW" and prior_list_pol.get("allValues") != "ALLOW":
                highlights.append(
                    f":rotating_light: *Organization Policy Constraint Set to Allow All*: Constraint `{escape_mrkdwn(c_name)}` now allows all values (`allValues=ALLOW`)."
                )
            added_v1_vals = sorted(set(list_pol.get("allowedValues") or []) - set(prior_list_pol.get("allowedValues") or []))
            if added_v1_vals:
                highlights.append(
                    f":warning: *Organization Policy Allowed Values Expanded*: Constraint `{escape_mrkdwn(c_name)}` added allowed value(s) `{escape_mrkdwn(', '.join(added_v1_vals))}`."
                )

    # 8. Kubernetes (GKE) & Fleet Service Mesh Posture
    curr_data = current_data
    if asset_type in ("container.googleapis.com/Cluster", "container.googleapis.com/NodePool"):
        # Confidential GKE Nodes (Cluster or NodePool level)
        curr_conf = (
            (curr_data.get("confidentialNodes") or {}).get("enabled")
            if "confidentialNodes" in curr_data
            else ((curr_data.get("config") or curr_data.get("nodeConfig") or {}).get("confidentialNodes") or {}).get("enabled")
        )
        prior_conf = (
            (prior_data.get("confidentialNodes") or {}).get("enabled")
            if "confidentialNodes" in prior_data
            else ((prior_data.get("config") or prior_data.get("nodeConfig") or {}).get("confidentialNodes") or {}).get("enabled")
        )
        if prior_conf is True and curr_conf is False:
            highlights.append(
                ":rotating_light: *Confidential GKE Nodes Disabled*: Hardware-enforced memory encryption (`confidentialNodes.enabled`) was turned OFF!"
            )
            recommendations.append(
                "Enable Confidential GKE Nodes (`confidentialNodes.enabled=true`) to encrypt workload memory in use."
            )
        elif curr_conf is False and ("confidentialNodes" in curr_data or "confidentialNodes" in (curr_data.get("config") or curr_data.get("nodeConfig") or {})):
            highlights.append(
                ":warning: *Confidential GKE Nodes Not Enabled*: `confidentialNodes.enabled` is set to `false`."
            )

        # Boot Disk Encryption (Cloud KMS key vs Google-managed encryption key)
        curr_node_cfg = curr_data.get("config") or curr_data.get("nodeConfig") or {}
        prior_node_cfg = prior_data.get("config") or prior_data.get("nodeConfig") or {}
        curr_boot_kms = curr_node_cfg.get("bootDiskKmsKey") or ""
        prior_boot_kms = prior_node_cfg.get("bootDiskKmsKey") or ""
        if prior_boot_kms and not curr_boot_kms:
            highlights.append(
                f":rotating_light: *GKE Boot Disk Cloud KMS Key Removed*: Node boot disk encryption reverted from Cloud KMS (`{escape_mrkdwn(prior_boot_kms.rsplit('/', 1)[-1])}`) to a Google-managed encryption key!"
            )
            recommendations.append(
                "Configure a customer-managed Cloud KMS key (`bootDiskKmsKey`) for GKE node boot disks."
            )
        elif prior_boot_kms and curr_boot_kms and prior_boot_kms != curr_boot_kms:
            highlights.append(
                f":key: *GKE Boot Disk Cloud KMS Key Changed*: `bootDiskKmsKey` changed from `{escape_mrkdwn(prior_boot_kms.rsplit('/', 1)[-1])}` to `{escape_mrkdwn(curr_boot_kms.rsplit('/', 1)[-1])}`."
            )

        # Node Service Account & OAuth Access Scopes
        curr_node_sa = curr_node_cfg.get("serviceAccount") or ""
        prior_node_sa = prior_node_cfg.get("serviceAccount") or ""
        if curr_node_sa == "default" and prior_node_sa != "default":
            highlights.append(
                ":warning: *GKE Default Compute Service Account Used*: Nodes are configured with the `default` Compute Engine service account."
            )
            recommendations.append(
                "Assign a dedicated, least-privilege IAM service account (`nodeConfig.serviceAccount`) to GKE nodes instead of `default`."
            )
        elif prior_node_sa and curr_node_sa and prior_node_sa != curr_node_sa:
            highlights.append(
                f":key: *GKE Node Service Account Changed*: Node service account changed from `{escape_mrkdwn(prior_node_sa)}` to `{escape_mrkdwn(curr_node_sa)}`."
            )

        curr_scopes = set(curr_node_cfg.get("oauthScopes") or [])
        prior_scopes = set(prior_node_cfg.get("oauthScopes") or [])
        if "https://www.googleapis.com/auth/cloud-platform" in curr_scopes and (
            "https://www.googleapis.com/auth/cloud-platform" not in prior_scopes or curr_node_sa == "default"
        ):
            highlights.append(
                ":warning: *Broad GKE Node Access Scope*: Node config grants full `cloud-platform` OAuth access scope."
            )

        # Node-level Shielded Instance Config (Secure Boot & Integrity Monitoring)
        curr_shielded_cfg = curr_node_cfg.get("shieldedInstanceConfig") or {}
        prior_shielded_cfg = prior_node_cfg.get("shieldedInstanceConfig") or {}
        if curr_shielded_cfg:
            if curr_shielded_cfg.get("enableSecureBoot") is False and prior_shielded_cfg.get("enableSecureBoot") is not False:
                highlights.append(
                    ":warning: *GKE Node Secure Boot Disabled*: `shieldedInstanceConfig.enableSecureBoot` is `false`."
                )
            if curr_shielded_cfg.get("enableIntegrityMonitoring") is False and prior_shielded_cfg.get("enableIntegrityMonitoring") is not False:
                highlights.append(
                    ":warning: *GKE Node Integrity Monitoring Disabled*: `shieldedInstanceConfig.enableIntegrityMonitoring` is `false`."
                )

    if asset_type == "container.googleapis.com/Cluster" and curr_data:
        # Application-layer Secret Encryption (Cloud KMS key vs Google-managed key)
        curr_db_enc = curr_data.get("databaseEncryption") or {}
        prior_db_enc = prior_data.get("databaseEncryption") or {}
        curr_db_state = curr_db_enc.get("state") or ""
        prior_db_state = prior_db_enc.get("state") or ""
        curr_db_key = curr_db_enc.get("keyName") or ""
        prior_db_key = prior_db_enc.get("keyName") or ""
        if prior_db_state == "ENCRYPTED" and curr_db_state == "DECRYPTED":
            highlights.append(
                f":rotating_light: *GKE Application-Layer Secret Encryption Disabled*: Cluster `databaseEncryption` downgraded from Cloud KMS (`{escape_mrkdwn(prior_db_key.rsplit('/', 1)[-1] or 'CMEK')}`) to `DECRYPTED` (Google-managed encryption key)!"
            )
            recommendations.append(
                "Re-enable GKE application-layer secret encryption (`databaseEncryption.state=ENCRYPTED`) with a Cloud KMS key to protect Kubernetes Secrets in etcd."
            )
        elif curr_db_state == "DECRYPTED" and prior_db_state != "DECRYPTED":
            highlights.append(
                ":warning: *GKE Application-Layer Secrets Using Google-Managed Key*: `databaseEncryption.state` is `DECRYPTED` (no Cloud KMS CMEK configured for etcd secrets)."
            )
        elif prior_db_key and curr_db_key and prior_db_key != curr_db_key:
            highlights.append(
                f":key: *GKE Application-Layer Cloud KMS Key Changed*: `databaseEncryption.keyName` changed from `{escape_mrkdwn(prior_db_key.rsplit('/', 1)[-1])}` to `{escape_mrkdwn(curr_db_key.rsplit('/', 1)[-1])}`."
            )

        # Security Posture, Misconfiguration Checks & Vulnerability Scanning
        curr_posture = curr_data.get("securityPostureConfig") or {}
        prior_posture = prior_data.get("securityPostureConfig") or {}
        if curr_posture.get("mode") in ("DISABLED", "MODE_UNSPECIFIED") and prior_posture.get("mode") not in (None, "DISABLED", "MODE_UNSPECIFIED"):
            highlights.append(
                f":rotating_light: *GKE Security Posture Disabled*: Cluster misconfiguration auditing (`securityPostureConfig.mode`) changed from `{escape_mrkdwn(prior_posture.get('mode'))}` to `{escape_mrkdwn(curr_posture.get('mode'))}`!"
            )
            recommendations.append(
                "Enable GKE Security Posture (`securityPostureConfig.mode=BASIC` or `ENTERPRISE`) and workload vulnerability scanning to continuously detect misconfigurations and CVEs."
            )
        if curr_posture.get("vulnerabilityMode") in ("VULNERABILITY_DISABLED", "VULNERABILITY_MODE_UNSPECIFIED") and prior_posture.get("vulnerabilityMode") not in (None, "VULNERABILITY_DISABLED", "VULNERABILITY_MODE_UNSPECIFIED"):
            highlights.append(
                f":warning: *GKE Workload Vulnerability Scanning Disabled*: `securityPostureConfig.vulnerabilityMode` changed from `{escape_mrkdwn(prior_posture.get('vulnerabilityMode'))}` to `{escape_mrkdwn(curr_posture.get('vulnerabilityMode'))}`."
            )

        # Security Bulletins & Upgrade Notifications
        curr_notif = (curr_data.get("notificationConfig") or {}).get("pubsub") or {}
        prior_notif = (prior_data.get("notificationConfig") or {}).get("pubsub") or {}
        if prior_notif.get("enabled") is True and curr_notif.get("enabled") is False:
            highlights.append(
                ":warning: *GKE Security Bulletin Notifications Disabled*: `notificationConfig.pubsub.enabled` was turned OFF (security bulletins and upgrade alerts will no longer be published)."
            )

        # Cluster Networking: Private Cluster, Authorized Networks, Network Policy
        curr_priv = curr_data.get("privateClusterConfig") or {}
        prior_priv = prior_data.get("privateClusterConfig") or {}
        if prior_priv.get("enablePrivateNodes") is True and curr_priv.get("enablePrivateNodes") is False:
            highlights.append(
                ":rotating_light: *GKE Private Nodes Disabled*: `privateClusterConfig.enablePrivateNodes` changed to `false` (worker nodes exposed with external IPs)!"
            )
            recommendations.append(
                "Enable private nodes (`enablePrivateNodes=true`) and restrict control plane access via Authorized Networks or Private Endpoint."
            )
        if prior_priv.get("enablePrivateEndpoint") is True and curr_priv.get("enablePrivateEndpoint") is False:
            highlights.append(
                ":warning: *GKE Public Control Plane Endpoint Enabled*: `privateClusterConfig.enablePrivateEndpoint` changed from `true` to `false`."
            )

        curr_auth_net = curr_data.get("masterAuthorizedNetworksConfig") or {}
        prior_auth_net = prior_data.get("masterAuthorizedNetworksConfig") or {}
        if prior_auth_net.get("enabled") is True and curr_auth_net.get("enabled") is False:
            highlights.append(
                ":rotating_light: *GKE Control Plane Authorized Networks Disabled*: `masterAuthorizedNetworksConfig.enabled` was turned OFF!"
            )
            recommendations.append(
                "Keep `masterAuthorizedNetworksConfig.enabled=true` and restrict `cidrBlocks` to trusted corporate/bastion IP ranges."
            )
        curr_auth_cidrs = {
            b.get("cidrBlock")
            for b in (curr_auth_net.get("cidrBlocks") or [])
            if isinstance(b, dict) and b.get("cidrBlock")
        }
        if ("0.0.0.0/0" in curr_auth_cidrs or "::/0" in curr_auth_cidrs) and curr_auth_net.get("enabled") is not False:
            highlights.append(
                ":rotating_light: *GKE Control Plane Open to the Internet*: `masterAuthorizedNetworksConfig.cidrBlocks` allows `0.0.0.0/0`!"
            )
            recommendations.append(
                "Remove `0.0.0.0/0` from `masterAuthorizedNetworksConfig.cidrBlocks` and restrict Kubernetes API access to specific management subnets."
            )

        curr_net_pol = (curr_data.get("networkPolicy") or {}).get("enabled")
        prior_net_pol = (prior_data.get("networkPolicy") or {}).get("enabled")
        datapath = (curr_data.get("networkConfig") or {}).get("datapathProvider")
        if prior_net_pol is True and curr_net_pol is False and datapath != "ADVANCED_DATAPATH":
            highlights.append(
                ":warning: *GKE Network Policy Disabled*: Pod-to-Pod network policy enforcement (`networkPolicy.enabled`) was turned OFF."
            )

        # Service Mesh Certificates on Cluster
        curr_mesh = (curr_data.get("meshCertificates") or {}).get("enableCertificates")
        prior_mesh = (prior_data.get("meshCertificates") or {}).get("enableCertificates")
        if prior_mesh is True and curr_mesh is False:
            highlights.append(
                ":warning: *GKE Service Mesh Certificates Disabled*: `meshCertificates.enableCertificates` was turned OFF."
            )

        # Binary Authorization on GKE
        curr_binauth = curr_data.get("binaryAuthorization") or {}
        prior_binauth = prior_data.get("binaryAuthorization") or {}
        prior_ba_enforced = prior_binauth.get("enabled") is True or (
            prior_binauth.get("evaluationMode") or ""
        ).startswith("PROJECT_SINGLETON_POLICY")
        curr_ba_disabled = curr_binauth.get("enabled") is False or curr_binauth.get("evaluationMode") == "DISABLED"
        if prior_ba_enforced and curr_ba_disabled:
            highlights.append(
                ":rotating_light: *GKE Binary Authorization Disabled*: Container image signature verification (`binaryAuthorization`) was turned OFF!"
            )
            recommendations.append(
                "Set `binaryAuthorization.evaluationMode` to `PROJECT_SINGLETON_POLICY_ENFORCE` to block unsigned container images."
            )

        # Client Certificate (Master Auth)
        curr_client_cert = ((curr_data.get("masterAuth") or {}).get("clientCertificateConfig") or {}).get("issueClientCertificate")
        prior_client_cert = ((prior_data.get("masterAuth") or {}).get("clientCertificateConfig") or {}).get("issueClientCertificate")
        if curr_client_cert is True and prior_client_cert is not True:
            highlights.append(
                ":rotating_light: *GKE Legacy Client Certificate Issued*: `masterAuth.clientCertificateConfig.issueClientCertificate` is `true` (static client certificates cannot be revoked without cluster credential rotation)!"
            )

        # Google Groups for RBAC
        curr_groups = (curr_data.get("authenticatorGroupsConfig") or {}).get("enabled")
        prior_groups = (prior_data.get("authenticatorGroupsConfig") or {}).get("enabled")
        if prior_groups is True and curr_groups is False:
            highlights.append(
                ":warning: *GKE Google Groups for RBAC Disabled*: `authenticatorGroupsConfig.enabled` was turned OFF."
            )

        # Legacy Authorization (ABAC)
        curr_abac = (curr_data.get("legacyAbac") or {}).get("enabled")
        prior_abac = (prior_data.get("legacyAbac") or {}).get("enabled")
        if curr_abac is True and prior_abac is not True:
            highlights.append(
                ":rotating_light: *GKE Legacy ABAC Authorization Enabled*: `legacyAbac.enabled` is `true`, bypassing Kubernetes RBAC and IAM controls!"
            )
            recommendations.append(
                "Disable Legacy ABAC (`legacyAbac.enabled=false`) immediately and use Kubernetes RBAC with IAM / Google Groups for RBAC."
            )

        # Secret Manager CSI Add-on
        curr_sm_addon = (curr_data.get("secretManagerConfig") or {}).get("enabled")
        prior_sm_addon = (prior_data.get("secretManagerConfig") or {}).get("enabled")
        if prior_sm_addon is True and curr_sm_addon is False:
            highlights.append(
                ":warning: *GKE Secret Manager Add-on Disabled*: `secretManagerConfig.enabled` was turned OFF."
            )

        # Shielded GKE Nodes
        curr_shielded = (curr_data.get("shieldedNodes") or {}).get("enabled")
        prior_shielded = (prior_data.get("shieldedNodes") or {}).get("enabled")
        if prior_shielded is True and curr_shielded is False:
            highlights.append(
                ":rotating_light: *GKE Shielded Nodes Disabled*: `shieldedNodes.enabled` was turned OFF (cluster nodes can no longer cryptographically verify node identity)!"
            )
            recommendations.append(
                "Enable Shielded GKE Nodes (`shieldedNodes.enabled=true`) and Secure Boot on all node pools."
            )

        # Workload Identity
        curr_wi_pool = (curr_data.get("workloadIdentityConfig") or {}).get("workloadPool") or ""
        prior_wi_pool = (prior_data.get("workloadIdentityConfig") or {}).get("workloadPool") or ""
        if prior_wi_pool and not curr_wi_pool:
            highlights.append(
                f":rotating_light: *GKE Workload Identity Disabled*: `workloadIdentityConfig.workloadPool` (`{escape_mrkdwn(prior_wi_pool)}`) was removed!"
            )
            recommendations.append(
                "Keep Workload Identity enabled (`workloadIdentityConfig.workloadPool`) so Kubernetes workloads authenticate to GCP APIs without static service account keys."
            )

    if asset_type in ("gkehub.googleapis.com/Feature", "gkehub.googleapis.com/Membership") and curr_data:
        short_feat = (asset.get("name") or "").rsplit("/", 1)[-1]
        highlights.append(
            f":gear: *GKE Fleet / Service Mesh Configuration {escape_mrkdwn(action)}*: `{escape_mrkdwn(short_feat)}`."
        )

    # 9. Cloud Run & Binary Authorization Posture
    if asset_type in ("run.googleapis.com/Service", "run.googleapis.com/Job") and curr_data:
        curr_annotations = (curr_data.get("metadata") or {}).get("annotations") or {}
        prior_annotations = (prior_data.get("metadata") or {}).get("annotations") or {}
        curr_tmpl = curr_data.get("template") or {}
        prior_tmpl = prior_data.get("template") or {}
        curr_tmpl_ann = (curr_tmpl.get("metadata") or {}).get("annotations") or curr_tmpl.get("annotations") or {}
        prior_tmpl_ann = (prior_tmpl.get("metadata") or {}).get("annotations") or prior_tmpl.get("annotations") or {}

        # Authentication: invokerIamDisabled
        curr_iam_disabled = curr_data.get("invokerIamDisabled") is True or curr_annotations.get("run.googleapis.com/invoker-iam-disabled") == "true"
        prior_iam_disabled = prior_data.get("invokerIamDisabled") is True or prior_annotations.get("run.googleapis.com/invoker-iam-disabled") == "true"
        if curr_iam_disabled and not prior_iam_disabled:
            highlights.append(
                ":rotating_light: *Cloud Run Unauthenticated Access Enabled*: IAM authentication check (`invokerIamDisabled=true`) was disabled on this Cloud Run service!"
            )
            recommendations.append(
                "Require IAM authentication (`invokerIamDisabled=false`) and restrict `roles/run.invoker` to authorized principals."
            )

        # Network Exposure: Ingress & VPC Egress
        curr_ingress = curr_data.get("ingress") or curr_annotations.get("run.googleapis.com/ingress") or ""
        prior_ingress = prior_data.get("ingress") or prior_annotations.get("run.googleapis.com/ingress") or ""
        if curr_ingress in ("INGRESS_TRAFFIC_ALL", "all") and prior_ingress not in ("", "INGRESS_TRAFFIC_ALL", "all"):
            highlights.append(
                f":rotating_light: *Cloud Run Ingress Exposed to Public Internet*: Ingress widened from `{escape_mrkdwn(prior_ingress)}` to `{escape_mrkdwn(curr_ingress)}`!"
            )
            recommendations.append(
                "Restrict Cloud Run ingress to `INGRESS_TRAFFIC_INTERNAL_ONLY` or `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER` unless direct public access is required."
            )

        curr_egress = (curr_tmpl.get("vpcAccess") or {}).get("egress") or curr_tmpl_ann.get("run.googleapis.com/vpc-access-egress") or ""
        prior_egress = (prior_tmpl.get("vpcAccess") or {}).get("egress") or prior_tmpl_ann.get("run.googleapis.com/vpc-access-egress") or ""
        if prior_egress in ("ALL_TRAFFIC", "all-traffic") and curr_egress and curr_egress not in ("ALL_TRAFFIC", "all-traffic"):
            highlights.append(
                f":warning: *Cloud Run VPC Egress Weakened*: Outbound VPC routing (`vpcAccess.egress`) changed from `{escape_mrkdwn(prior_egress)}` to `{escape_mrkdwn(curr_egress)}` (internet traffic bypasses VPC firewall/NAT)."
            )

        # Encryption (Cloud KMS CMEK vs Google-managed key)
        curr_kms = curr_tmpl.get("encryptionKey") or curr_data.get("encryptionKey") or curr_tmpl_ann.get("run.googleapis.com/encryption-key") or ""
        prior_kms = prior_tmpl.get("encryptionKey") or prior_data.get("encryptionKey") or prior_tmpl_ann.get("run.googleapis.com/encryption-key") or ""
        if prior_kms and not curr_kms:
            highlights.append(
                f":rotating_light: *Cloud Run Cloud KMS Key (CMEK) Removed*: Encryption reverted from Cloud KMS (`{escape_mrkdwn(prior_kms.rsplit('/', 1)[-1])}`) to Google-managed encryption key!"
            )
            recommendations.append(
                "Restore the customer-managed Cloud KMS encryption key (`template.encryptionKey`) on the Cloud Run revision template."
            )
        elif prior_kms and curr_kms and prior_kms != curr_kms:
            highlights.append(
                f":key: *Cloud Run Cloud KMS Encryption Key Changed*: `encryptionKey` changed from `{escape_mrkdwn(prior_kms.rsplit('/', 1)[-1])}` to `{escape_mrkdwn(curr_kms.rsplit('/', 1)[-1])}`."
            )

        # Threat Detection status (Enabled or Disabled)
        curr_td = curr_data.get("threatDetectionEnabled")
        if curr_td is None and isinstance(curr_data.get("threatDetection"), dict):
            curr_td = curr_data["threatDetection"].get("enabled")
        if curr_td is None and "run.googleapis.com/threat-detection-enabled" in curr_annotations:
            curr_td = curr_annotations.get("run.googleapis.com/threat-detection-enabled") == "true"

        prior_td = prior_data.get("threatDetectionEnabled")
        if prior_td is None and isinstance(prior_data.get("threatDetection"), dict):
            prior_td = prior_data["threatDetection"].get("enabled")
        if prior_td is None and "run.googleapis.com/threat-detection-enabled" in prior_annotations:
            prior_td = prior_annotations.get("run.googleapis.com/threat-detection-enabled") == "true"

        if prior_td is True and curr_td is False:
            highlights.append(
                ":rotating_light: *Cloud Run Threat Detection Disabled*: Runtime threat detection was turned OFF!"
            )
            recommendations.append(
                "Re-enable Cloud Run Threat Detection (`threatDetectionEnabled=true`) to monitor for container drift and malicious execution."
            )
        elif prior_td is False and curr_td is True:
            highlights.append(
                ":white_check_mark: *Cloud Run Threat Detection Enabled*: Runtime threat detection was turned ON."
            )

        # Service Account changes
        curr_sa = curr_tmpl.get("serviceAccount") or ((curr_tmpl.get("spec") or {}).get("serviceAccountName")) or ""
        prior_sa = prior_tmpl.get("serviceAccount") or ((prior_tmpl.get("spec") or {}).get("serviceAccountName")) or ""
        if prior_sa != curr_sa and (prior_sa or curr_sa):
            highlights.append(
                f":key: *Cloud Run Service Account Changed*: Runtime identity changed from `{escape_mrkdwn(prior_sa or 'default')}` to `{escape_mrkdwn(curr_sa or 'default')}`."
            )
            if curr_sa.endswith("-compute@developer.gserviceaccount.com"):
                highlights.append(
                    f":warning: *Cloud Run Using Default Compute Service Account*: `{escape_mrkdwn(curr_sa)}` often carries broad project permissions."
                )
                recommendations.append(
                    "Assign a dedicated, least-privilege IAM service account (`template.serviceAccount`) to each Cloud Run workload."
                )

        # Binary Authorization status & Breakglass on Cloud Run
        curr_ba = curr_data.get("binaryAuthorization") or {}
        prior_ba = prior_data.get("binaryAuthorization") or {}
        prior_ba_on = bool(prior_ba.get("useDefault") or prior_ba.get("policy") or prior_annotations.get("run.googleapis.com/binary-authorization"))
        curr_ba_on = bool(curr_ba.get("useDefault") or curr_ba.get("policy") or curr_annotations.get("run.googleapis.com/binary-authorization"))
        if prior_ba_on and not curr_ba_on:
            highlights.append(
                ":rotating_light: *Cloud Run Binary Authorization Disabled*: Image attestation enforcement (`binaryAuthorization`) was removed from this service!"
            )
            recommendations.append(
                "Keep Binary Authorization (`binaryAuthorization.useDefault=true` or policy binding) enabled on Cloud Run services."
            )
        breakglass = curr_ba.get("breakglassJustification") or curr_annotations.get("run.googleapis.com/binary-authorization-breakglass") or ""
        prior_breakglass = prior_ba.get("breakglassJustification") or prior_annotations.get("run.googleapis.com/binary-authorization-breakglass") or ""
        if breakglass and breakglass != prior_breakglass:
            highlights.append(
                f":rotating_light: *Cloud Run Binary Authorization Breakglass Used*: Deployment bypassed image attestation with justification: `{escape_mrkdwn(breakglass)}`!"
            )
            recommendations.append(
                "Audit the breakglass deployment immediately and replace the unverified container image with a properly attested build."
            )

    if asset_type in ("binaryauthorization.googleapis.com/Policy", "binaryauthorization.googleapis.com/Attestor") and curr_data:
        default_rule = curr_data.get("defaultAdmissionRule") or {}
        prior_default_rule = prior_data.get("defaultAdmissionRule") or {}
        eval_mode = default_rule.get("evaluationMode") or ""
        prior_eval_mode = prior_default_rule.get("evaluationMode") or ""
        enf_mode = default_rule.get("enforcementMode") or ""
        prior_enf_mode = prior_default_rule.get("enforcementMode") or ""

        if eval_mode == "ALWAYS_ALLOW" and prior_eval_mode != "ALWAYS_ALLOW":
            highlights.append(
                ":rotating_light: *Binary Authorization Policy Set to ALWAYS_ALLOW*: `defaultAdmissionRule.evaluationMode` now allows any container image without cryptographic attestation!"
            )
            recommendations.append(
                "Set `defaultAdmissionRule.evaluationMode` to `REQUIRE_ATTESTATION` and `enforcementMode` to `ENFORCED_BLOCK_AND_AUDIT_LOG`."
            )
        if enf_mode == "DRYRUN_AUDIT_LOG_ONLY" and prior_enf_mode != "DRYRUN_AUDIT_LOG_ONLY":
            highlights.append(
                ":warning: *Binary Authorization Policy Weakened to Dry-Run*: `defaultAdmissionRule.enforcementMode` is `DRYRUN_AUDIT_LOG_ONLY` (unsigned images are logged but not blocked)."
            )
        if prior_data.get("globalPolicyEvaluationMode") == "ENABLE" and curr_data.get("globalPolicyEvaluationMode") == "DISABLE":
            highlights.append(
                ":warning: *Binary Authorization Global Policy Disabled*: `globalPolicyEvaluationMode` changed from `ENABLE` to `DISABLE`."
            )

    # 10. IAM Policy changes: monitor privilege escalation (more permissions for a user/SA) & added roles
    current_iam = (asset.get("iamPolicy") or {}).get("bindings") or []
    prior_iam = ((notification.get("priorAsset") or {}).get("iamPolicy") or {}).get("bindings") or []
    if current_iam or prior_iam:
        old_map = _normalize_bindings(prior_iam)
        new_map = _normalize_bindings(current_iam)
        old_principals = _normalize_principal_roles(prior_iam)
        new_principals = _normalize_principal_roles(current_iam)

        # Detect newly added roles on the policy
        newly_added_roles = sorted(set(new_map.keys()) - set(old_map.keys()))
        if newly_added_roles:
            highlights.append(
                f":key: *Added IAM Role(s)*: `{escape_mrkdwn(', '.join(newly_added_roles))}` added to policy."
            )

        # Detect per-principal privilege escalation (existing user or SA granted additional roles)
        for principal, current_roles in sorted(new_principals.items()):
            prior_roles = old_principals.get(principal, set())
            gained_roles = sorted(current_roles - prior_roles)
            if prior_roles and gained_roles:
                highlights.append(
                    f":rotating_light: *IAM Privilege Escalation*: `{escape_mrkdwn(principal)}` gained `{escape_mrkdwn(', '.join(gained_roles))}` (in addition to existing `{escape_mrkdwn(', '.join(sorted(prior_roles)))}`)."
                )

        for role, members in new_map.items():
            added_members = members - old_map.get(role, set())
            if not added_members:
                continue
            base_role = role.split(" [", 1)[0]
            if any(m in ("allUsers", "allAuthenticatedUsers") for m in added_members):
                highlights.append(
                    f":rotating_light: *Public IAM Access Granted*: `{escape_mrkdwn(role)}` granted to `{escape_mrkdwn(', '.join(sorted(added_members)))}`!"
                )
                recommendations.append(
                    "Immediately remove `allUsers` / `allAuthenticatedUsers` from the IAM policy unless the resource is intentionally public."
                )
            elif base_role in PRIVILEGED_ROLES:
                highlights.append(
                    f":key: *Privileged IAM Role Granted*: `{escape_mrkdwn(role)}` granted to `{escape_mrkdwn(', '.join(sorted(added_members)))}`."
                )
                if not recommendations:
                    recommendations.append(
                        "Verify that granting this privileged IAM role adheres to least privilege and uses time-bound IAM Conditions or PAM where possible."
                    )

    # 11. SCC Finding fallback
    if "finding" in notification and "asset" not in notification:
        finding = notification.get("finding") or {}
        props = finding.get("sourceProperties") or {}
        sev = finding.get("severity") or "HIGH"
        cat = finding.get("category") or "FINDING"
        highlights.append(f":rotating_light: *SCC {escape_mrkdwn(sev)} Finding*: `{escape_mrkdwn(cat)}`")
        rec = props.get("Recommendation") or finding.get("nextSteps")
        if rec:
            recommendations.append(str(rec))

    return highlights, recommendations


# --------------------------------------------------------------------------
# Formatting & Slack Block Kit Builder
# --------------------------------------------------------------------------

def escape_mrkdwn(text):
    """Escape the three characters Slack treats as control characters."""
    if text is None:
        return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def truncate(text, limit):
    if text is None:
        return None
    return text if len(text) <= limit else text[: limit - 1] + "…"


def console_url(notification, project_id):
    """Deep link to the asset or finding in the Google Cloud Console."""
    if "finding" in notification and "asset" not in notification:
        finding_name = (notification.get("finding") or {}).get("name") or ""
        parts = finding_name.split("/")
        if len(parts) >= 2 and parts[0] == "organizations":
            return f"{CONSOLE_FINDINGS_URL}?organizationId={parts[1]}"
        if project_id and project_id != "n/a":
            return f"{CONSOLE_FINDINGS_URL}?project={quote(project_id, safe='')}"
        return CONSOLE_FINDINGS_URL

    asset = notification.get("asset") or notification.get("priorAsset") or {}
    asset_type = asset.get("assetType") or ""
    asset_name = asset.get("name") or ""
    short_name = asset_name.rsplit("/", 1)[-1] if asset_name else ""
    location = extract_location(notification)

    if project_id and project_id != "n/a":
        p_enc = quote(project_id, safe="")
        if asset_type == "compute.googleapis.com/Firewall" and short_name:
            return f"https://console.cloud.google.com/net-security/firewall-manager/firewall-policies/details/{quote(short_name, safe='')}?project={p_enc}"
        if asset_type == "compute.googleapis.com/Instance" and short_name:
            return f"https://console.cloud.google.com/compute/instancesDetail/zones/{quote(location, safe='')}/instances/{quote(short_name, safe='')}?project={p_enc}"
        if asset_type == "compute.googleapis.com/Network" and short_name:
            return f"https://console.cloud.google.com/networking/networks/details/{quote(short_name, safe='')}?project={p_enc}"
        if asset_type == "compute.googleapis.com/Subnetwork" and short_name:
            return f"https://console.cloud.google.com/networking/subnetworks/details/{quote(location, safe='')}/{quote(short_name, safe='')}?project={p_enc}"
        if asset_type in ("compute.googleapis.com/Route", "compute.googleapis.com/Router", "compute.googleapis.com/VpnTunnel"):
            return f"https://console.cloud.google.com/networking/networks/list?project={p_enc}"
        if "container.googleapis.com/" in asset_type or "gkehub.googleapis.com/" in asset_type:
            return f"https://console.cloud.google.com/kubernetes/list/overview?project={p_enc}"
        if "run.googleapis.com/" in asset_type:
            return f"https://console.cloud.google.com/run?project={p_enc}"
        if "binaryauthorization.googleapis.com/" in asset_type:
            return f"https://console.cloud.google.com/security/binary-authorization?project={p_enc}"
        if asset_type == "secretmanager.googleapis.com/Secret" and short_name:
            return f"https://console.cloud.google.com/security/secret-manager/secret/{quote(short_name, safe='')}/versions?project={p_enc}"
        if asset_type == "sqladmin.googleapis.com/Instance" and short_name:
            return f"https://console.cloud.google.com/sql/instances/{quote(short_name, safe='')}/overview?project={p_enc}"
        if "bigquery.googleapis.com" in asset_type:
            return f"https://console.cloud.google.com/bigquery?project={p_enc}"
        if asset_type in ("iam.googleapis.com/ServiceAccount", "iam.googleapis.com/ServiceAccountKey"):
            return f"https://console.cloud.google.com/iam-admin/serviceaccounts?project={p_enc}"
        if asset_type == "iam.googleapis.com/Role":
            return f"https://console.cloud.google.com/iam-admin/roles?project={p_enc}"
        if "WorkloadIdentityPool" in asset_type:
            return f"https://console.cloud.google.com/iam-admin/workload-identity-pools?project={p_enc}"
        if "orgpolicy.googleapis.com" in asset_type or "orgPolicy" in asset:
            if project_id.startswith("organizations/"):
                org_id = quote(project_id.split("/", 1)[1], safe="")
                return f"https://console.cloud.google.com/iam-admin/orgpolicies/list?organizationId={org_id}"
            return f"https://console.cloud.google.com/iam-admin/orgpolicies/list?project={p_enc}"
        if "iamPolicy" in asset:
            return f"https://console.cloud.google.com/iam-admin/iam?project={p_enc}"
        return f"{CONSOLE_ASSET_URL}?project={p_enc}"

    return CONSOLE_ASSET_URL


def audit_log_console_url(project_id, resource_name):
    """Build a direct link to Cloud Logging filtered for this asset's audit trail."""
    if not project_id or project_id == "n/a":
        return CONSOLE_LOGS_URL
    short_name = (resource_name or "").rsplit("/", 1)[-1]
    query = f'protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"'
    if short_name:
        query += f'\nprotoPayload.resourceName:"{short_name}"'
    return f"{CONSOLE_LOGS_URL};query={quote(query, safe='')};TimeRange=PT1H?project={quote(project_id, safe='')}"


def should_notify(notification):
    """Validate project allowlist, monitored asset types, and burst deduplication."""
    allow_proj = allowed_projects()
    _, proj_ids = extract_project_identifiers(notification)
    if allow_proj and not (proj_ids & allow_proj):
        return False

    asset = notification.get("asset") or notification.get("priorAsset") or {}
    asset_type = asset.get("assetType") or (notification.get("resource") or {}).get("type") or ""
    allowed_types = monitored_asset_types()
    if allowed_types and asset_type and asset_type not in allowed_types:
        return False

    # If the notification is an updates-only CAI event with zero diff in resource, IAM, & Org Policy, skip noise
    if "asset" in notification or "priorAsset" in notification:
        action = determine_change_action(notification)
        if action in ("MODIFIED", "IAM_POLICY_UPDATED"):
            current_data = (asset.get("resource") or {}).get("data") or {}
            prior_data = ((notification.get("priorAsset") or {}).get("resource") or {}).get("data") or {}
            current_iam = asset.get("iamPolicy") or {}
            prior_iam = (notification.get("priorAsset") or {}).get("iamPolicy") or {}
            current_org_pol = asset.get("orgPolicy") or []
            prior_org_pol = (notification.get("priorAsset") or {}).get("orgPolicy") or []
            if (
                not diff_dicts(prior_data, current_data)
                and not diff_iam_policies(prior_iam, current_iam)
                and not diff_org_policies(prior_org_pol, current_org_pol)
            ):
                return False

    window = dedup_window_seconds()
    if window > 0:
        digest_src = json.dumps(
            {
                "name": asset.get("name") or (notification.get("finding") or {}).get("name"),
                "action": determine_change_action(notification),
                "diff": compute_asset_diff(notification),
            },
            sort_keys=True,
        )
        dedup_key = hashlib.sha256(digest_src.encode("utf-8")).hexdigest()
        now = time.time()
        last_sent = _recent_alerts_cache.get(dedup_key)
        if last_sent is not None and (now - last_sent) < window:
            return False
        _recent_alerts_cache[dedup_key] = now

    return True


def asset_change_values(notification, session=requests):
    """Extract and escape all template placeholder values for a CAI or SCC notification."""
    asset = notification.get("asset") or notification.get("priorAsset") or {}
    finding = notification.get("finding") or {}
    scc_res = notification.get("resource") or {}

    full_asset_name = (
        asset.get("name")
        or scc_res.get("name")
        or finding.get("resourceName")
        or "n/a"
    )
    data = get_data(notification)
    resource_type = (
        asset.get("assetType")
        or scc_res.get("type")
        or finding.get("category")
        or "Unknown asset type"
    )
    short_name = (
        data.get("name")
        or scc_res.get("displayName")
        or full_asset_name.rsplit("/", 1)[-1]
        or full_asset_name
    )
    if resource_type.startswith("run.googleapis.com/") and "/" in str(short_name):
        short_name = str(short_name).rsplit("/", 1)[-1]
    project_id, _ = extract_project_identifiers(notification)
    location = extract_location(notification)
    action = determine_change_action(notification)
    action_emoji = ACTION_EMOJI_MAP.get(action, ":bell:")

    window = notification.get("window") or {}
    timestamp = (
        window.get("startTime")
        or asset.get("updateTime")
        or finding.get("eventTime")
        or finding.get("createTime")
        or "n/a"
    )

    attribution = extract_attribution(
        notification, project_id, full_asset_name, timestamp, session=session
    )
    highlights, recommendations = analyze_security_posture(notification, attribution)

    # Header & Subject
    if action == "SCC_FINDING":
        alert_header = ":shield: *Security Command Center Alert*"
        subject = f"[{finding.get('severity', 'HIGH')}] {finding.get('category', 'Security Finding')} on {short_name}"
    else:
        risk_prefix = ":rotating_light: *Crown Jewel Asset Alert*" if highlights else ":bell: *Cloud Asset Change Notification*"
        alert_header = risk_prefix
        subject = f"{resource_type} `{short_name}` was {action}"

    # Build Attribution section (Who & How)
    audit_link = audit_log_console_url(project_id, full_asset_name)
    attr_lines = [
        "*Change Attribution (Cloud Audit Logs):*",
        f"• *Who (Actor)*: {attribution['actor_display']}",
        f"• *How (Executed via)*: *{attribution['execution_display']}*",
    ]
    if attribution.get("method_name"):
        attr_lines.append(f"• *API Method*: `{escape_mrkdwn(attribution['method_name'])}`")
    if attribution.get("caller_ip"):
        attr_lines.append(
            f"• *Caller IP*: `{escape_mrkdwn(attribution['caller_ip'])}` | <{audit_link}|View Audit Trail in Cloud Logging ↗>"
        )
    else:
        attr_lines.append(f"• *Audit Trail*: <{audit_link}|View Audit Trail in Cloud Logging ↗>")

    attribution_text = "\n".join(attr_lines)

    # Security Highlights section
    security_text = None
    if highlights:
        security_text = "*Security Posture & Risk Signals:*\n" + "\n".join(
            f"• {h}" for h in highlights
        )

    recommendation_text = "\n".join(recommendations) if recommendations else None
    diff_text = compute_asset_diff(notification)

    return {
        "ALERT_HEADER": alert_header,
        "WEB_LINK": console_url(notification, project_id),
        "SUBJECT": escape_mrkdwn(subject),
        "RESOURCE_NAME": escape_mrkdwn(short_name),
        "RESOURCE_TYPE": escape_mrkdwn(resource_type),
        "PROJECT_ID": escape_mrkdwn(project_id),
        "LOCATION": escape_mrkdwn(location),
        "CHANGE_ACTION": escape_mrkdwn(action),
        "ACTION_EMOJI": action_emoji,
        "TIMESTAMP": escape_mrkdwn(timestamp),
        "ATTRIBUTION_DETAILS": attribution_text,
        "SECURITY_HIGHLIGHTS": security_text,
        "CHANGE_DIFF": diff_text,
        "RECOMMENDATION": escape_mrkdwn(recommendation_text) if recommendation_text else None,
    }


def load_template():
    global _template_cache
    if _template_cache is None:
        with TEMPLATE_PATH.open("rt", encoding="utf-8") as fh:
            _template_cache = json.load(fh)
    return copy.deepcopy(_template_cache)


def _placeholders_in(obj):
    text = json.dumps(obj)
    return {key for key in PLACEHOLDER_KEYS if f"<{key}>" in text}


def _fill(obj, values):
    if isinstance(obj, dict):
        return {k: _fill(v, values) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill(v, values) for v in obj]
    if isinstance(obj, str):
        for key, value in values.items():
            obj = obj.replace(f"<{key}>", value or "")
        return obj
    return obj


def build_blocks(notification, template=None, session=requests):
    """Return Slack Block Kit blocks for the CAI asset change or SCC notification."""
    template = template if template is not None else load_template()
    values = asset_change_values(notification, session=session)
    optional = {k for k, v in values.items() if v is None}

    blocks = []
    for block in template:
        if _placeholders_in(block) & optional:
            continue
        filled = _fill(block, values)
        text = filled.get("text")
        if isinstance(text, dict) and isinstance(text.get("text"), str):
            raw_text = text["text"]
            if (
                len(raw_text) > SLACK_SECTION_TEXT_LIMIT
                and "accessory" not in filled
                and "```" not in raw_text
                and "\n" in raw_text
            ):
                chunk_lines = []
                chunk_len = 0
                for line in raw_text.split("\n"):
                    line_len = len(line) + (1 if chunk_lines else 0)
                    if chunk_lines and chunk_len + line_len > SLACK_SECTION_TEXT_LIMIT:
                        blocks.append(
                            {
                                "type": "section",
                                "text": {
                                    "type": text.get("type", "mrkdwn"),
                                    "text": truncate("\n".join(chunk_lines), SLACK_SECTION_TEXT_LIMIT),
                                },
                            }
                        )
                        chunk_lines = [line]
                        chunk_len = len(line)
                    else:
                        chunk_lines.append(line)
                        chunk_len += line_len
                if chunk_lines:
                    blocks.append(
                        {
                            "type": "section",
                            "text": {
                                "type": text.get("type", "mrkdwn"),
                                "text": truncate("\n".join(chunk_lines), SLACK_SECTION_TEXT_LIMIT),
                            },
                        }
                    )
                continue
            text["text"] = truncate(raw_text, SLACK_SECTION_TEXT_LIMIT)
        blocks.append(filled)
    return blocks


def fallback_text(notification):
    """Plain text used for push notifications and screen readers."""
    asset = notification.get("asset") or notification.get("priorAsset") or {}
    data = get_data(notification)
    name = data.get("name") or (asset.get("name") or "").rsplit("/", 1)[-1] or "resource"
    asset_type = asset.get("assetType") or (notification.get("finding") or {}).get("category") or "asset"
    project_id, _ = extract_project_identifiers(notification)
    action = determine_change_action(notification)
    return f"CAI Alert: {asset_type} '{name}' {action} in project {project_id}"


# --------------------------------------------------------------------------
# Slack Delivery
# --------------------------------------------------------------------------

def post_to_slack(blocks, text, token, channel, session=requests):
    """Post a Block Kit message to Slack. Raises TransientError or PermanentError on failure."""
    parsed_url = urlparse(SLACK_API_URL)
    if parsed_url.scheme != "https":
        raise PermanentError("Slack API URL must use HTTPS.")

    try:
        response = session.post(
            SLACK_API_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; charset=utf-8",
            },
            data=json.dumps({
                "channel": channel,
                "blocks": blocks,
                "text": text,
                "unfurl_links": False,
                "unfurl_media": False,
            }),
            timeout=SLACK_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise TransientError(f"Slack request failed: {exc}") from exc

    if response.status_code == 429 or response.status_code >= 500:
        raise TransientError(f"Slack returned HTTP {response.status_code}")

    try:
        body = response.json()
    except ValueError as exc:
        raise TransientError(f"Slack returned non-JSON, HTTP {response.status_code}") from exc

    if not body.get("ok"):
        error = body.get("error", "unknown_error")
        detail = {
            "slack_error": error,
            "response_metadata": body.get("response_metadata"),
        }
        if error in TRANSIENT_SLACK_ERRORS:
            raise TransientError(f"Slack error {error}: {detail}")
        raise PermanentError(f"Slack error {error}: {detail}")
    return body


def handle_notification(notification, token=None, channel=None, session=requests):
    """Format and send one CAI or SCC notification to Slack. Returns False when skipped."""
    asset = notification.get("asset") or notification.get("priorAsset") or {}
    asset_name = asset.get("name") or (notification.get("finding") or {}).get("name")

    if not should_notify(notification):
        log("INFO", "Notification skipped by filter or deduplication", asset=asset_name)
        return False

    token = token or get_secret()
    channel = channel or os.environ.get("SLACK_CHANNEL", "#general")
    if not token or not channel:
        raise PermanentError("SLACK_BOT_TOKEN and SLACK_CHANNEL must be set")

    blocks = build_blocks(notification, session=session)
    post_to_slack(
        blocks,
        fallback_text(notification),
        token.strip(),
        channel.strip(),
        session=session,
    )
    log(
        "INFO",
        "Asset change notification posted to Slack",
        asset=asset_name,
        asset_type=asset.get("assetType"),
        action=determine_change_action(notification),
    )
    return True


def _entry_point(cloud_event, context=None):
    """Unified entry point supporting both Cloud Run functions (2nd gen CloudEvent) and 1st gen (event, context)."""
    event_id = "n/a"
    event_time = None

    if hasattr(cloud_event, "data") and hasattr(cloud_event, "__getitem__"):
        try:
            event_id = cloud_event["id"]
            event_time = cloud_event["time"]
        except (KeyError, TypeError):
            pass
    elif context is not None:
        event_id = getattr(context, "event_id", "n/a")
        event_time = getattr(context, "timestamp", None)

    max_age = int(os.environ.get("MAX_EVENT_AGE_SECONDS", "3600"))
    age = event_age_seconds(event_time)
    if age is not None and age > max_age:
        log(
            "ERROR",
            "Dropping event older than MAX_EVENT_AGE_SECONDS",
            event_id=event_id,
            age_seconds=int(age),
        )
        return

    try:
        notification = parse_pubsub_message(cloud_event)
        handle_notification(notification)
    except PermanentError as exc:
        log("ERROR", f"Permanent failure, event not retried: {exc}", event_id=event_id)
    except TransientError as exc:
        log("WARNING", f"Transient failure, event will be retried: {exc}", event_id=event_id)
        raise


if functions_framework is not None:
    send_slack_chat_notification = functions_framework.cloud_event(_entry_point)
else:
    send_slack_chat_notification = _entry_point

# Backwards-compatible entry point aliases
asset_inventory_to_slack = send_slack_chat_notification
filter_rule = _entry_point


if __name__ == "__main__":
    # Local dry run: python3 main.py path/to/notification.json [--send]
    if len(sys.argv) < 2:
        sys.exit("usage: python3 main.py <notification.json> [--send]")
    input_path = Path(sys.argv[1])
    if not input_path.exists():
        repo_root_candidate = Path(__file__).resolve().parents[2] / sys.argv[1]
        if repo_root_candidate.exists():
            input_path = repo_root_candidate
    with input_path.open("rt", encoding="utf-8") as fh:
        sample = json.load(fh)
    print(json.dumps(build_blocks(sample), indent=2, ensure_ascii=False))
    if "--send" in sys.argv[2:]:
        handle_notification(sample)