"""Service Account IAM policy change monitor.

Triggered by Cloud Asset Inventory (CAI) IAM_POLICY feed notifications on
Pub/Sub when IAM bindings on a Service Account (`iam.googleapis.com/ServiceAccount`)
are added, removed, or altered.
"""

import base64
import html
import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    class _UrllibResponse:
        def __init__(self, status_code, body_bytes):
            self.status_code = status_code
            self._body = body_bytes

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")

    class _UrllibRequestsShim:
        @staticmethod
        def post(url, headers=None, json=None, timeout=10):
            payload = __import__("json").dumps(json).encode("utf-8") if json is not None else None
            req = urllib.request.Request(url, data=payload, headers=headers or {}, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return _UrllibResponse(resp.status, resp.read())

    requests = _UrllibRequestsShim()

try:
    import functions_framework
except ImportError:
    functions_framework = None

try:
    from google.cloud import secretmanager
except ImportError:
    secretmanager = None

WEBHOOK_TIMEOUT_SECONDS = 10
_secret_client = None


def get_secret(secret_id=None, version_id="latest", project_id=None):
    """Retrieve the Teams webhook URL from environment or Secret Manager."""
    env_webhook = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
    if env_webhook and not env_webhook.startswith("projects/"):
        return env_webhook

    if secretmanager is None:
        raise RuntimeError(
            "TEAMS_WEBHOOK_URL is not set and google-cloud-secret-manager is not installed."
        )

    global _secret_client
    if _secret_client is None:
        _secret_client = secretmanager.SecretManagerServiceClient()

    secret_id = secret_id or os.environ.get("SECRET_ID", "secret_teams_webhook")
    project_id = (
        project_id
        or os.environ.get("GCP_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
    )
    if not project_id:
        raise ValueError(
            "GCP_PROJECT (or TEAMS_WEBHOOK_URL) environment variable must be set."
        )

    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
    request = secretmanager.AccessSecretVersionRequest(name=name)
    return _secret_client.access_secret_version(request=request).payload.data.decode("utf-8").strip()


def _decode_event(event):
    """Extract JSON payload from either a 2nd gen CloudEvent or 1st gen Pub/Sub event dict."""
    if hasattr(event, "data") and isinstance(event.data, dict):
        event = event.data
    if isinstance(event, dict) and "message" in event and isinstance(event["message"], dict):
        raw_b64 = event["message"]["data"]
    else:
        raw_b64 = event["data"]
    pubsub_message = base64.b64decode(raw_b64).decode("utf-8")
    return json.loads(pubsub_message)


def _aggregate_bindings(bindings):
    """Aggregate members per role so duplicate role entries (e.g., IAM conditions) are merged."""
    aggregated = {}
    if not isinstance(bindings, list):
        return aggregated
    for binding in bindings:
        if not isinstance(binding, dict) or "role" not in binding:
            continue
        role = binding["role"]
        members = binding.get("members") or []
        existing = aggregated.setdefault(role, [])
        for member in members:
            if member not in existing:
                existing.append(member)
    return aggregated


def compare_bindings(current_bindings, old_bindings):
    """Compare current and previous IAM policy bindings to identify added/removed roles and members."""
    curr_map = _aggregate_bindings(current_bindings)
    old_map = _aggregate_bindings(old_bindings)

    current_roles = list(curr_map.keys())
    old_roles = list(old_map.keys())

    added_roles = [role for role in current_roles if role not in old_map]
    removed_roles = [role for role in old_roles if role not in curr_map]
    remaining_roles = [role for role in current_roles if role in old_map]

    altered_members = []
    for remaining_role in remaining_roles:
        curr_members = curr_map[remaining_role]
        prev_members = old_map[remaining_role]
        added_members = [m for m in curr_members if m not in prev_members]
        removed_members = [m for m in prev_members if m not in curr_members]
        if added_members or removed_members:
            altered_members.append(
                {
                    remaining_role: (
                        {"added_members": added_members},
                        {"removed_members": removed_members},
                    )
                }
            )

    return added_roles, removed_roles, altered_members


def craft_roles_message(roles, bindings, update):
    """Craft HTML message to alert when IAM roles are added or removed."""
    curr_map = _aggregate_bindings(bindings)
    safe_update = html.escape(str(update))
    message = f"IAM policy has been <b>{safe_update}</b>.<ol>"

    for role in roles:
        if role in curr_map:
            message += f"<li>{html.escape(str(role))}<ul>"
            for member in curr_map[role]:
                message += f"<li>{html.escape(str(member))}</li>"
            message += "</ul></li>"

    message += "</ol>"
    return message


def craft_member_adjust_message(altered_members, bindings):
    """Craft HTML message to alert when IAM policy role members are modified."""
    curr_map = _aggregate_bindings(bindings)
    message = "IAM Policy has been <b>altered</b>.<ol>"

    for am in altered_members:
        for role, members in am.items():
            safe_role = html.escape(str(role))
            message += f"<li>{safe_role}<ol><li><b>Added Members:</b><ul>"
            for added_member in members[0]["added_members"]:
                message += f"<li>{html.escape(str(added_member))}</li>"
            message += "</ul></li><li><b>Removed Members:</b><ul>"
            for removed_member in members[1]["removed_members"]:
                message += f"<li>{html.escape(str(removed_member))}</li>"
            message += "</ul></li><li>All Current Members:<ul>"
            for member in curr_map.get(role, []):
                message += f"<li>{html.escape(str(member))}</li>"
            message += "</ul></li></ol></li>"
    message += "</ol>"
    return message


def create_message(content):
    """Craft a notification message and title from a CAI Service Account IAM policy event."""
    if not isinstance(content, dict):
        return None, ""

    prior_state = content.get("priorAssetState", "PRESENT")
    asset = content.get("asset") or {}
    prior_asset = content.get("priorAsset") or {}

    current_bindings = (asset.get("iamPolicy") or {}).get("bindings") or []
    old_bindings = (prior_asset.get("iamPolicy") or {}).get("bindings") or []

    asset_name = asset.get("name") or prior_asset.get("name") or ""
    parts = asset_name.split("/")
    sa_id = html.escape(parts[-1] if parts else "unknown")
    project = html.escape(parts[-3] if len(parts) >= 3 else "unknown")

    title = f"Service account <b>{sa_id}</b> alert on Project <b>{project}</b>!"

    message = None
    messages = []

    if prior_state == "PRESENT" or prior_state == "DOES_NOT_EXIST":
        added_roles, removed_roles, altered_members = compare_bindings(
            current_bindings, old_bindings
        )

        if added_roles:
            messages.append(craft_roles_message(added_roles, current_bindings, "added"))
        if removed_roles:
            messages.append(craft_roles_message(removed_roles, old_bindings, "removed"))
        if altered_members:
            messages.append(craft_member_adjust_message(altered_members, current_bindings))

        if messages:
            message = "".join(messages)

    return message, title


def send_teams(webhook_url: str, message: str, title: str, color: str = "FF0000") -> int:
    """Send a Microsoft Teams notification (supports Workflows Adaptive Cards & Connector MessageCards)."""
    parsed = urlparse(webhook_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("Teams webhook URL must use https://")

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": title,
        "sections": [
            {
                "activityTitle": title,
                "activitySubtitle": message,
            }
        ],
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Medium",
                            "weight": "Bolder",
                            "text": title,
                            "wrap": True,
                        },
                        {
                            "type": "TextBlock",
                            "text": message,
                            "wrap": True,
                        },
                    ],
                },
            }
        ],
    }

    response = requests.post(
        url=webhook_url,
        headers={"Content-Type": "application/json"},
        json=payload,
        timeout=WEBHOOK_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.status_code


def _entry_point(event, context=None):
    """Triggered from a message on a Cloud Pub/Sub topic (Gen 2 CloudEvent or Gen 1 event)."""
    json_pubsub_message = _decode_event(event)
    message, title = create_message(json_pubsub_message)

    if message is not None:
        webhook = str(get_secret())
        send_teams(webhook_url=webhook, message=message, title=title)


if functions_framework is not None:
    hello_pubsub = functions_framework.cloud_event(_entry_point)
else:
    hello_pubsub = _entry_point
