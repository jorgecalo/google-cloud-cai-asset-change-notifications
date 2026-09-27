"""Compute Engine VM machine type and security posture monitor.

Triggered by Cloud Asset Inventory (CAI) or Security Command Center (SCC)
notifications on Pub/Sub when a Compute Engine VM instance is created or
running without an approved machine series (default: `n2d-`).
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


def _extract_project_name(content):
    asset = content.get("asset") or content.get("priorAsset") or {}
    asset_name = asset.get("name") or ""
    if "/projects/" in asset_name:
        return asset_name.split("/projects/", 1)[1].split("/", 1)[0]
    parts = asset_name.split("/")
    if len(parts) > 4 and parts[4]:
        return parts[4]
    scc_res = content.get("resource") or {}
    return scc_res.get("projectDisplayName") or "unknown-project"


def check_conditions(content):
    """Check if a running VM uses a non-compliant machine type (default: must start with `n2d-`).

    Safely handles optional Compute Engine fields (`confidentialInstanceConfig`,
    `shieldedInstanceConfig`, `cpuPlatform`) and escapes all untrusted values.
    """
    message = None
    if not isinstance(content, dict) or content.get("deleted") is True:
        return None, ""

    asset = content.get("asset") or {}
    data = (asset.get("resource") or {}).get("data") or {}
    vm_name = data.get("name")
    if not vm_name:
        return None, ""

    project_name = _extract_project_name(content)
    vm_status = data.get("status", "UNKNOWN")
    raw_machine_type = data.get("machineType", "")
    current_machine_type = raw_machine_type.rsplit("/", 1)[-1] if raw_machine_type else "unknown"

    conf_config = data.get("confidentialInstanceConfig") or {}
    confidential_compute = conf_config.get("enableConfidentialCompute", False)
    cpu_platform = data.get("cpuPlatform", "Unknown")

    shielded_vm = data.get("shieldedInstanceConfig") or {}
    integ_monitor = shielded_vm.get("enableIntegrityMonitoring", False)
    secure_boot = shielded_vm.get("enableSecureBoot", False)
    vtpm = shielded_vm.get("enableVtpm", False)

    safe_params = {
        "project_name": html.escape(str(project_name)),
        "vm": html.escape(str(vm_name)),
        "vm_status": html.escape(str(vm_status)),
        "machine_type": html.escape(str(current_machine_type)),
        "conf_compute": html.escape(str(confidential_compute)),
        "cpu": html.escape(str(cpu_platform)),
        "integ": html.escape(str(integ_monitor)),
        "secure_boot": html.escape(str(secure_boot)),
        "vtpm": html.escape(str(vtpm)),
    }

    title = f'Project {safe_params["project_name"]} alert on VM "{safe_params["vm"]}"!'

    allowed_prefixes = tuple(
        p.strip()
        for p in os.environ.get("ALLOWED_MACHINE_PREFIXES", "n2d-").split(",")
        if p.strip()
    )

    if vm_status == "RUNNING" and not current_machine_type.startswith(allowed_prefixes):
        message = (
            "VM is running with <b>incorrect machine type</b><br>"
            "<ul>"
            f"<li>VM Name: {safe_params['vm']}</li>"
            f"<li>VM Status: {safe_params['vm_status']}</li>"
            f"<li>Machine Type: <b>{safe_params['machine_type']}</b></li>"
            f"<li>CPU Platform: {safe_params['cpu']}</li>"
            f"<li>Confidential Compute Enabled: {safe_params['conf_compute']}</li>"
            "<li>Shielded VM Status:"
            "<ul>"
            f"<li>Integrity Monitoring Enabled: {safe_params['integ']}</li>"
            f"<li>Secure Boot Enabled: {safe_params['secure_boot']}</li>"
            f"<li>VTPM Enabled: {safe_params['vtpm']}</li>"
            "</ul>"
            "</li>"
            "</ul>"
        )

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
    message, title = check_conditions(json_pubsub_message)

    if message is not None:
        webhook = str(get_secret())
        send_teams(webhook_url=webhook, message=message, title=title)


if functions_framework is not None:
    hello_pubsub = functions_framework.cloud_event(_entry_point)
else:
    hello_pubsub = _entry_point
