import base64
import json
import requests

from google.cloud import logging
from google.cloud import secretmanager

def get_secret(secret_id="sccnotifier-slack-bot-token", version_id="latest"):
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/[INSERT-PROJECT-ID]/secrets/{secret_id}/versions/{version_id}"
    request = secretmanager.AccessSecretVersionRequest(name=name)
    # print(client.access_secret_version(request=request).payload.data.decode("utf-8"))
    return client.access_secret_version(request=request).payload.data.decode("utf-8")

# Triggered from a message on a Cloud Pub/Sub topic.
def filter_rule(event, context):
    """Triggered from a message on a Cloud Pub/Sub topic.
    Args:
         event (dict): Event payload.
         context (google.cloud.functions.Context): Metadata for the event.
    """
    TOKEN = str(get_secret("sccnotifier-slack-bot-token"))
    URL = "https://slack.com/api/chat.postMessage"
    
    pubsub_message = base64.b64decode(event['data']).decode('utf-8')
    message_json = json.loads(pubsub_message)
    natIP = json_extract(message_json,"type")
   
    if 'ONE_TO_ONE_NAT' in natIP:
        payload = get_data(message_json)
        name = payload["name"]
        requests.post(URL, data={
            "token": TOKEN,
            "channel": "#general",
            "text": f"Instance *{name}* was created with external IP!"
        })

def get_data(message_json):
    try:
        return message_json["asset"]["resource"]["data"]
    except:
        return message_json["priorAsset"]["resource"]["data"]

def json_extract(obj, key):
    """Recursively fetch values from nested JSON."""
    arr = []
    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    extract(v, arr, key)
                elif k == key:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr, key)
        return arr
    values = extract(obj, arr, key)
    return values