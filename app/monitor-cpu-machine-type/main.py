import requests 
import base64
import json

from google.cloud import secretmanager

def get_secret(secret_id="secret_teams_webhook", version_id="latest", project_id="asml-dta-tst-tstsusi"):
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
    request = secretmanager.AccessSecretVersionRequest(name=name)
    
    return client.access_secret_version(request=request).payload.data.decode("utf-8")

def hello_pubsub(event, context):
    """Triggered from a message on a Cloud Pub/Sub topic.
    Args:
         event (dict): Event payload.
         context (google.cloud.functions.Context): Metadata for the event.
    """
    pubsub_message = base64.b64decode(event['data']).decode('utf-8')
    json_pubsub_message = json.loads(pubsub_message) 

    webhook = str(get_secret())

    message, title = check_conditions(json_pubsub_message)

    if message is not None: 
        send_teams(webhook_url=webhook, message=message, title=title)
 
def check_conditions(content:str):
    """
    Check to see if either a VM's machine type has changed away from N2D or new VM created without N2D.
    Proposed solution changed from priorAssetState = PRESENT/DID_NOT_EXIST to status. 
    Due to new VM triggering PRESENT as well (especially if VM deleted then recreated with same name).
    Args:
        content (json) : content of event received by cloud feed.
    """
    #message = "unknown state, something triggered this function but did not capture any expected situations"
    message = None 

    try: # sometimes event occurs that is not related to VM being created e.g. deletion
        vm_name = content['asset']['resource']['data']['name']
    except:
        print("vm name was not found")
        return None, ""

    # instantiate some useful variables
    project_name = content['asset']['name'].split("/")[4]
    vm_status = content['asset']['resource']['data']['status']
    current_machine_type = content['asset']['resource']['data']['machineType'].split("/")[-1]
    confidential_compute = content['asset']['resource']['data']['confidentialInstanceConfig']['enableConfidentialCompute']
    cpu_platform = content['asset']['resource']['data']['cpuPlatform']
    shielded_vm = content['asset']['resource']['data']['shieldedInstanceConfig']
    integ_monitor = shielded_vm['enableIntegrityMonitoring']
    secure_boot = shielded_vm['enableSecureBoot']
    vtpm = shielded_vm['enableVtpm']

    message_parameters = {"project_name": project_name,
                          "vm": vm_name,
                          "vm_status": vm_status,
                          "machine_type": current_machine_type,
                          "conf_compute": confidential_compute,
                          "cpu": cpu_platform,
                          "shielded_vm": shielded_vm,
                          "integ": integ_monitor,
                          "secure_boot": secure_boot,
                          "vtpm": vtpm}

    title = "Project {project_name} alert on VM \"{vm}\"!".format(**message_parameters)

    # known issue: currently triggers twice due to change in fingerprint in asset when in status "running"
    if vm_status == "RUNNING":
        if current_machine_type[:4] != "n2d-":
            message = """VM is running with <b>incorrect machine type</b><br>
            <ul>
            <li>VM Name: {vm}</li>
            <li>VM Status: {vm_status}</li>
            <li>Machine Type: <b>{machine_type}<b></li>
            <li>CPU Platform: {cpu}</li>
            <li>Confidential Compute Enabled: {conf_compute}</li>
            <li>Shielded VM Status:
            <ul>
            <li>Integrity Monitoring Enabled: {integ}</li>
            <li>Secure Boot Enabled: {secure_boot}</li>
            <li>VTPM Enabled: {vtpm}</li>
            </ul>
            </li>
            </ul>""".format(**message_parameters)

    return message, title 
    

def send_teams(webhook_url:str, message:str, title:str, color:str="FF0000") -> int:
    """
      - Send a teams notification to the desired webhook_url
      - Returns the status code of the HTTP request
        - webhook_url : the url you got from the teams webhook configuration
        - content : your formatted notification content
        - title : the message that'll be displayed as title, and on phone notifications
        - color (optional) : hexadecimal code of the notification's top line color, default corresponds to black
    """
    response = requests.post(
        url=webhook_url,
        headers={"Content-Type": "application/json"},
        json={
            "themeColor": color,
            "summary": title,
            "sections": [{
                "activityTitle": title,
                "activitySubtitle": message
            }],
        },
    )
    print(response.status_code) # Should be 200
