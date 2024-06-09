import requests 
import base64
import json

from google.cloud import secretmanager

def get_secret(secret_id="secret_teams_webhook", version_id="latest", project_id="asml-dta-tst-tstsusi"):
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
    request = secretmanager.AccessSecretVersionRequest(name=name)
    # print(client.access_secret_version(request=request).payload.data.decode("utf-8"))
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

    message, title = create_message(json_pubsub_message)

    if message is not None: 
        send_teams(webhook_url=webhook, message=message, title=title)


def compare_bindings(current_bindings, old_bindings):
    """
    Compare current and previous binding to check if any new changes have been made.
    Args:
        current_bindings (list of dict): current IAM policy in place.
        old_bindings (list of dict): old IAM policy.
    """
    # find roles that were added/removed.
    current_roles = [binding['role'] for binding in current_bindings]
    old_roles = [binding['role']for binding in old_bindings]

    added_roles = [role for role in current_roles if role not in old_roles]
    removed_roles = [role for role in old_roles if role not in current_roles]

    # find added/removed members from roles.
    remaining_roles =  [role for role in current_roles if role in old_roles]
    altered_members = []

    # for each remaining role, extract the member from current and old bindings. 
    # then compare to see if any members have changed.
    for remaining_role in remaining_roles:
        for current_binding in current_bindings: # find the members in current bindings 
            if current_binding['role'] == remaining_role:
                for old_binding in old_bindings: # find the members in old bindings
                    if old_binding['role'] == remaining_role:

                        # find members that were added/removed.
                        added_members = [member for member in current_binding['members'] if member not in old_binding['members']]
                        removed_members = [member for member in old_binding['members'] if member not in current_binding['members']]

                        # only update if the members were actually changed.
                        if (len(added_members) or len(removed_members)) > 0:
                            altered_members.append({remaining_role: ({"added_members": added_members}, {"removed_members": removed_members})})

    return added_roles, removed_roles, altered_members


def craft_roles_message(roles, bindings, update):
    """
    Craft message to alert when an IAM policy is added/deleted.
    Args:
        roles (list): list of role names.
        bindings (list of dict): IAM policy.
        update (string): added/deleted.
    """
    message = f"IAM policy has been <b>{update}</b>.<ol>"

    for role in roles:
        for binding in bindings:
            if binding['role'] == role:

                message += f"<li>{role}</li><ul>"
                for member in binding['members']:
                    message += f"""<li>{member}</li>"""
                message += "</ul>"

    message += "</ol>"
    return message

def craft_member_adjust_message(altered_members, bindings):
    """
    Craft message to alert when IAM policy has been changed (the members).
    Args:
        altered_members ([rolename: ({added}, removed)]): information containing altered roles and their respective members.
        bindings (list of dict): IAM policy.
    """
    message = "IAM Policy has been <b>altered</b>.<ol>"

    for am in altered_members:
        for role, members in am.items():
            message += f"<li>{role}</li><ol><li><b>Added Members:</b> <ul>"
            for added_member in members[0]['added_members']:
                message += f"<li>{added_member}</li>"
            message += """</li></ul>
                        <li><b>Removed Members:</b><ul>"""
            for removed_member in members[1]['removed_members']:
                message += f"<li>{removed_member}</li>"
            message += """</li></ul>
            <li>All Current Members:<ul>"""

            for binding in bindings:
                if binding['role'] == role:
                    for member in binding['members']:
                        message += f"<li>{member}</li>"
            message += "</li></ul></ol>"
    message += "</ol>"
    return message 

def create_message(content:str):
    """
    Craft a message to send to teams.
    Args:
        content (json) : content of event received by cloud feed.
    """
    # extract useful variables
    msg_args = {}
    msg_args['prior_state'] = content["priorAssetState"]
    msg_args['current_bindings'] = content['asset']['iamPolicy']["bindings"]
    msg_args['project'] = content['asset']['name'].split("/")[-1]
    
    messages = []
    title = "IAM Policy alert on Project <b>{project}</b>!".format(**msg_args)

    if msg_args['prior_state'] == "PRESENT":
        msg_args['old_bindings'] = content['priorAsset']['iamPolicy']["bindings"]

        added_roles, removed_roles, altered_members = compare_bindings(msg_args['current_bindings'], msg_args['old_bindings'])

        messages = []

        if len(added_roles) > 0:
            messages.append(craft_roles_message(added_roles, msg_args['current_bindings'], "added"))
        
        if len(removed_roles) > 0:
            messages.append(craft_roles_message(removed_roles, msg_args['old_bindings'], "removed"))

        if len(altered_members) > 0:
            messages.append(craft_member_adjust_message(altered_members, msg_args['current_bindings']))

        if len(messages) > 0:
            message = ""
            for m in messages:
                message += m
        else:
            message = None 
   
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
