"""
collector.py

Job: read a role's messy IAM policy JSON, and turn it into a simple,
flat list of actions. Like a security guard summarizing "here's every
door this badge can open" instead of you reading the raw badge logs.
"""

import json


def get_actions_from_policy(policy_doc):
    """
    Given ONE policy document (the JSON with "Statement" in it),
    return the list of actions it allows.

    We only look at "Allow" statements for now - keeping this simple
    on purpose for version 1.
    """
    actions = []
    statements = policy_doc.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        action = statement.get("Action", [])
        if isinstance(action, str):
            action = [action]
        actions.extend(action)

    return actions

def get_passable_roles(policy_doc):
    """
    Looks specifically for iam:PassRole permissions, and extracts WHICH
    role(s) they apply to (from the "Resource" field), not just that
    the permission exists.

    Why this matters: 'iam:PassRole' on Resource '*' means "can pass ANY
    role" (very dangerous, broad). But 'iam:PassRole' scoped to one
    specific role ARN means "can pass THIS ONE role" - which only
    matters if THAT specific role happens to be privileged.

    This is what lets us build chains: "Role A can pass Role B" becomes
    a link in the graph, worth following to see where Role B can go.
    """
    passable = []
    statements = policy_doc.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        action = statement.get("Action", [])
        if isinstance(action, str):
            action = [action]

        if "iam:PassRole" in action or "iam:*" in action:
            resource = statement.get("Resource", [])
            if isinstance(resource, str):
                resource = [resource]
            passable.extend(resource)

    return passable

def collect_role_permissions(iam_client, role_name):
    """
    For ONE role, gather:
      1. every action it's allowed to perform (as before)
      2. which specific roles it's allowed to "pass" to services (new)

    Returns a dict like:
        {
            "actions": ["iam:PassRole", "lambda:CreateFunction"],
            "passable_roles": ["arn:aws:iam::123456789012:role/ci-deploy-role"]
        }
    """
    all_actions = []
    all_passable = []

    policy_names = iam_client.list_role_policies(RoleName=role_name)["PolicyNames"]

    for policy_name in policy_names:
        response = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        doc = response["PolicyDocument"]
        if isinstance(doc, str):
            doc = json.loads(doc)
        all_actions.extend(get_actions_from_policy(doc))
        all_passable.extend(get_passable_roles(doc))

    return {
        "actions": sorted(set(all_actions)),
        "passable_roles": sorted(set(all_passable)),
    }


def collect_all_roles(iam_client):
    """
    Runs collect_role_permissions() for EVERY role in the account.

    Returns a dict like:
        {
            "app-reader-role": ["s3:GetObject"],
            "ci-deploy-role": ["iam:CreatePolicyVersion"],
        }
    """
    roles_data = {}
    roles = iam_client.list_roles()["Roles"]

    for role in roles:
        role_name = role["RoleName"]
        roles_data[role_name] = collect_role_permissions(iam_client, role_name)

    return roles_data
