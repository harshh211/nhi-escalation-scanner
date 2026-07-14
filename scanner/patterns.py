"""
patterns.py

The "knowledge base" - known ways a role's permissions can be abused
to reach admin access. Each pattern = one known attacker trick.

Based on real, documented AWS privilege escalation research.
"""


def check_create_policy_version(actions):
    """
    Pattern: iam:CreatePolicyVersion

    If a role can create a new version of a policy, it can rewrite a
    policy attached to ITSELF to grant full admin ('*' action on '*'
    resource), then activate that new version. AWS lets you switch
    which version of a policy is "active" - this abuses that feature.
    """
    if "iam:CreatePolicyVersion" in actions or "iam:*" in actions:
        return {
            "pattern": "CreatePolicyVersion",
            "risk": "HIGH",
            "explanation": (
                "This identity can create a new version of an IAM policy. "
                "It could rewrite a policy attached to itself to grant "
                "full admin access, then activate that version."
            ),
            "attack_steps": [
                "Find a policy currently attached to this role",
                "Create a new version of it granting '*' on '*' (full admin)",
                "Set that new version as the default",
                "Role now effectively has full admin access",
            ],
        }
    return None


def check_attach_role_policy(actions):
    """
    Pattern: iam:AttachRolePolicy

    If a role can attach policies to OTHER roles (or itself), it can
    simply attach AWS's built-in 'AdministratorAccess' policy directly.
    No need to write a custom policy - AWS already provides this one.
    """
    if "iam:AttachRolePolicy" in actions or "iam:*" in actions:
        return {
            "pattern": "AttachRolePolicy",
            "risk": "HIGH",
            "explanation": (
                "This identity can attach any IAM policy to any role, "
                "including itself. It could directly attach AWS's built-in "
                "'AdministratorAccess' policy."
            ),
            "attack_steps": [
                "Call iam:AttachRolePolicy targeting this same role",
                "Attach the AWS managed policy 'AdministratorAccess'",
                "Role now has full admin access",
            ],
        }
    return None
def check_put_role_policy(actions):
    """
    Pattern: iam:PutRolePolicy

    If a role can put (create/overwrite) an inline policy on any role,
    it can simply write a brand new policy granting itself full admin -
    no need to touch existing policies at all.
    """
    if "iam:PutRolePolicy" in actions or "iam:*" in actions:
        return {
            "pattern": "PutRolePolicy",
            "risk": "HIGH",
            "explanation": (
                "This identity can create or overwrite an inline policy "
                "on any role, including itself. It could simply write a "
                "brand new policy granting full admin access directly."
            ),
            "attack_steps": [
                "Call iam:PutRolePolicy targeting this same role",
                "Write a new inline policy granting '*' on '*'",
                "Role now has full admin access - no existing policy needed",
            ],
        }
    return None


def check_update_assume_role_policy(actions):
    """
    Pattern: iam:UpdateAssumeRolePolicy

    Every role has a 'trust policy' - it defines WHO is allowed to use
    that role. If an identity can edit another role's trust policy, it
    can add itself as a trusted user of a MORE privileged role, then
    simply assume it.
    """
    if "iam:UpdateAssumeRolePolicy" in actions or "iam:*" in actions:
        return {
            "pattern": "UpdateAssumeRolePolicy",
            "risk": "HIGH",
            "explanation": (
                "This identity can edit the trust policy of any role - "
                "the rule that defines who's allowed to use that role. "
                "It could add itself as a trusted user of a more "
                "privileged role, then assume it directly."
            ),
            "attack_steps": [
                "Find a role with higher privileges (e.g. admin)",
                "Call iam:UpdateAssumeRolePolicy to add yourself as trusted",
                "Call sts:AssumeRole to become that privileged role",
            ],
        }
    return None


def check_create_access_key(actions):
    """
    Pattern: iam:CreateAccessKey

    If an identity can create access keys for OTHER users, it can
    generate long-lived credentials for a more privileged user and
    simply authenticate as them directly.
    """
    if "iam:CreateAccessKey" in actions or "iam:*" in actions:
        return {
            "pattern": "CreateAccessKey",
            "risk": "HIGH",
            "explanation": (
                "This identity can create AWS access keys for any user. "
                "It could generate a fresh access key for a more "
                "privileged user (e.g. an admin) and authenticate as them."
            ),
            "attack_steps": [
                "Find a user with higher privileges",
                "Call iam:CreateAccessKey targeting that user",
                "Use the new key/secret pair to authenticate as them",
            ],
        }
    return None


def check_pass_role_to_lambda(actions):
    """
    Pattern: iam:PassRole + lambda:CreateFunction (combo pattern)

    'PassRole' lets an identity hand a role to an AWS service, like
    Lambda. Combined with the ability to create a Lambda function, an
    identity can create a function that runs AS a more privileged role,
    then invoke it to perform admin actions on their behalf.

    NOTE: a full check would also confirm the specific role being passed
    is actually privileged - this simplified version flags the
    COMBINATION as worth investigating, which is still valuable signal.
    """
    has_pass_role = "iam:PassRole" in actions or "iam:*" in actions
    has_lambda_create = "lambda:CreateFunction" in actions or "lambda:*" in actions

    if has_pass_role and has_lambda_create:
        return {
            "pattern": "PassRoleToLambda",
            "risk": "MEDIUM",
            "explanation": (
                "This identity can both pass IAM roles to services AND "
                "create Lambda functions. If a privileged role exists in "
                "the account, it could create a function using that role "
                "and run admin-level code through it."
            ),
            "attack_steps": [
                "Identify a role with elevated permissions",
                "Create a Lambda function, passing that role to it",
                "Write function code performing admin actions",
                "Invoke the function - code runs with the role's permissions",
            ],
        }
    return None

# The list of every pattern the scanner checks. To add a new escalation
# trick later: write a function above, add it here. Nothing else changes.
ALL_PATTERNS = [
    check_create_policy_version,
    check_attach_role_policy,
    check_put_role_policy,
    check_update_assume_role_policy,
    check_create_access_key,
    check_pass_role_to_lambda,
]


def find_escalation_paths(actions):
    """
    Runs every known pattern against one role's action list.
    Returns a list of all patterns that matched.
    """
    findings = []
    for check in ALL_PATTERNS:
        result = check(actions)
        if result is not None:
            findings.append(result)
    return findings
