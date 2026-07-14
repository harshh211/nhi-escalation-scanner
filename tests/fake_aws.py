"""
fake_aws.py

Builds a FAKE AWS account in memory using moto, with deliberately risky
non-human identities (IAM roles). We KNOW what's wrong here, so later we
can check whether our scanner correctly finds it.
"""

import boto3


def build_fake_account():
    """
    Creates 3 IAM ROLES (non-human identities), mimicking real workloads:

    1. 'app-reader-role'    -> SAFE. A web app that only reads from S3.
    2. 'ci-deploy-role'     -> RISKY. A CI/CD pipeline role that can modify
                               IAM policies — a build pipeline that could
                               quietly grant itself admin.
    3. 'lambda-worker-role' -> RISKY. A Lambda function's role that can
                               attach any policy to any role, including
                               itself -> a hidden path to admin.
    """
    iam = boto3.client("iam", region_name="us-east-1")

    trust = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

    # --- Role 1: safe reader ---
    iam.create_role(RoleName="app-reader-role", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(
        RoleName="app-reader-role",
        PolicyName="ReadS3",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}',
    )

    # --- Role 2: CI/CD role that can rewrite IAM policies (RISKY) ---
    iam.create_role(RoleName="ci-deploy-role", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(
        RoleName="ci-deploy-role",
        PolicyName="ManageIAM",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreatePolicyVersion","Resource":"*"}]}',
    )

    # --- Role 3: Lambda role that can attach policies to roles (RISKY) ---
    iam.create_role(RoleName="lambda-worker-role", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(
        RoleName="lambda-worker-role",
        PolicyName="AttachAny",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*"}]}',
    )

    # --- Role 4: can edit trust policies (RISKY - new pattern) ---
    iam.create_role(RoleName="backup-service-role", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(
        RoleName="backup-service-role",
        PolicyName="EditTrustPolicies",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateAssumeRolePolicy","Resource":"*"}]}',
    )
   
    # --- Role 5: can write new inline policies on any role (RISKY) ---
    iam.create_role(RoleName="monitoring-agent-role", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(
        RoleName="monitoring-agent-role",
        PolicyName="WriteInlinePolicies",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutRolePolicy","Resource":"*"}]}',
    )

    # --- Role 6: can create access keys for any user (RISKY) ---
    iam.create_role(RoleName="data-sync-role", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(
        RoleName="data-sync-role",
        PolicyName="CreateAccessKeys",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*"}]}',
    )

    # --- Role 7: can't escalate directly, but CAN pass a dangerous
    #     role (ci-deploy-role) to Lambda - a CHAINED escalation path ---
    iam.create_role(RoleName="auditor-role", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(
        RoleName="auditor-role",
        PolicyName="PassCIDeployRole",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:PassRole","lambda:CreateFunction"],"Resource":"arn:aws:iam::123456789012:role/ci-deploy-role"}]}',
    )   
 
    # --- Role 8: PURE chain example. Can ONLY pass ci-deploy-role
    #     (no lambda:CreateFunction, so no direct pattern matches) ---
    iam.create_role(RoleName="reporting-role", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(
        RoleName="reporting-role",
        PolicyName="PassCIDeployRoleOnly",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/ci-deploy-role"}]}',
    )

    return iam
