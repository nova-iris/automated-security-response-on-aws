# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Reviews and removes overly permissive KMS inline policies from IAM principals.
"""
import boto3
import json
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})

# KMS actions that are considered high-risk when allowed with wildcard resources
HIGH_RISK_KMS_ACTIONS = [
    "kms:*",
    "kms:Decrypt",
    "kms:Encrypt",
    "kms:ReEncrypt*",
    "kms:GenerateDataKey*",
    "kms:CreateGrant",
    "kms:DescribeKey"
]


def connect_to_iam():
    return boto3.client("iam", config=BOTO_CONFIG)


def get_principal_type(principal_arn):
    """Determine the type of IAM principal from ARN."""
    if ":user/" in principal_arn:
        return "user"
    elif ":role/" in principal_arn:
        return "role"
    elif ":group/" in principal_arn:
        return "group"
    return None


def get_principal_name(principal_arn):
    """Extract principal name from ARN."""
    return principal_arn.split("/")[-1]


def check_policy_for_kms_issues(policy_document):
    """Check if a policy has overly permissive KMS statements."""
    issues = []
    
    if isinstance(policy_document, str):
        policy_document = json.loads(policy_document)
    
    statements = policy_document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        
        # Check for high-risk KMS actions with wildcard resources
        for action in actions:
            if any(action == risk_action or action.startswith(risk_action.replace("*", "")) 
                   for risk_action in HIGH_RISK_KMS_ACTIONS):
                if "*" in resources or any("*" in r for r in resources):
                    issues.append({
                        "action": action,
                        "resources": resources,
                        "statement": stmt
                    })
    
    return issues


def lambda_handler(event, _):
    """
    Reviews and reports on KMS inline policies for an IAM principal.
    """
    principal_arn = event["principal_arn"]

    iam_client = connect_to_iam()
    
    principal_type = get_principal_type(principal_arn)
    principal_name = get_principal_name(principal_arn)
    
    if not principal_type:
        return {
            "status": "FAILED",
            "message": f"Unable to determine principal type from ARN: {principal_arn}"
        }

    findings = []
    
    try:
        # Get inline policies based on principal type
        if principal_type == "user":
            paginator = iam_client.get_paginator("list_user_policies")
            for page in paginator.paginate(UserName=principal_name):
                for policy_name in page.get("PolicyNames", []):
                    policy_response = iam_client.get_user_policy(
                        UserName=principal_name,
                        PolicyName=policy_name
                    )
                    issues = check_policy_for_kms_issues(policy_response["PolicyDocument"])
                    if issues:
                        findings.append({
                            "policy_name": policy_name,
                            "issues": issues
                        })
        
        elif principal_type == "role":
            paginator = iam_client.get_paginator("list_role_policies")
            for page in paginator.paginate(RoleName=principal_name):
                for policy_name in page.get("PolicyNames", []):
                    policy_response = iam_client.get_role_policy(
                        RoleName=principal_name,
                        PolicyName=policy_name
                    )
                    issues = check_policy_for_kms_issues(policy_response["PolicyDocument"])
                    if issues:
                        findings.append({
                            "policy_name": policy_name,
                            "issues": issues
                        })
        
        elif principal_type == "group":
            paginator = iam_client.get_paginator("list_group_policies")
            for page in paginator.paginate(GroupName=principal_name):
                for policy_name in page.get("PolicyNames", []):
                    policy_response = iam_client.get_group_policy(
                        GroupName=principal_name,
                        PolicyName=policy_name
                    )
                    issues = check_policy_for_kms_issues(policy_response["PolicyDocument"])
                    if issues:
                        findings.append({
                            "policy_name": policy_name,
                            "issues": issues
                        })

        if not findings:
            return {
                "status": "SUCCESS",
                "message": f"No overly permissive KMS inline policies found for {principal_type} {principal_name}"
            }

        return {
            "status": "MANUAL_REMEDIATION_REQUIRED",
            "message": f"Found {len(findings)} inline policies with overly permissive KMS actions for {principal_type} {principal_name}",
            "findings": findings,
            "remediation_steps": [
                "Review each identified policy and its KMS-related statements",
                "Replace wildcard (*) resources with specific KMS key ARNs",
                "Apply principle of least privilege - only grant necessary KMS actions",
                "Consider using KMS key policies instead of IAM policies for KMS access",
                "Test applications after policy changes to ensure functionality"
            ]
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to review KMS inline policies: {str(e)}"
        }
