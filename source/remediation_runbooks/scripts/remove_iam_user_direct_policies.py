# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Removes directly attached IAM policies from an IAM user.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_iam():
    return boto3.client("iam", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Removes directly attached IAM policies from an IAM user.
    """
    iam_user_name = event["iam_user_name"]

    iam_client = connect_to_iam()
    removed_policies = []
    errors = []

    try:
        # Remove attached managed policies
        paginator = iam_client.get_paginator("list_attached_user_policies")
        for page in paginator.paginate(UserName=iam_user_name):
            for policy in page.get("AttachedPolicies", []):
                try:
                    iam_client.detach_user_policy(
                        UserName=iam_user_name,
                        PolicyArn=policy["PolicyArn"]
                    )
                    removed_policies.append(f"Detached: {policy['PolicyArn']}")
                except Exception as e:
                    errors.append(f"Failed to detach {policy['PolicyArn']}: {str(e)}")

        # Remove inline policies
        paginator = iam_client.get_paginator("list_user_policies")
        for page in paginator.paginate(UserName=iam_user_name):
            for policy_name in page.get("PolicyNames", []):
                try:
                    iam_client.delete_user_policy(
                        UserName=iam_user_name,
                        PolicyName=policy_name
                    )
                    removed_policies.append(f"Deleted inline: {policy_name}")
                except Exception as e:
                    errors.append(f"Failed to delete inline {policy_name}: {str(e)}")

        if errors:
            return {
                "status": "PARTIAL",
                "message": f"Removed policies: {removed_policies}. Errors: {errors}"
            }
        
        if not removed_policies:
            return {
                "status": "SUCCESS",
                "message": f"No direct policies found on user {iam_user_name}"
            }

        return {
            "status": "SUCCESS",
            "message": f"Removed direct policies from user {iam_user_name}: {removed_policies}"
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to remove direct policies: {str(e)}"
        }
