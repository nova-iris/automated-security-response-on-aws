# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Enables image scanning on push for an ECR repository.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_ecr():
    return boto3.client("ecr", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Enables scan on push for an ECR repository.
    """
    repository_name = event["RepositoryName"]

    ecr_client = connect_to_ecr()

    try:
        # Check current scanning configuration
        repos = ecr_client.describe_repositories(repositoryNames=[repository_name])
        if not repos.get("repositories"):
            return {
                "status": "FAILED",
                "message": f"ECR repository {repository_name} not found",
            }

        repo = repos["repositories"][0]
        scan_config = repo.get("imageScanningConfiguration", {})

        if scan_config.get("scanOnPush", False):
            return {
                "status": "Success",
                "message": f"Image scanning already enabled on repository {repository_name}",
            }

        # Enable scan on push
        ecr_client.put_image_scanning_configuration(
            repositoryName=repository_name,
            imageScanningConfiguration={"scanOnPush": True},
        )

        return {
            "status": "Success",
            "message": f"Image scanning enabled on ECR repository {repository_name}",
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to enable image scanning: {str(e)}",
        }
