# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Sets lifecycle policy on an ECR repository.
"""
import json
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_ecr():
    return boto3.client("ecr", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Configures lifecycle policy on an ECR repository to retain
    a limited number of images and clean up untagged images.
    """
    repository_name = event["RepositoryName"]

    ecr_client = connect_to_ecr()

    try:
        # Check if lifecycle policy already exists
        try:
            existing = ecr_client.get_lifecycle_policy(repositoryName=repository_name)
            if existing.get("lifecyclePolicyText"):
                return {
                    "status": "Success",
                    "message": f"Lifecycle policy already exists on repository {repository_name}",
                }
        except ecr_client.exceptions.LifecyclePolicyNotFoundException:
            pass

        # Define lifecycle policy
        lifecycle_policy = {
            "rules": [
                {
                    "rulePriority": 1,
                    "description": "Remove untagged images older than 14 days",
                    "selection": {
                        "tagStatus": "untagged",
                        "countType": "sinceImagePushed",
                        "countUnit": "days",
                        "countNumber": 14,
                    },
                    "action": {"type": "expire"},
                },
                {
                    "rulePriority": 2,
                    "description": "Keep only last 100 tagged images",
                    "selection": {
                        "tagStatus": "any",
                        "countType": "imageCountMoreThan",
                        "countNumber": 100,
                    },
                    "action": {"type": "expire"},
                },
            ]
        }

        ecr_client.put_lifecycle_policy(
            repositoryName=repository_name,
            lifecyclePolicyText=json.dumps(lifecycle_policy),
        )

        return {
            "status": "Success",
            "message": f"Lifecycle policy set on ECR repository {repository_name}",
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to set lifecycle policy: {str(e)}",
        }
