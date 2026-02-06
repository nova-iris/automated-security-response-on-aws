# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Sets lifecycle policy on a versioned S3 bucket to manage noncurrent object versions.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_s3():
    return boto3.client("s3", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Configures lifecycle policy for noncurrent versions on a versioned S3 bucket.
    """
    bucket_name = event["BucketName"]
    noncurrent_days = int(event.get("NoncurrentDays", 90))
    noncurrent_transition_days = int(event.get("NoncurrentTransitionDays", 30))

    s3_client = connect_to_s3()

    try:
        # Verify versioning is enabled
        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
        if versioning.get("Status") != "Enabled":
            return {
                "status": "FAILED",
                "message": f"Bucket {bucket_name} does not have versioning enabled. Enable versioning first.",
            }

        # Check for existing lifecycle configuration
        existing_rules = []
        try:
            existing_config = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            existing_rules = existing_config.get("Rules", [])
        except s3_client.exceptions.ClientError as e:
            if "NoSuchLifecycleConfiguration" not in str(e):
                raise

        # Add noncurrent version management rule
        new_rule = {
            "ID": "ASR-S3.10-NoncurrentVersionManagement",
            "Status": "Enabled",
            "Filter": {"Prefix": ""},
            "NoncurrentVersionTransitions": [
                {
                    "NoncurrentDays": noncurrent_transition_days,
                    "StorageClass": "STANDARD_IA",
                }
            ],
            "NoncurrentVersionExpiration": {
                "NoncurrentDays": noncurrent_days,
            },
        }

        # Remove any existing ASR rule with same ID
        existing_rules = [r for r in existing_rules if r.get("ID") != "ASR-S3.10-NoncurrentVersionManagement"]
        existing_rules.append(new_rule)

        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration={"Rules": existing_rules},
        )

        return {
            "status": "Success",
            "message": f"Lifecycle policy configured on versioned bucket {bucket_name}. "
            f"Noncurrent versions transition to STANDARD_IA after {noncurrent_transition_days} days "
            f"and expire after {noncurrent_days} days.",
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to set lifecycle policy: {str(e)}",
        }
