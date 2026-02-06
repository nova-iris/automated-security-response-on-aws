# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Enables versioning on an S3 bucket.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_s3():
    return boto3.client("s3", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Enables versioning on an S3 bucket.
    """
    bucket_name = event["BucketName"]

    s3_client = connect_to_s3()

    try:
        # Check current versioning status
        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
        current_status = versioning.get("Status", "Disabled")

        if current_status == "Enabled":
            return {
                "status": "Success",
                "message": f"Versioning is already enabled on bucket {bucket_name}",
            }

        # Enable versioning
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"},
        )

        # Verify
        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
        if versioning.get("Status") == "Enabled":
            return {
                "status": "Success",
                "message": f"Versioning enabled on bucket {bucket_name}",
            }
        else:
            return {
                "status": "FAILED",
                "message": f"Failed to verify versioning on bucket {bucket_name}",
            }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to enable versioning: {str(e)}",
        }
