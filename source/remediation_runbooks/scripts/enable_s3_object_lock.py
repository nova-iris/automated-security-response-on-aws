# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Checks and provides remediation steps for S3 Object Lock.
Note: Object Lock cannot be enabled on existing buckets.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_s3():
    return boto3.client("s3", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Checks Object Lock status and provides remediation guidance.
    """
    bucket_name = event["bucket_name"]

    s3_client = connect_to_s3()

    try:
        # Check if Object Lock is enabled
        try:
            response = s3_client.get_object_lock_configuration(Bucket=bucket_name)
            if response.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled":
                return {
                    "status": "SUCCESS",
                    "message": f"Object Lock is already enabled on bucket {bucket_name}"
                }
        except s3_client.exceptions.ObjectLockConfigurationNotFoundError:
            pass

        # Object Lock is not enabled - provide remediation guidance
        return {
            "status": "MANUAL_REMEDIATION_REQUIRED",
            "message": f"Object Lock cannot be enabled on existing bucket {bucket_name}. "
                      "To remediate this finding, you must: "
                      "1. Create a new bucket with Object Lock enabled "
                      "2. Copy all objects from the original bucket to the new bucket "
                      "3. Update applications to use the new bucket "
                      "4. Delete the original bucket (after verifying data migration)",
            "remediation_steps": [
                f"aws s3api create-bucket --bucket {bucket_name}-new --object-lock-enabled-for-bucket",
                f"aws s3 sync s3://{bucket_name} s3://{bucket_name}-new",
                "Update application configuration to use the new bucket",
                f"aws s3 rb s3://{bucket_name} --force (after verification)"
            ]
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to check Object Lock status: {str(e)}"
        }
