# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Checks and provides remediation steps for S3 MFA Delete.
Note: MFA Delete can only be enabled by the root account.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_s3():
    return boto3.client("s3", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Checks MFA Delete status and provides remediation guidance.
    """
    bucket_name = event["bucket_name"]

    s3_client = connect_to_s3()

    try:
        # Check current versioning configuration
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        mfa_delete = response.get("MFADelete", "Disabled")
        versioning = response.get("Status", "Disabled")

        if mfa_delete == "Enabled":
            return {
                "status": "SUCCESS",
                "message": f"MFA Delete is already enabled on bucket {bucket_name}"
            }

        # MFA Delete is not enabled - provide remediation guidance
        return {
            "status": "MANUAL_REMEDIATION_REQUIRED",
            "message": f"MFA Delete cannot be enabled automatically on bucket {bucket_name}. "
                      "MFA Delete requires root account credentials and must be enabled via AWS CLI. "
                      "Current versioning status: {versioning}",
            "remediation_steps": [
                "1. Sign in to AWS as the root user",
                "2. Enable MFA on the root account if not already enabled",
                "3. Run the following AWS CLI command with root credentials:",
                f"   aws s3api put-bucket-versioning --bucket {bucket_name} "
                "--versioning-configuration Status=Enabled,MFADelete=Enabled "
                "--mfa 'arn:aws:iam::ACCOUNT_ID:mfa/root-account-mfa-device TOTP_CODE'",
                "4. Replace ACCOUNT_ID with your AWS account ID",
                "5. Replace TOTP_CODE with the current code from your MFA device"
            ],
            "note": "This operation can only be performed by the root account holder"
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to check MFA Delete status: {str(e)}"
        }
