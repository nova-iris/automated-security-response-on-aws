# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Enables EBS encryption by default for the AWS account in the current region.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_ec2():
    return boto3.client("ec2", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Enables EBS encryption by default for the current region.
    """
    ec2_client = connect_to_ec2()

    try:
        # Check current status
        current = ec2_client.get_ebs_encryption_by_default()
        if current.get("EbsEncryptionByDefault", False):
            return {
                "status": "Success",
                "message": "EBS encryption by default is already enabled",
            }

        # Enable EBS encryption by default
        response = ec2_client.enable_ebs_encryption_by_default()

        if response.get("EbsEncryptionByDefault", False):
            return {
                "status": "Success",
                "message": "EBS encryption by default enabled successfully",
            }
        else:
            return {
                "status": "FAILED",
                "message": "Failed to enable EBS encryption by default",
            }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to enable EBS encryption by default: {str(e)}",
        }
