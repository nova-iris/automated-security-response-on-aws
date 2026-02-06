# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Enables cross-region replication on an S3 bucket.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_s3():
    return boto3.client("s3", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Enables cross-region replication on an S3 bucket.
    """
    bucket_name = event["bucket_name"]
    destination_bucket_arn = event["destination_bucket_arn"]
    replication_role_arn = event["replication_role_arn"]

    s3_client = connect_to_s3()

    # First, ensure versioning is enabled (required for replication)
    try:
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"}
        )
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to enable versioning on bucket {bucket_name}: {str(e)}"
        }

    # Configure replication
    replication_config = {
        "Role": replication_role_arn,
        "Rules": [
            {
                "ID": "ASR-CrossRegionReplication",
                "Status": "Enabled",
                "Priority": 1,
                "DeleteMarkerReplication": {"Status": "Disabled"},
                "Filter": {"Prefix": ""},
                "Destination": {
                    "Bucket": destination_bucket_arn,
                    "ReplicaModifications": {"Status": "Enabled"},
                }
            }
        ]
    }

    try:
        s3_client.put_bucket_replication(
            Bucket=bucket_name,
            ReplicationConfiguration=replication_config
        )
        return {
            "status": "SUCCESS",
            "message": f"Cross-region replication enabled on bucket {bucket_name} to {destination_bucket_arn}"
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to enable cross-region replication: {str(e)}"
        }
