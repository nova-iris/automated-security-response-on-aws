# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Enables IAM authentication on an RDS DB instance.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_rds():
    return boto3.client("rds", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Enables IAM database authentication on an RDS DB instance.
    """
    db_instance_identifier = event["DBInstanceIdentifier"]

    rds_client = connect_to_rds()

    try:
        # Get current instance info
        response = rds_client.describe_db_instances(
            DBInstanceIdentifier=db_instance_identifier
        )

        if not response.get("DBInstances"):
            return {
                "status": "FAILED",
                "message": f"RDS instance {db_instance_identifier} not found",
            }

        instance = response["DBInstances"][0]

        # Check if IAM authentication is already enabled
        if instance.get("IAMDatabaseAuthenticationEnabled", False):
            return {
                "status": "Success",
                "message": f"IAM authentication is already enabled on instance {db_instance_identifier}",
            }

        # Enable IAM authentication
        rds_client.modify_db_instance(
            DBInstanceIdentifier=db_instance_identifier,
            EnableIAMDatabaseAuthentication=True,
            ApplyImmediately=True,
        )

        return {
            "status": "Success",
            "message": f"IAM authentication enabled on RDS instance {db_instance_identifier}",
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to enable IAM authentication: {str(e)}",
        }
