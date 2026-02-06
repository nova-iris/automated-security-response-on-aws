# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Changes the port of an RDS database instance.
Note: This operation requires application updates and causes downtime.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_rds():
    return boto3.client("rds", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Changes the port of an RDS database instance.
    """
    db_instance_identifier = event["db_instance_identifier"]
    new_port = event["new_port"]

    rds_client = connect_to_rds()

    try:
        # Get current instance info
        response = rds_client.describe_db_instances(
            DBInstanceIdentifier=db_instance_identifier
        )
        
        if not response.get("DBInstances"):
            return {
                "status": "FAILED",
                "message": f"RDS instance {db_instance_identifier} not found"
            }

        instance = response["DBInstances"][0]
        current_port = instance.get("Endpoint", {}).get("Port")
        engine = instance.get("Engine")

        # Check if port is already correct
        if current_port == new_port:
            return {
                "status": "SUCCESS",
                "message": f"RDS instance {db_instance_identifier} is already using port {new_port}"
            }

        # Modify the instance port
        rds_client.modify_db_instance(
            DBInstanceIdentifier=db_instance_identifier,
            DBPortNumber=new_port,
            ApplyImmediately=True
        )

        return {
            "status": "SUCCESS",
            "message": f"Port change initiated for RDS instance {db_instance_identifier} from {current_port} to {new_port}. "
                      "WARNING: This will cause a brief outage. "
                      "Ensure all applications are updated to use the new port.",
            "warnings": [
                "Database will be briefly unavailable during port change",
                f"Update all applications to connect to port {new_port}",
                "Update security group rules if necessary",
                "Test connectivity after change completes"
            ]
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to change RDS port: {str(e)}"
        }
