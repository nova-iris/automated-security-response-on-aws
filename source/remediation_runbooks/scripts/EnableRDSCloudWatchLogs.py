# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Enables CloudWatch Logs publishing for an RDS DB instance.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_rds():
    return boto3.client("rds", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Enables CloudWatch Logs exports for an RDS DB instance.
    Determines the appropriate log types based on the DB engine.
    """
    db_instance_identifier = event["DBInstanceIdentifier"]

    rds_client = connect_to_rds()

    try:
        # Get DB instance details
        response = rds_client.describe_db_instances(
            DBInstanceIdentifier=db_instance_identifier
        )

        if not response.get("DBInstances"):
            return {
                "status": "FAILED",
                "message": f"RDS instance {db_instance_identifier} not found",
            }

        instance = response["DBInstances"][0]
        engine = instance.get("Engine", "").lower()
        current_exports = instance.get("EnabledCloudwatchLogsExports", [])

        # Determine log types based on engine
        log_types = _get_log_types_for_engine(engine)

        if not log_types:
            return {
                "status": "FAILED",
                "message": f"Unsupported engine type: {engine}",
            }

        # Find which logs need to be enabled
        logs_to_enable = [lt for lt in log_types if lt not in current_exports]

        if not logs_to_enable:
            return {
                "status": "Success",
                "message": f"All applicable logs already enabled for {db_instance_identifier}",
            }

        # Enable CloudWatch logs
        rds_client.modify_db_instance(
            DBInstanceIdentifier=db_instance_identifier,
            CloudwatchLogsExportConfiguration={
                "EnableLogTypes": logs_to_enable,
            },
            ApplyImmediately=True,
        )

        return {
            "status": "Success",
            "message": f"CloudWatch logs enabled on RDS instance {db_instance_identifier}: {', '.join(logs_to_enable)}",
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to enable CloudWatch logs: {str(e)}",
        }


def _get_log_types_for_engine(engine):
    """Returns the appropriate log types for the given RDS engine."""
    engine_log_map = {
        "mysql": ["audit", "error", "general", "slowquery"],
        "mariadb": ["audit", "error", "general", "slowquery"],
        "postgres": ["postgresql", "upgrade"],
        "oracle-ee": ["alert", "audit", "listener", "trace"],
        "oracle-se2": ["alert", "audit", "listener", "trace"],
        "oracle-ee-cdb": ["alert", "audit", "listener", "trace"],
        "oracle-se2-cdb": ["alert", "audit", "listener", "trace"],
        "sqlserver-ee": ["agent", "error"],
        "sqlserver-se": ["agent", "error"],
        "sqlserver-ex": ["agent", "error"],
        "sqlserver-web": ["agent", "error"],
    }

    for key, value in engine_log_map.items():
        if engine.startswith(key):
            return value

    return []
