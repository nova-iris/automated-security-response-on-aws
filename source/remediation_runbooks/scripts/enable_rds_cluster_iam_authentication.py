# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Enables IAM authentication on an RDS cluster.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_rds():
    return boto3.client("rds", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Enables IAM database authentication on an RDS cluster.
    """
    db_cluster_identifier = event["db_cluster_identifier"]

    rds_client = connect_to_rds()

    try:
        # Get current cluster info
        response = rds_client.describe_db_clusters(
            DBClusterIdentifier=db_cluster_identifier
        )
        
        if not response.get("DBClusters"):
            return {
                "status": "FAILED",
                "message": f"RDS cluster {db_cluster_identifier} not found"
            }
        
        cluster = response["DBClusters"][0]
        
        # Check if IAM authentication is already enabled
        if cluster.get("IAMDatabaseAuthenticationEnabled", False):
            return {
                "status": "SUCCESS",
                "message": f"IAM authentication is already enabled on cluster {db_cluster_identifier}"
            }

        # Enable IAM authentication
        rds_client.modify_db_cluster(
            DBClusterIdentifier=db_cluster_identifier,
            EnableIAMDatabaseAuthentication=True,
            ApplyImmediately=True
        )
        
        return {
            "status": "SUCCESS",
            "message": f"IAM authentication enabled on RDS cluster {db_cluster_identifier}"
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to enable IAM authentication: {str(e)}"
        }
