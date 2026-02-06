# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Enables logging on a WAF Web ACL.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_wafv2():
    return boto3.client("wafv2", config=BOTO_CONFIG)


def connect_to_logs():
    return boto3.client("logs", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Enables logging on a WAF Web ACL.
    """
    web_acl_arn = event["web_acl_arn"]
    log_destination_configs = event.get("log_destination_configs", "")

    waf_client = connect_to_wafv2()
    logs_client = connect_to_logs()

    try:
        # Check if logging is already enabled
        try:
            existing_config = waf_client.get_logging_configuration(
                ResourceArn=web_acl_arn
            )
            if existing_config.get("LoggingConfiguration"):
                return {
                    "status": "SUCCESS",
                    "message": f"Logging already enabled on Web ACL {web_acl_arn}"
                }
        except waf_client.exceptions.WAFNonexistentItemException:
            pass  # No logging configuration exists, proceed to create one

        # If no log destination provided, create a CloudWatch log group
        if not log_destination_configs:
            # Extract Web ACL name from ARN
            web_acl_name = web_acl_arn.split("/")[-2]
            log_group_name = f"aws-waf-logs-{web_acl_name}"
            
            try:
                logs_client.create_log_group(logGroupName=log_group_name)
            except logs_client.exceptions.ResourceAlreadyExistsException:
                pass  # Log group already exists

            # Get log group ARN
            response = logs_client.describe_log_groups(
                logGroupNamePrefix=log_group_name
            )
            for lg in response.get("logGroups", []):
                if lg["logGroupName"] == log_group_name:
                    log_destination_configs = lg["arn"]
                    break

        # Enable logging
        waf_client.put_logging_configuration(
            LoggingConfiguration={
                "ResourceArn": web_acl_arn,
                "LogDestinationConfigs": [log_destination_configs]
            }
        )

        return {
            "status": "SUCCESS",
            "message": f"Logging enabled on Web ACL {web_acl_arn} to {log_destination_configs}"
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to enable WAF logging: {str(e)}"
        }
