# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Enables access logging on API Gateway stages.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_apigatewayv2():
    return boto3.client("apigatewayv2", config=BOTO_CONFIG)


def connect_to_logs():
    return boto3.client("logs", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Enables access logging on API Gateway stages.
    """
    api_id = event["api_id"]
    stage_name = event["stage_name"]
    log_group_arn = event.get("log_group_arn", "")

    apigw_client = connect_to_apigatewayv2()
    logs_client = connect_to_logs()

    try:
        # Check current stage configuration
        stage = apigw_client.get_stage(ApiId=api_id, StageName=stage_name)
        
        current_logging = stage.get("AccessLogSettings", {})
        if current_logging.get("DestinationArn"):
            return {
                "status": "SUCCESS",
                "message": f"Access logging already enabled on stage {stage_name}: {current_logging.get('DestinationArn')}"
            }

        # If no log group ARN provided, create a new log group
        if not log_group_arn:
            log_group_name = f"/aws/apigateway/{api_id}/{stage_name}"
            
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
                    log_group_arn = lg["arn"]
                    break

        # Enable access logging
        log_format = '{"requestId":"$context.requestId","ip":"$context.identity.sourceIp","requestTime":"$context.requestTime","httpMethod":"$context.httpMethod","routeKey":"$context.routeKey","status":"$context.status","protocol":"$context.protocol","responseLength":"$context.responseLength"}'
        
        apigw_client.update_stage(
            ApiId=api_id,
            StageName=stage_name,
            AccessLogSettings={
                "DestinationArn": log_group_arn,
                "Format": log_format
            }
        )

        return {
            "status": "SUCCESS",
            "message": f"Access logging enabled on stage {stage_name} to {log_group_arn}"
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to enable access logging: {str(e)}"
        }
