# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Configures a dead-letter queue (DLQ) for a Lambda function.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_lambda():
    return boto3.client("lambda", config=BOTO_CONFIG)


def connect_to_sqs():
    return boto3.client("sqs", config=BOTO_CONFIG)


def connect_to_sts():
    return boto3.client("sts", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Configures a DLQ for a Lambda function.
    """
    function_name = event["function_name"]
    dlq_target_arn = event.get("dlq_target_arn", "")

    lambda_client = connect_to_lambda()
    sqs_client = connect_to_sqs()
    sts_client = connect_to_sts()

    try:
        # Get current function configuration
        function_config = lambda_client.get_function_configuration(
            FunctionName=function_name
        )

        # Check if DLQ is already configured
        current_dlq = function_config.get("DeadLetterConfig", {}).get("TargetArn", "")
        if current_dlq:
            return {
                "status": "SUCCESS",
                "message": f"DLQ already configured on function {function_name}: {current_dlq}"
            }

        # If no DLQ ARN provided, create a new SQS queue
        if not dlq_target_arn:
            account_id = sts_client.get_caller_identity()["Account"]
            region = sqs_client.meta.region_name
            queue_name = f"{function_name}-dlq"
            
            try:
                response = sqs_client.create_queue(
                    QueueName=queue_name,
                    Attributes={
                        "MessageRetentionPeriod": "1209600",  # 14 days
                        "VisibilityTimeout": "300"
                    }
                )
                queue_url = response["QueueUrl"]
                
                # Get the queue ARN
                queue_attrs = sqs_client.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=["QueueArn"]
                )
                dlq_target_arn = queue_attrs["Attributes"]["QueueArn"]
            except sqs_client.exceptions.QueueNameExists:
                # Queue already exists, get its ARN
                queue_url = sqs_client.get_queue_url(QueueName=queue_name)["QueueUrl"]
                queue_attrs = sqs_client.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=["QueueArn"]
                )
                dlq_target_arn = queue_attrs["Attributes"]["QueueArn"]

        # Configure the DLQ on the Lambda function
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            DeadLetterConfig={
                "TargetArn": dlq_target_arn
            }
        )

        return {
            "status": "SUCCESS",
            "message": f"DLQ configured on function {function_name}: {dlq_target_arn}"
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to configure DLQ: {str(e)}"
        }
