# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Updates the runtime of a Lambda function.
Note: Runtime updates may require code changes and testing.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_lambda():
    return boto3.client("lambda", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Updates the runtime of a Lambda function.
    """
    function_name = event["function_name"]
    new_runtime = event["new_runtime"]

    lambda_client = connect_to_lambda()

    try:
        # Get current function configuration
        function_config = lambda_client.get_function_configuration(
            FunctionName=function_name
        )

        current_runtime = function_config.get("Runtime")
        
        # Check if runtime is already correct
        if current_runtime == new_runtime:
            return {
                "status": "SUCCESS",
                "message": f"Lambda function {function_name} is already using runtime {new_runtime}"
            }

        # Update runtime
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            Runtime=new_runtime
        )

        return {
            "status": "SUCCESS",
            "message": f"Runtime updated on Lambda function {function_name} from {current_runtime} to {new_runtime}",
            "warnings": [
                f"Previous runtime: {current_runtime}",
                f"New runtime: {new_runtime}",
                "Test function thoroughly after runtime update",
                "Check for deprecated features or breaking changes",
                "Review Lambda documentation for migration guides"
            ]
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to update runtime: {str(e)}"
        }
