# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Configures a Lambda function to run in a VPC.
Note: This may affect the function's ability to access internet resources.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_lambda():
    return boto3.client("lambda", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Configures VPC settings for a Lambda function.
    """
    function_name = event["function_name"]
    subnet_ids = event["subnet_ids"]
    security_group_ids = event["security_group_ids"]

    lambda_client = connect_to_lambda()

    try:
        # Get current function configuration
        function_config = lambda_client.get_function_configuration(
            FunctionName=function_name
        )

        # Check if VPC is already configured
        current_vpc = function_config.get("VpcConfig", {})
        if current_vpc.get("SubnetIds"):
            return {
                "status": "SUCCESS",
                "message": f"Lambda function {function_name} is already configured with VPC: "
                          f"Subnets: {current_vpc.get('SubnetIds')}, "
                          f"Security Groups: {current_vpc.get('SecurityGroupIds')}"
            }

        # Configure VPC
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            VpcConfig={
                "SubnetIds": subnet_ids,
                "SecurityGroupIds": security_group_ids
            }
        )

        return {
            "status": "SUCCESS",
            "message": f"VPC configured on Lambda function {function_name}. "
                      f"Subnets: {subnet_ids}, Security Groups: {security_group_ids}",
            "warnings": [
                "Function may lose direct internet access",
                "Consider adding NAT Gateway if internet access is required",
                "Ensure VPC endpoints exist for AWS services the function uses",
                "Test function thoroughly after VPC configuration"
            ]
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to configure VPC: {str(e)}"
        }
