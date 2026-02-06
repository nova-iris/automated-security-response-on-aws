# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Enables server-side encryption on a Kinesis Data Firehose delivery stream.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_firehose():
    return boto3.client("firehose", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Enables encryption on a Firehose delivery stream.
    """
    delivery_stream_name = event["delivery_stream_name"]
    key_type = event.get("key_type", "AWS_OWNED_CMK")

    firehose_client = connect_to_firehose()

    try:
        # Get current stream configuration
        response = firehose_client.describe_delivery_stream(
            DeliveryStreamName=delivery_stream_name
        )
        
        stream_description = response.get("DeliveryStreamDescription", {})
        
        # Check if encryption is already enabled
        encryption_config = stream_description.get("DeliveryStreamEncryptionConfiguration", {})
        if encryption_config.get("Status") == "ENABLED":
            return {
                "status": "SUCCESS",
                "message": f"Encryption already enabled on stream {delivery_stream_name}"
            }

        # Enable encryption
        firehose_client.start_delivery_stream_encryption(
            DeliveryStreamName=delivery_stream_name,
            DeliveryStreamEncryptionConfigurationInput={
                "KeyType": key_type
            }
        )

        return {
            "status": "SUCCESS",
            "message": f"Encryption ({key_type}) enabled on stream {delivery_stream_name}"
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to enable encryption: {str(e)}"
        }
