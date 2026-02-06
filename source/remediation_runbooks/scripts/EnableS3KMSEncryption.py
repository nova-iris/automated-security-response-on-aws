# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Configures S3 bucket encryption with AWS KMS (SSE-KMS).
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_s3():
    return boto3.client("s3", config=BOTO_CONFIG)


def connect_to_kms():
    return boto3.client("kms", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Configures S3 bucket default encryption to use AWS KMS.
    """
    bucket_name = event["BucketName"]
    kms_key_arn = event.get("KMSKeyArn", "")

    s3_client = connect_to_s3()

    try:
        # If no KMS key specified, create or use the default aws/s3 key
        if not kms_key_arn:
            kms_client = connect_to_kms()
            # Use the AWS managed key for S3
            aliases = kms_client.list_aliases()
            s3_key_arn = None
            for alias in aliases.get("Aliases", []):
                if alias.get("AliasName") == "alias/aws/s3":
                    s3_key_arn = alias.get("AliasArn")
                    break

            if s3_key_arn:
                kms_key_arn = s3_key_arn
            else:
                return {
                    "status": "FAILED",
                    "message": "No KMS key provided and default aws/s3 key not found.",
                }

        # Configure KMS encryption
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": kms_key_arn,
                        },
                        "BucketKeyEnabled": True,
                    }
                ]
            },
        )

        # Verify
        encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules and rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") == "aws:kms":
            return {
                "status": "Success",
                "message": f"KMS encryption configured on bucket {bucket_name}",
            }
        else:
            return {
                "status": "FAILED",
                "message": f"Failed to verify KMS encryption on bucket {bucket_name}",
            }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to configure KMS encryption: {str(e)}",
        }
