# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Checks and provides remediation steps for enabling MFA for an IAM user.
Note: MFA setup requires user interaction and cannot be fully automated.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_iam():
    return boto3.client("iam", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Checks MFA status and provides remediation guidance.
    """
    iam_user_name = event["iam_user_name"]

    iam_client = connect_to_iam()

    try:
        # Check if MFA is already enabled
        response = iam_client.list_mfa_devices(UserName=iam_user_name)
        mfa_devices = response.get("MFADevices", [])

        if mfa_devices:
            return {
                "status": "SUCCESS",
                "message": f"MFA is already enabled for user {iam_user_name}. "
                          f"MFA devices: {[d['SerialNumber'] for d in mfa_devices]}"
            }

        # MFA is not enabled - provide remediation guidance
        return {
            "status": "MANUAL_REMEDIATION_REQUIRED",
            "message": f"MFA is not enabled for user {iam_user_name}. "
                      "MFA setup requires user interaction.",
            "remediation_steps": [
                f"1. Sign in to AWS Console as user {iam_user_name}",
                "2. Navigate to IAM > Users > Security credentials",
                "3. In the Multi-factor authentication section, click 'Assign MFA device'",
                "4. Choose the MFA device type (Virtual MFA, Hardware, or Security Key)",
                "5. Follow the setup instructions for the chosen device type",
                "6. Complete MFA registration by entering two consecutive codes"
            ],
            "alternative_steps": [
                "An administrator can create a virtual MFA device for the user:",
                f"   aws iam create-virtual-mfa-device --virtual-mfa-device-name {iam_user_name}-mfa",
                "   Then provide the QR code/secret to the user for setup",
                f"   aws iam enable-mfa-device --user-name {iam_user_name} --serial-number <mfa-serial> --authentication-code1 <code1> --authentication-code2 <code2>"
            ],
            "note": "The user must complete MFA setup themselves for virtual/hardware MFA devices"
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to check MFA status: {str(e)}"
        }
