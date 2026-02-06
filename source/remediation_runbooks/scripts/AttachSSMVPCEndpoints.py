# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Creates VPC interface endpoints for AWS Systems Manager services.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_ec2():
    return boto3.client("ec2", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Creates VPC endpoints for SSM, SSM Messages, and EC2 Messages
    to enable private connectivity to Systems Manager.
    """
    vpc_id = event["VPCId"]

    ec2_client = connect_to_ec2()

    try:
        # Get region from session
        session = boto3.session.Session()
        region = session.region_name

        # SSM service names
        ssm_services = [
            f"com.amazonaws.{region}.ssm",
            f"com.amazonaws.{region}.ssmmessages",
            f"com.amazonaws.{region}.ec2messages",
        ]

        # Get existing endpoints
        existing_endpoints = ec2_client.describe_vpc_endpoints(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "vpc-endpoint-state", "Values": ["available", "pending"]},
            ]
        )
        existing_services = [
            ep.get("ServiceName", "") for ep in existing_endpoints.get("VpcEndpoints", [])
        ]

        # Get subnets for the VPC
        subnets = ec2_client.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )
        subnet_ids = [s["SubnetId"] for s in subnets.get("Subnets", [])]

        if not subnet_ids:
            return {
                "status": "FAILED",
                "message": f"No subnets found in VPC {vpc_id}",
            }

        # Create a security group for the endpoints
        sg_response = ec2_client.create_security_group(
            GroupName=f"asr-ssm-endpoints-{vpc_id}",
            Description="Security group for SSM VPC endpoints created by ASR",
            VpcId=vpc_id,
        )
        sg_id = sg_response["GroupId"]

        # Get VPC CIDR
        vpc_info = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        vpc_cidr = vpc_info["Vpcs"][0]["CidrBlock"]

        # Allow HTTPS from VPC CIDR
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": vpc_cidr, "Description": "HTTPS from VPC"}],
                }
            ],
        )

        created_endpoints = []
        skipped_endpoints = []

        for service_name in ssm_services:
            if service_name in existing_services:
                skipped_endpoints.append(service_name)
                continue

            try:
                ec2_client.create_vpc_endpoint(
                    VpcEndpointType="Interface",
                    VpcId=vpc_id,
                    ServiceName=service_name,
                    SubnetIds=subnet_ids[:3],  # Use up to 3 subnets
                    SecurityGroupIds=[sg_id],
                    PrivateDnsEnabled=True,
                )
                created_endpoints.append(service_name)
            except Exception as e:
                return {
                    "status": "FAILED",
                    "message": f"Failed to create endpoint for {service_name}: {str(e)}",
                }

        message_parts = []
        if created_endpoints:
            message_parts.append(f"Created endpoints: {', '.join(created_endpoints)}")
        if skipped_endpoints:
            message_parts.append(f"Already existing: {', '.join(skipped_endpoints)}")

        return {
            "status": "Success",
            "message": ". ".join(message_parts) if message_parts else "No endpoints needed.",
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to create SSM VPC endpoints: {str(e)}",
        }
