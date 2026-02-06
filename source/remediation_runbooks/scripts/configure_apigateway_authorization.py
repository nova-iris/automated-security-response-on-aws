# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Configures authorization on API Gateway routes.
"""
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_apigatewayv2():
    return boto3.client("apigatewayv2", config=BOTO_CONFIG)


def lambda_handler(event, _):
    """
    Configures authorization on API Gateway routes.
    """
    api_id = event["api_id"]
    authorization_type = event.get("authorization_type", "AWS_IAM")

    apigw_client = connect_to_apigatewayv2()
    updated_routes = []
    errors = []

    try:
        # Get all routes for the API
        paginator = apigw_client.get_paginator("get_routes")
        for page in paginator.paginate(ApiId=api_id):
            for route in page.get("Items", []):
                route_id = route["RouteId"]
                route_key = route.get("RouteKey", "")
                current_auth = route.get("AuthorizationType", "NONE")

                # Skip routes that already have authorization
                if current_auth != "NONE":
                    continue

                try:
                    apigw_client.update_route(
                        ApiId=api_id,
                        RouteId=route_id,
                        AuthorizationType=authorization_type
                    )
                    updated_routes.append(f"{route_key} ({route_id})")
                except Exception as e:
                    errors.append(f"Failed to update route {route_key}: {str(e)}")

        if errors:
            return {
                "status": "PARTIAL",
                "message": f"Updated routes: {updated_routes}. Errors: {errors}"
            }

        if not updated_routes:
            return {
                "status": "SUCCESS",
                "message": f"All routes on API {api_id} already have authorization configured"
            }

        return {
            "status": "SUCCESS",
            "message": f"Authorization ({authorization_type}) configured on routes: {updated_routes}"
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "message": f"Failed to configure authorization: {str(e)}"
        }
