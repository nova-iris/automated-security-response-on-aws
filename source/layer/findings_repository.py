# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from typing import TYPE_CHECKING, Any, Optional, TypedDict

from layer.powertools_logger import get_logger

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.client import DynamoDBClient
else:
    DynamoDBClient = object

logger = get_logger("findings_repository")


class PartialFindingData(TypedDict, total=False):
    """Subset of fields from a Finding table item used for history record creation."""

    accountId: str
    resourceId: str
    resourceType: str
    resourceTypeNormalized: str
    severity: str
    region: str
    lastUpdatedBy: str


def get(
    dynamodb: "DynamoDBClient",
    finding_type: str,
    finding_id: str,
) -> Optional[dict[str, Any]]:
    try:
        response = dynamodb.get_item(
            TableName=os.getenv("FINDINGS_TABLE_NAME", ""),
            Key={
                "findingType": {"S": finding_type},
                "findingId": {"S": finding_id},
            },
        )

        if "Item" not in response:
            return None

        item: dict[str, Any] = response["Item"]
        return item

    except Exception as e:
        logger.warning(
            "Error retrieving finding data",
            extra={
                "findingType": finding_type,
                "findingId": finding_id,
                "error": str(e),
            },
        )
        return None


def build_update_item(
    finding_type: str,
    finding_id: str,
    remediation_status: str,
    execution_id: str,
    error: Optional[str] = None,
) -> dict[str, Any]:
    update_expression = "SET remediationStatus = :rs"
    expression_values = {
        ":rs": {"S": remediation_status},
    }
    expression_names = {}

    if execution_id:
        update_expression += ", executionId = :eid"
        expression_values[":eid"] = {"S": execution_id}

    if error:
        update_expression += ", #err = :err"
        expression_names["#err"] = "error"
        expression_values[":err"] = {"S": error}

    finding_update_item: dict[str, Any] = {
        "Update": {
            "TableName": os.getenv("FINDINGS_TABLE_NAME", ""),
            "Key": {"findingType": {"S": finding_type}, "findingId": {"S": finding_id}},
            "UpdateExpression": update_expression,
            "ExpressionAttributeValues": expression_values,
        }
    }

    if expression_names:
        finding_update_item["Update"]["ExpressionAttributeNames"] = expression_names

    return finding_update_item


def update(
    dynamodb: "DynamoDBClient",
    finding_type: str,
    finding_id: str,
    remediation_status: str,
    execution_id: str,
    error: Optional[str] = None,
) -> None:
    update_item = build_update_item(
        finding_type,
        finding_id,
        remediation_status,
        execution_id,
        error,
    )
    dynamodb.update_item(**update_item["Update"])


def extract_partial_finding_data(item: dict[str, Any]) -> PartialFindingData:
    """Extracts a subset of fields from a Finding DynamoDB item."""
    finding_data: PartialFindingData = {}
    field_mappings = [
        "accountId",
        "resourceId",
        "resourceType",
        "resourceTypeNormalized",
        "severity",
        "region",
        "lastUpdatedBy",
    ]

    for field in field_mappings:
        if field in item:
            finding_data[field] = item[field]["S"]  # type: ignore[literal-required]

    return finding_data
