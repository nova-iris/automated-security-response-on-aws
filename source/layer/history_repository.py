# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Optional, cast

from layer.findings_repository import build_update_item as build_finding_update_item
from layer.powertools_logger import get_logger

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.client import DynamoDBClient
    from mypy_boto3_dynamodb.type_defs import TransactWriteItemTypeDef
else:
    DynamoDBClient = object
    TransactWriteItemTypeDef = dict[str, Any]

logger = get_logger("history_repository")

FINDING_ID_EXECUTION_ID_KEY = "findingId#executionId"
SORT_KEY_ATTRIBUTE_NAME = "#sortKey"


@dataclass
class RemediationUpdateRequest:
    finding_id: str
    execution_id: str
    remediation_status: str
    finding_type: str
    error: Optional[str] = None
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    account_id: Optional[str] = None
    severity: Optional[str] = None
    region: Optional[str] = None
    lastUpdatedBy: Optional[str] = "Automated"

    def validate(self) -> bool:
        if not self.finding_id or not self.execution_id or not self.finding_type:
            logger.error(
                "Missing required parameters",
                extra={
                    "findingId": self.finding_id,
                    "executionId": self.execution_id,
                    "findingType": self.finding_type,
                },
            )
            return False

        return True


def calculate_ttl_timestamp(timestamp: str) -> int:
    ttl_days = int(os.getenv("HISTORY_TTL_DAYS", "365"))
    dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    ttl_dt = dt + timedelta(days=ttl_days)
    return int(ttl_dt.timestamp())


def build_create_item(
    request: RemediationUpdateRequest,
    extra_fields: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    timestamp = datetime.utcnow().isoformat() + "Z"
    sort_key = f"{request.finding_id}#{request.execution_id}"

    item = {
        "findingType": {"S": request.finding_type},
        "findingId": {"S": request.finding_id},
        FINDING_ID_EXECUTION_ID_KEY: {"S": sort_key},
        "executionId": {"S": request.execution_id},
        "remediationStatus": {"S": request.remediation_status},
        "lastUpdatedTime": {"S": timestamp},
        "lastUpdatedTime#findingId": {"S": f"{timestamp}#{request.finding_id}"},
        "REMEDIATION_CONSTANT": {"S": "remediation"},
        "lastUpdatedBy": {"S": request.lastUpdatedBy or "Automated"},
        "expireAt": {"N": str(calculate_ttl_timestamp(timestamp))},
    }

    # Only add GSI key attributes if they have non-empty values to avoid ValidationException
    if request.account_id:
        item["accountId"] = {"S": request.account_id}
    if request.resource_id:
        item["resourceId"] = {"S": request.resource_id}
    if request.resource_type:
        item["resourceType"] = {"S": request.resource_type}
    if request.severity:
        item["severity"] = {"S": request.severity}
    if request.region:
        item["region"] = {"S": request.region}

    if request.error:
        item["error"] = {"S": request.error}

    if extra_fields:
        for field, value in extra_fields.items():
            item[field] = {"S": value}

    return {
        "Put": {
            "TableName": os.getenv("HISTORY_TABLE_NAME", ""),
            "Item": item,
            "ConditionExpression": "attribute_not_exists(findingType) AND attribute_not_exists(#sortKey)",
            "ExpressionAttributeNames": {
                SORT_KEY_ATTRIBUTE_NAME: FINDING_ID_EXECUTION_ID_KEY
            },
        }
    }


def build_update_item(
    finding_id: str,
    execution_id: str,
    remediation_status: str,
    finding_type: str,
    error: Optional[str] = None,
) -> dict[str, Any]:
    update_expression = "SET remediationStatus = :rs"
    expression_values = {
        ":rs": {"S": remediation_status},
    }
    expression_names = {}

    if error:
        update_expression += ", #err = :err"
        expression_names["#err"] = "error"
        expression_values[":err"] = {"S": error}

    sort_key = f"{finding_id}#{execution_id}"

    history_update_item: dict[str, Any] = {
        "Update": {
            "TableName": os.getenv("HISTORY_TABLE_NAME", ""),
            "Key": {
                "findingType": {"S": finding_type},
                FINDING_ID_EXECUTION_ID_KEY: {"S": sort_key},
            },
            "UpdateExpression": update_expression,
            "ExpressionAttributeValues": expression_values,
            "ConditionExpression": "attribute_exists(findingType) AND attribute_exists(#sortKey)",
        }
    }

    if expression_names:
        expression_names[SORT_KEY_ATTRIBUTE_NAME] = FINDING_ID_EXECUTION_ID_KEY
    else:
        expression_names = {SORT_KEY_ATTRIBUTE_NAME: FINDING_ID_EXECUTION_ID_KEY}

    history_update_item["Update"]["ExpressionAttributeNames"] = expression_names

    return history_update_item


def transact_update_finding_and_history(
    dynamodb: "DynamoDBClient",
    finding_type: str,
    finding_id: str,
    execution_id: str,
    remediation_status: str,
    error: Optional[str] = None,
) -> None:
    transact_items = [
        build_finding_update_item(
            finding_type,
            finding_id,
            remediation_status,
            execution_id,
            error,
        ),
        build_update_item(
            finding_id,
            execution_id,
            remediation_status,
            finding_type,
            error,
        ),
    ]

    dynamodb.transact_write_items(
        TransactItems=cast(list["TransactWriteItemTypeDef"], transact_items)
    )


def transact_create_history_and_update_finding(
    dynamodb: "DynamoDBClient",
    request: RemediationUpdateRequest,
    extra_fields: Optional[dict[str, str]] = None,
    include_finding_update: bool = True,
) -> None:
    transact_items = []

    if include_finding_update:
        transact_items.append(
            build_finding_update_item(
                request.finding_type,
                request.finding_id,
                request.remediation_status,
                request.execution_id,
                request.error,
            )
        )

    transact_items.append(build_create_item(request, extra_fields))

    dynamodb.transact_write_items(
        TransactItems=cast(list["TransactWriteItemTypeDef"], transact_items)
    )
