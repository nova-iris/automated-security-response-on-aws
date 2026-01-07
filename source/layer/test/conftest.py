# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from unittest.mock import patch

import boto3
import pytest
from layer.awsapi_cached_client import AWSCachedClient


@pytest.fixture(scope="module", autouse=True)
def aws_credentials():
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="module", autouse=True)
def test_environment():
    os.environ["SOLUTION_ID"] = "SOTestID"
    os.environ["AWS_ACCOUNT"] = "123456789012"
    os.environ["FINDINGS_TABLE_NAME"] = "test-findings-table"
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"


@pytest.fixture(scope="module", autouse=True)
def mock_get_local_account_id():
    mock = patch.object(
        AWSCachedClient, "_get_local_account_id", return_value="111111111111"
    )
    mock.start()
    yield
    mock.stop()


def create_dynamodb_tables():
    dynamodb = boto3.client("dynamodb", region_name="us-east-1")

    dynamodb.create_table(
        TableName="test-findings-table",
        KeySchema=[
            {"AttributeName": "findingType", "KeyType": "HASH"},
            {"AttributeName": "findingId", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "findingType", "AttributeType": "S"},
            {"AttributeName": "findingId", "AttributeType": "S"},
            {
                "AttributeName": "securityHubUpdatedAtTime#findingId",
                "AttributeType": "S",
            },
            {"AttributeName": "accountId", "AttributeType": "S"},
            {"AttributeName": "resourceId", "AttributeType": "S"},
            {"AttributeName": "severity", "AttributeType": "S"},
            {"AttributeName": "FINDING_CONSTANT", "AttributeType": "S"},
            {
                "AttributeName": "severityNormalized#securityHubUpdatedAtTime#findingId",
                "AttributeType": "S",
            },
        ],
        LocalSecondaryIndexes=[
            {
                "IndexName": "securityHubUpdatedAtTime-findingId-LSI",
                "KeySchema": [
                    {"AttributeName": "findingType", "KeyType": "HASH"},
                    {
                        "AttributeName": "securityHubUpdatedAtTime#findingId",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "accountId-securityHubUpdatedAtTime-GSI",
                "KeySchema": [
                    {"AttributeName": "accountId", "KeyType": "HASH"},
                    {
                        "AttributeName": "securityHubUpdatedAtTime#findingId",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "resourceId-securityHubUpdatedAtTime-GSI",
                "KeySchema": [
                    {"AttributeName": "resourceId", "KeyType": "HASH"},
                    {
                        "AttributeName": "securityHubUpdatedAtTime#findingId",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "severity-securityHubUpdatedAtTime-GSI",
                "KeySchema": [
                    {"AttributeName": "severity", "KeyType": "HASH"},
                    {
                        "AttributeName": "securityHubUpdatedAtTime#findingId",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "allFindings-securityHubUpdatedAtTime-GSI",
                "KeySchema": [
                    {"AttributeName": "FINDING_CONSTANT", "KeyType": "HASH"},
                    {
                        "AttributeName": "securityHubUpdatedAtTime#findingId",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "allFindings-severityNormalized-GSI",
                "KeySchema": [
                    {"AttributeName": "FINDING_CONSTANT", "KeyType": "HASH"},
                    {
                        "AttributeName": "severityNormalized#securityHubUpdatedAtTime#findingId",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    dynamodb.create_table(
        TableName="test-history-table",
        KeySchema=[
            {"AttributeName": "findingType", "KeyType": "HASH"},
            {"AttributeName": "findingId#executionId", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "findingType", "AttributeType": "S"},
            {"AttributeName": "findingId#executionId", "AttributeType": "S"},
            {"AttributeName": "accountId", "AttributeType": "S"},
            {"AttributeName": "lastUpdatedTime#findingId", "AttributeType": "S"},
            {"AttributeName": "userId", "AttributeType": "S"},
            {"AttributeName": "resourceId", "AttributeType": "S"},
            {"AttributeName": "REMEDIATION_CONSTANT", "AttributeType": "S"},
            {"AttributeName": "findingId", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "accountId-lastUpdatedTime-GSI",
                "KeySchema": [
                    {"AttributeName": "accountId", "KeyType": "HASH"},
                    {"AttributeName": "lastUpdatedTime#findingId", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "userId-lastUpdatedTime-GSI",
                "KeySchema": [
                    {"AttributeName": "userId", "KeyType": "HASH"},
                    {"AttributeName": "lastUpdatedTime#findingId", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "resourceId-lastUpdatedTime-GSI",
                "KeySchema": [
                    {"AttributeName": "resourceId", "KeyType": "HASH"},
                    {"AttributeName": "lastUpdatedTime#findingId", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "allRemediations-lastUpdatedTime-GSI",
                "KeySchema": [
                    {"AttributeName": "REMEDIATION_CONSTANT", "KeyType": "HASH"},
                    {"AttributeName": "lastUpdatedTime#findingId", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "findingId-lastUpdatedTime-GSI",
                "KeySchema": [
                    {"AttributeName": "findingId", "KeyType": "HASH"},
                    {"AttributeName": "lastUpdatedTime#findingId", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    waiter = dynamodb.get_waiter("table_exists")
    waiter.wait(TableName="test-findings-table")
    waiter.wait(TableName="test-history-table")

    return dynamodb
