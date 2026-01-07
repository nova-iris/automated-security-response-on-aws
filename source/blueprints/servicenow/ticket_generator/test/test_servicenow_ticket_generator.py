# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import re
import urllib.error
from unittest.mock import MagicMock, patch

import boto3
from aws_lambda_context import LambdaContext
from botocore.config import Config
from moto import mock_aws
from servicenow_ticket_generator import (
    ProjectInfo,
    RemediationInfo,
    create_ticket,
    get_account_alias,
    get_api_credentials,
    get_post_endpoint_from_project_info,
    lambda_handler,
)

REGION = "us-east-1"
FAKE_API_CREDENTIALS = {"API_Key": "my-api-key"}
FAKE_INSTANCE_URI = "https://my-instance.service-now.com"
FAKE_SERVICENOW_ENDPOINT = f"{FAKE_INSTANCE_URI}/api/now/table/"
TABLE_NAME = "incident"
MOTO_ACCOUNT_ID = "123456789012"

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")


def setup():
    client = boto3.client("secretsmanager", config=BOTO_CONFIG)
    response = client.create_secret(
        Name="my_new_secret",
        SecretString=json.dumps(FAKE_API_CREDENTIALS),
    )

    client = boto3.client("organizations", region_name="us-east-1")
    client.create_organization(FeatureSet="ALL")

    os.environ["SECRET_ARN"] = response["ARN"]
    os.environ["INSTANCE_URI"] = FAKE_INSTANCE_URI
    os.environ["TABLE_NAME"] = TABLE_NAME


def setup_lambda_context():
    lambda_context = LambdaContext()
    lambda_context.function_name = "function_name"
    lambda_context.function_version = "function_version"
    lambda_context.invoked_function_arn = "invoked_function_arn"
    lambda_context.memory_limit_in_mb = 2
    lambda_context.aws_request_id = "aws_request_id"
    lambda_context.log_group_name = "log_group_name"
    lambda_context.log_stream_name = "log_stream_name"
    return lambda_context


@patch("urllib.request.urlopen")
@mock_aws
def test_ticket_generator(mock_urlopen):
    # ARRANGE
    setup()
    lambda_context = setup_lambda_context()
    mock_response = MagicMock()
    mock_response.__enter__.return_value = mock_response
    mock_response.getcode.return_value = 201
    mock_response.read.return_value = json.dumps(
        {"result": {"sys_id": "system-id"}}
    ).encode("utf-8")
    mock_urlopen.return_value = mock_response

    # ACT
    response = lambda_handler(
        {
            "RemediationInfo": {
                "Message": "my message",
                "FindingDescription": "this is a finding",
                "FindingSeverity": "LOW",
                "SecurityControlId": "foobar.1",
                "FindingAccountId": MOTO_ACCOUNT_ID,
                "AffectedResource": "my-s3-bucket",
            },
        },
        lambda_context,
    )

    # ASSERT
    assert response["ResponseCode"] == "201"
    assert (
        response["TicketURL"]
        == f"{FAKE_INSTANCE_URI}/nav_to.do?uri={TABLE_NAME}.do?sys_id=system-id"
    )
    assert response["Ok"]


@patch("urllib.request.urlopen")
@mock_aws
def test_ticket_generator_servicenow_error(mock_urlopen):
    # ARRANGE
    setup()
    lambda_context = setup_lambda_context()
    mock_urlopen.side_effect = urllib.error.HTTPError(
        FAKE_SERVICENOW_ENDPOINT, 400, "Bad Request", {}, None  # type: ignore
    )

    # ACT
    response = lambda_handler(
        {
            "RemediationInfo": {
                "Message": "my message",
                "FindingDescription": "this is a finding",
                "FindingSeverity": "LOW",
                "SecurityControlId": "foobar.1",
                "FindingAccountId": MOTO_ACCOUNT_ID,
                "AffectedResource": "my-s3-bucket",
            },
        },
        lambda_context,
    )

    # ASSERT
    assert not response["Ok"]
    assert response["ResponseCode"] == "400"
    assert response["ResponseReason"] == "Bad Request"


@mock_aws
def test_ticket_generator_without_secret():
    # ARRANGE
    lambda_context = setup_lambda_context()
    os.environ["SECRET_ARN"] = "my-secret-arn"

    # ACT
    response = lambda_handler(
        {
            "RemediationInfo": {
                "Message": "my message",
                "FindingDescription": "this is a finding",
                "FindingSeverity": "LOW",
                "SecurityControlId": "foobar.1",
                "FindingAccountId": MOTO_ACCOUNT_ID,
                "AffectedResource": "my-s3-bucket",
            },
        },
        lambda_context,
    )

    # ASSERT
    assert not response["Ok"]
    assert response["ResponseCode"] == "Error"
    assert re.search(
        r"Could not retrieve value stored in secret ", response["ResponseReason"]
    )


def test_ticket_generator_with_invalid_uri():
    # ARRANGE
    lambda_context = setup_lambda_context()
    os.environ["INSTANCE_URI"] = "https://example.com"
    os.environ["PROJECT_NAME"] = "MP"

    # ACT
    response = lambda_handler(
        {
            "RemediationInfo": {
                "Message": "my message",
                "FindingDescription": "this is a finding",
                "FindingSeverity": "LOW",
                "SecurityControlId": "foobar.1",
                "FindingAccountId": MOTO_ACCOUNT_ID,
                "AffectedResource": "my-s3-bucket",
            },
        },
        lambda_context,
    )

    # ASSERT
    assert not response["Ok"]
    assert response["ResponseCode"] == "Error"
    assert re.search(
        r"ServiceNow Instance URI https://example.com does not match expected structure",
        response["ResponseReason"],
    )


@mock_aws
def test_get_account_alias():
    client = boto3.client("organizations", region_name="us-east-1")
    client.create_organization(FeatureSet="ALL")

    account_alias = get_account_alias(MOTO_ACCOUNT_ID)

    assert account_alias == "master"


@mock_aws
def test_get_account_alias_error():
    account_alias = get_account_alias(MOTO_ACCOUNT_ID)

    assert account_alias == MOTO_ACCOUNT_ID


def test_get_post_endpoint_from_project_info():
    # ARRANGE
    project_info: ProjectInfo = {
        "InstanceURI": "https://test.service-now.com",
        "TableName": "incident",
    }

    # ACT
    result = get_post_endpoint_from_project_info(project_info)

    # ASSERT
    assert result == "https://test.service-now.com/api/now/table/incident"


def test_get_post_endpoint_invalid_uri():
    # ARRANGE
    project_info: ProjectInfo = {
        "InstanceURI": "https://invalid.com",
        "TableName": "incident",
    }

    # ACT & ASSERT
    try:
        get_post_endpoint_from_project_info(project_info)
        assert False, "Expected RuntimeError"
    except RuntimeError:
        pass


@patch("servicenow_ticket_generator.get_secret_value_cached")
def test_get_api_credentials(mock_get_secret):
    # ARRANGE
    mock_get_secret.return_value = '{"API_Key": "test-key"}'

    # ACT
    result = get_api_credentials("test-arn")

    # ASSERT
    assert result == "test-key"


@patch("servicenow_ticket_generator.get_secret_value_cached")
def test_get_api_credentials_missing_key(mock_get_secret):
    # ARRANGE
    mock_get_secret.return_value = "{}"

    # ACT & ASSERT
    try:
        get_api_credentials("test-arn")
        assert False, "Expected RuntimeError"
    except RuntimeError:
        pass


@patch("servicenow_ticket_generator.connect_to_service")
def test_get_account_alias_with_connect_mock(mock_connect):
    # ARRANGE
    mock_org = MagicMock()
    mock_org.describe_account.return_value = {"Account": {"Name": "TestAccount"}}
    mock_connect.return_value = mock_org

    # ACT
    result = get_account_alias("123456789012")

    # ASSERT
    assert result == "TestAccount"


@patch("servicenow_ticket_generator.connect_to_service")
def test_get_account_alias_error_with_connect_mock(mock_connect):
    # ARRANGE
    mock_connect.side_effect = Exception("Error")

    # ACT
    result = get_account_alias("123456789012")

    # ASSERT
    assert result == "123456789012"


@patch("urllib.request.urlopen")
def test_create_ticket_success(mock_urlopen):
    # ARRANGE
    mock_response = MagicMock()
    mock_response.__enter__.return_value = mock_response
    mock_response.getcode.return_value = 201
    mock_response.read.return_value = json.dumps(
        {"result": {"sys_id": "test-id"}}
    ).encode("utf-8")
    mock_urlopen.return_value = mock_response

    remediation_info: RemediationInfo = {
        "Message": "Test",
        "FindingDescription": "Test",
        "FindingSeverity": "HIGH",
        "SecurityControlId": "TEST.1",
        "FindingAccountId": "123456789012",
        "AffectedResource": "test",
    }
    project_info: ProjectInfo = {
        "InstanceURI": "https://test.service-now.com",
        "TableName": "incident",
    }

    # ACT
    result = create_ticket(
        remediation_info,
        project_info,
        "https://test.service-now.com/api/now/table/incident",
        "test-key",
        "TestAccount",
    )

    # ASSERT
    assert result["Ok"] is True
    assert "test-id" in result["TicketURL"]
