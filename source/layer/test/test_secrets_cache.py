# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os

import boto3
from layer.secrets_cache import clear_cache, get_secret_value_cached
from moto import mock_aws


@mock_aws
def test_get_secret_value_returns_cached_value_on_subsequent_requests():
    # ARRANGE
    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(Name="test-secret", SecretString='{"key": "value"}')

    # ACT
    result1 = get_secret_value_cached("test-secret")
    client.update_secret(SecretId="test-secret", SecretString='{"key": "new_value"}')
    result2 = get_secret_value_cached("test-secret")

    # ASSERT
    assert result1 == result2 == '{"key": "value"}'

    clear_cache()


@mock_aws
def test_get_secret_value_fetches_fresh_value_after_cache_clear():
    # ARRANGE
    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(Name="test-secret", SecretString='{"key": "value"}')

    # ACT
    result1 = get_secret_value_cached("test-secret")
    clear_cache()
    client.update_secret(SecretId="test-secret", SecretString='{"key": "new_value"}')
    result2 = get_secret_value_cached("test-secret")

    # ASSERT
    assert result1 == '{"key": "value"}'
    assert result2 == '{"key": "new_value"}'

    clear_cache()


@mock_aws
def test_get_secret_value_with_custom_ttl():
    # ARRANGE
    os.environ["SECRETS_CACHE_TTL_SECONDS"] = "0"
    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(Name="test-secret", SecretString='{"key": "value"}')

    # ACT
    result1 = get_secret_value_cached("test-secret")
    client.update_secret(SecretId="test-secret", SecretString='{"key": "new_value"}')
    result2 = get_secret_value_cached("test-secret")

    # ASSERT
    assert result1 == '{"key": "value"}'
    assert result2 == '{"key": "value"}'

    del os.environ["SECRETS_CACHE_TTL_SECONDS"]
    clear_cache()


@mock_aws
def test_get_secret_value_raises_error_for_binary_secret():
    # ARRANGE
    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(Name="test-secret", SecretBinary=b"binary-data")

    # ACT & ASSERT
    try:
        get_secret_value_cached("test-secret")
        assert False, "Expected RuntimeError"
    except RuntimeError as e:
        assert "Missing SecretString in response" in str(e)

    clear_cache()
