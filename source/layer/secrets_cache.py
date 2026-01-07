# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Secrets caching for Lambda functions.

This module leverages Lambda's execution environment reuse to cache secrets between invocations.
Global variables persist in memory when Lambda reuses an execution environment (warm start),
allowing subsequent invocations to access cached values without making additional API calls to
Secrets Manager. This reduces both latency and costs associated with KMS decrypt operations.

When Lambda creates a new execution environment (cold start), global variables are initialized
fresh and the cache starts empty. There is no guarantee whether a given invocation will run in
a warm or cold environment, so the code handle both scenarios transparently.
"""

import os
from datetime import datetime, timedelta
from typing import Dict, Tuple, cast

from layer.awsapi_cached_client import AWSCachedClient

secrets_client = None
_secrets_cache: Dict[str, Tuple[str, datetime]] = {}
_cache_ttl = int(os.getenv("SECRETS_CACHE_TTL_SECONDS", "300"))


def get_secrets_client():
    """Get or create cached Secrets Manager client"""
    global secrets_client
    if secrets_client is None:
        secrets_client = AWSCachedClient(
            os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        ).get_connection("secretsmanager")
    return secrets_client


def get_secret_value_cached(secret_arn: str) -> str:
    """
    Get secret value with caching to reduce KMS decrypt calls.
    Caches for 1 hour by default (configurable via SECRETS_CACHE_TTL_SECONDS).

    Args:
        secret_arn: Secret ARN or name

    Returns:
        Secret string value
    """
    now = datetime.now()

    if secret_arn in _secrets_cache:
        value, expiry = _secrets_cache[secret_arn]
        if now < expiry:
            return value

    client = get_secrets_client()
    response = client.get_secret_value(SecretId=secret_arn)

    if "SecretString" not in response:
        raise RuntimeError(
            f"Missing SecretString in response for {secret_arn}, please ensure the secret was not stored as binary data."
        )

    value = cast(str, response["SecretString"])

    expiry = now + timedelta(seconds=_cache_ttl)
    _secrets_cache[secret_arn] = (value, expiry)

    return value


def clear_cache():
    """Clear the cache"""
    _secrets_cache.clear()
