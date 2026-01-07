# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os

import boto3
import layer.sechub_findings as findings
import pytest
from botocore.stub import Stubber

log_level = "info"
test_data = "test/test_json_data/"

my_session = boto3.session.Session()
my_region = my_session.region_name


# ------------------------------------------------------------------------------
# CIS v1.2.0
# ------------------------------------------------------------------------------
def test_parse_cis_v120(mocker):
    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/shortname",
                "Type": "String",
                "Value": "CIS",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:11:30.658000-04:00",
                "ARN": f"arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/shortname",
                "DataType": "text",
            }
        },
    )
    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )
    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:12:13.893000-04:00",
                "ARN": f"arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/cis-aws-foundations-benchmark/version",
                "DataType": "text",
            }
        },
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    assert finding.details.get("Id") == event["detail"]["findings"][0]["Id"]
    assert (
        finding.generator_id
        == "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3"
    )
    assert finding.account_id == "111111111111"
    assert finding.standard_name == "cis-aws-foundations-benchmark"
    assert finding.standard_shortname == "CIS"
    assert finding.standard_version == "1.2.0"
    assert finding.standard_control == "1.3"
    assert finding.playbook_enabled == "True"

    stubbed_ssm_client.deactivate()


# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
def test_parse_bad_imported():
    test_file = open(test_data + "CIS-bad.json")
    event = json.loads(test_file.read())
    test_file.close()

    with pytest.raises(findings.InvalidFindingJson):
        findings.Finding(event["detail"]["findings"][0])


# ------------------------------------------------------------------------------
# CIS v1.7.0 finding should show unsupported
# ------------------------------------------------------------------------------
def test_parse_unsupported_version(mocker):
    test_data_in = open(test_data + "CIS_unsupversion.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)

    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.7.0/shortname",
                "Type": "String",
                "Value": "CIS",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:11:30.658000-04:00",
                "ARN": f"arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/cis-aws-foundations-benchmark/1.7.0/shortname",
                "DataType": "text",
            }
        },
    )

    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])

    assert finding.details.get("Id") == event["detail"]["findings"][0]["Id"]
    assert (
        finding.generator_id
        == "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.7.0/rule/1.6"
    )
    assert finding.account_id == "111111111111"
    assert finding.standard_name == "cis-aws-foundations-benchmark"
    assert finding.standard_shortname == "CIS"
    assert finding.standard_version == "1.7.0"
    assert finding.standard_control == "1.6"
    assert finding.playbook_enabled == "False"

    stubbed_ssm_client.deactivate()


# ------------------------------------------------------------------------------
# AFSBP v1.0.0
# ------------------------------------------------------------------------------
def test_parse_afsbp_v100(mocker):
    test_data_in = open(test_data + "afsbp-ec2.7.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)

    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname",
                "Type": "String",
                "Value": "AFSBP",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:11:30.658000-04:00",
                "ARN": f"arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname",
                "DataType": "text",
            }
        },
    )
    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )
    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:12:13.893000-04:00",
                "ARN": f"arn:aws:ssm:us-{my_region}-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/version",
                "DataType": "text",
            }
        },
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    assert finding.details.get("Id") == event["detail"]["findings"][0]["Id"]
    assert finding.account_id == "111111111111"
    assert finding.standard_name == "aws-foundational-security-best-practices"
    assert finding.standard_shortname == "AFSBP"
    assert finding.standard_version == "1.0.0"
    assert finding.standard_control == "EC2.7"
    assert finding.playbook_enabled == "True"

    stubbed_ssm_client.deactivate()


# ------------------------------------------------------------------------------
# Security Standard not found
# ------------------------------------------------------------------------------
def test_undefined_security_standard(mocker):
    test_data_in = open(test_data + "afsbp-ec2.7.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    event["detail"]["findings"][0]["ProductFields"][
        "StandardsControlArn"
    ] = "arn:aws:securityhub:::standards/aws-invalid-security-standard/v/1.2.3/ABC.1"

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)

    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )

    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )

    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )

    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    assert finding.details.get("Id") == event["detail"]["findings"][0]["Id"]
    assert finding.account_id == "111111111111"
    assert finding.standard_name == "aws-invalid-security-standard"
    assert finding.standard_shortname == "error"
    assert finding.security_standard == "notfound"
    assert finding.standard_version == "1.2.3"
    assert finding.standard_control == "ABC.1"
    assert finding.playbook_enabled == "False"

    stubbed_ssm_client.deactivate()


# ------------------------------------------------------------------------------
# Test update_text_and_status method
# ------------------------------------------------------------------------------
def test_update_text_and_status_asff_format(mocker):
    """Test update_text_and_status with ASFF format (v2 disabled)"""
    os.environ["SECURITY_HUB_V2_ENABLED"] = "false"

    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    # Mock SecurityHub client
    mock_securityhub = mocker.MagicMock()
    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)

    # Mock SSM client
    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response("get_parameter", {"Parameter": {"Value": "CIS"}})
    stubbed_ssm_client.add_client_error("get_parameter", "ParameterNotFound")
    stubbed_ssm_client.add_response(
        "get_parameter", {"Parameter": {"Value": "enabled"}}
    )
    stubbed_ssm_client.activate()
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    finding.update_text_and_status("Test message", status="RESOLVED")

    mock_securityhub.batch_update_findings.assert_called_once()
    call_args = mock_securityhub.batch_update_findings.call_args[1]
    assert "Note" in call_args
    assert call_args["Note"]["Text"] == "Test message"
    assert "Workflow" in call_args
    mock_securityhub.batch_update_findings_v2.assert_not_called()
    stubbed_ssm_client.deactivate()

    del os.environ["SECURITY_HUB_V2_ENABLED"]


def test_update_text_and_status_productv2_format(mocker):
    """Test update_text_and_status with v2 enabled"""
    os.environ["SECURITY_HUB_V2_ENABLED"] = "true"

    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    # Mock SecurityHub client
    mock_securityhub = mocker.MagicMock()
    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)

    # Mock SSM client
    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response("get_parameter", {"Parameter": {"Value": "CIS"}})
    stubbed_ssm_client.add_client_error("get_parameter", "ParameterNotFound")
    stubbed_ssm_client.add_response(
        "get_parameter", {"Parameter": {"Value": "enabled"}}
    )
    stubbed_ssm_client.activate()
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    finding.update_text_and_status("Test message", status="NOTIFIED")

    mock_securityhub.batch_update_findings_v2.assert_called_once()
    mock_securityhub.batch_update_findings.assert_called_once()
    call_args = mock_securityhub.batch_update_findings.call_args[1]
    assert "Note" in call_args
    assert call_args["Note"]["Text"] == "Test message"
    assert "Workflow" in call_args
    stubbed_ssm_client.deactivate()

    del os.environ["SECURITY_HUB_V2_ENABLED"]


def test_update_text_and_status_ocsf_format(mocker):
    """Test update_text_and_status with v2 enabled and NOTIFIED status"""
    os.environ["SECURITY_HUB_V2_ENABLED"] = "true"

    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    # Mock SecurityHub client
    mock_securityhub = mocker.MagicMock()

    # Mock SSM client for Finding initialization
    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response("get_parameter", {"Parameter": {"Value": "CIS"}})
    stubbed_ssm_client.add_client_error("get_parameter", "ParameterNotFound")
    stubbed_ssm_client.add_response(
        "get_parameter", {"Parameter": {"Value": "enabled"}}
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    finding.update_text_and_status("Test message", status="NOTIFIED")

    mock_securityhub.batch_update_findings_v2.assert_called_once()
    mock_securityhub.batch_update_findings.assert_called_once()
    stubbed_ssm_client.deactivate()

    del os.environ["SECURITY_HUB_V2_ENABLED"]


def test_update_text_and_status_exception_handling(mocker):
    """Test update_text_and_status exception handling"""
    os.environ["SECURITY_HUB_V2_ENABLED"] = "false"

    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    # Mock SecurityHub client to raise exception
    mock_securityhub = mocker.MagicMock()
    mock_securityhub.batch_update_findings.side_effect = Exception("Access denied")

    # Mock SSM client for Finding initialization
    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response("get_parameter", {"Parameter": {"Value": "CIS"}})
    stubbed_ssm_client.add_client_error("get_parameter", "ParameterNotFound")
    stubbed_ssm_client.add_response(
        "get_parameter", {"Parameter": {"Value": "enabled"}}
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])

    # Should not raise exception, but log warning instead
    finding.update_text_and_status("Test message", status="RESOLVED")

    mock_securityhub.batch_update_findings.assert_called_once()
    stubbed_ssm_client.deactivate()

    del os.environ["SECURITY_HUB_V2_ENABLED"]


def test_security_control(mocker):
    test_data_in = open(test_data + "afsbp-ec2.7.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    event["detail"]["findings"][0]["ProductFields"]["StandardsControlArn"] = None
    event["detail"]["findings"][0]["Compliance"]["SecurityControlId"] = "EC2.7"

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)

    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/security-controls/2.0.0/shortname",
                "Type": "String",
                "Value": "SC",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:11:30.658000-04:00",
                "ARN": f"arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/security-controls/2.0.0/shortname",
                "DataType": "text",
            }
        },
    )
    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )
    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/security-controls/2.0.0/status",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:12:13.893000-04:00",
                "ARN": f"arn:aws:ssm:us-{my_region}-1:111111111111:parameter/Solutions/SO0111/security-controls/2.0.0/status",
                "DataType": "text",
            }
        },
    )
    stubbed_ssm_client.activate()

    finding = findings.Finding(event["detail"]["findings"][0])
    assert finding.details.get("Id") == event["detail"]["findings"][0]["Id"]
    assert finding.account_id == "111111111111"
    assert finding.standard_name == "security-control"
    assert finding.standard_version == "2.0.0"
    assert finding.standard_control == "EC2.7"


def test_update_text_and_status_productv2_arn_replacement(mocker):
    """Test that ProductArn is converted from 'product' to 'productv2' for v2 API and kept as 'product' for v1 API"""
    os.environ["SECURITY_HUB_V2_ENABLED"] = "true"

    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    original_product_arn = "arn:aws:securityhub:us-east-1::product/aws/securityhub"
    event["detail"]["findings"][0]["ProductArn"] = original_product_arn

    mock_securityhub = mocker.MagicMock()
    mock_securityhub.batch_update_findings_v2.return_value = {"UnprocessedFindings": []}

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response("get_parameter", {"Parameter": {"Value": "CIS"}})
    stubbed_ssm_client.add_client_error("get_parameter", "ParameterNotFound")
    stubbed_ssm_client.add_response(
        "get_parameter", {"Parameter": {"Value": "enabled"}}
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    finding.update_text_and_status("Test message", status="RESOLVED")

    v2_call_args = mock_securityhub.batch_update_findings_v2.call_args[1]
    v2_finding_identifier = v2_call_args["FindingIdentifiers"][0]
    assert (
        v2_finding_identifier["MetadataProductUid"]
        == "arn:aws:securityhub:us-east-1::productv2/aws/securityhub"
    )

    v1_call_args = mock_securityhub.batch_update_findings.call_args[1]
    v1_finding_identifier = v1_call_args["FindingIdentifiers"][0]
    assert v1_finding_identifier["ProductArn"] == original_product_arn

    stubbed_ssm_client.deactivate()
    del os.environ["SECURITY_HUB_V2_ENABLED"]


def test_update_text_and_status_productv2_arn_already_present(mocker):
    """Test that ProductArn with 'productv2' is kept for v2 API and converted to 'product' for v1 API"""
    os.environ["SECURITY_HUB_V2_ENABLED"] = "true"

    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    original_product_arn = "arn:aws:securityhub:us-east-1::productv2/aws/securityhub"
    event["detail"]["findings"][0]["ProductArn"] = original_product_arn

    mock_securityhub = mocker.MagicMock()
    mock_securityhub.batch_update_findings_v2.return_value = {"UnprocessedFindings": []}

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response("get_parameter", {"Parameter": {"Value": "CIS"}})
    stubbed_ssm_client.add_client_error("get_parameter", "ParameterNotFound")
    stubbed_ssm_client.add_response(
        "get_parameter", {"Parameter": {"Value": "enabled"}}
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    finding.update_text_and_status("Test message", status="RESOLVED")

    v2_call_args = mock_securityhub.batch_update_findings_v2.call_args[1]
    v2_finding_identifier = v2_call_args["FindingIdentifiers"][0]
    assert v2_finding_identifier["MetadataProductUid"] == original_product_arn

    v1_call_args = mock_securityhub.batch_update_findings.call_args[1]
    v1_finding_identifier = v1_call_args["FindingIdentifiers"][0]
    assert (
        v1_finding_identifier["ProductArn"]
        == "arn:aws:securityhub:us-east-1::product/aws/securityhub"
    )

    stubbed_ssm_client.deactivate()
    del os.environ["SECURITY_HUB_V2_ENABLED"]
