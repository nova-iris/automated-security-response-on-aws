# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import inspect
import json
import os
import re
from typing import Any, Optional, TypedDict, Union

from botocore.exceptions import ClientError
from layer.awsapi_cached_client import AWSCachedClient
from layer.powertools_logger import get_logger
from layer.simple_validation import clean_ssm
from layer.utils import publish_to_sns

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
securityhub = None
logger = get_logger("sechub_findings_layer")

SOLUTION_BASE_PATH = "/Solutions/SO0111"

ASFF_TO_OCSF_STATUS = {
    "NEW": 1,
    "NOTIFIED": 2,
    "SUPPRESSED": 3,
    "RESOLVED": 4,
}


def get_securityhub():
    global securityhub
    if securityhub is None:
        securityhub = AWSCachedClient(
            os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        ).get_connection("securityhub")
    return securityhub


UNHANDLED_CLIENT_ERROR = "An unhandled client error occurred: "

# Local functions


def get_ssm_connection(apiclient):
    # returns a client id for ssm in the region of the finding via apiclient
    return apiclient.get_connection("ssm")


# Classes


class InvalidFindingJson(Exception):
    pass


class Finding(object):
    """
    Security Hub Finding class
    """

    details: Any = {}  # Assuming ONE finding per event. We'll take the first.
    generator_id = "error"
    account_id = "error"
    resource_region = "error"
    standard_name = ""
    standard_shortname = "error"
    standard_version = "error"
    standard_control = "error"
    remediation_control = ""
    playbook_enabled = "False"
    title = ""
    description = ""
    region = None
    arn = ""
    uuid = ""

    def __init__(self, finding_rec):
        self.region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self.aws_api_client = AWSCachedClient(self.region)

        self.details = finding_rec
        self.arn = self.details.get("Id", "error")
        self.uuid = self.arn.split("/finding/")[1]
        self.generator_id = self.details.get("GeneratorId", "error")
        self.account_id = self.details.get("AwsAccountId", "error")
        resource = self.details.get("Resources", [])[0]
        self.resource_region = resource.get("Region", "error")

        if not self.is_valid_finding_json():
            raise InvalidFindingJson

        self.title = self.details.get("Title", "error")
        self.description = self.details.get("Description", "error")
        self.remediation_url = (
            self.details.get("Remediation", {}).get("Recommendation", {}).get("Url", "")
        )

        if (
            self.details.get("ProductFields").get("StandardsControlArn", None)
            is not None
        ):
            self._get_security_standard_fields_from_arn(
                self.details.get("ProductFields").get("StandardsControlArn")
            )
        else:
            self.standard_control = self.details.get("Compliance").get(
                "SecurityControlId"
            )
            self.standard_version = "2.0.0"
            self.standard_name = "security-control"

        self._get_security_standard_abbreviation_from_ssm()
        self._get_control_remap()
        self._set_playbook_enabled()

    def is_valid_finding_json(self):
        if self.generator_id == "error":
            return False

        # Verify finding['Id']
        if not self.details.get("Id"):
            return False

        # Account Id
        if self.account_id == "error":
            return False

        return True

    def resolve(self, message):
        """
        Update the finding_id workflow status to "RESOLVED"
        """
        self.update_text_and_status(
            f"[automated-security-response-on-aws] {message}", status="RESOLVED"
        )

    def flag(self, message):
        """
        Update the finding_id workflow status to "NOTIFIED" to prevent
        further CWE rules matching. Do this in playbooks after validating input
        so multiple remediations are not initiated when automatic triggers are
        in use.
        """
        self.update_text_and_status(message, status="NOTIFIED")

    def update_text_and_status(self, message, status=None):
        """
        Update the finding_id text and status
        """

        workflow_status = {}
        securityhub_v2_enabled = (
            os.getenv("SECURITY_HUB_V2_ENABLED", "false").lower() == "true"
        )
        if status:
            workflow_status = {"Workflow": {"Status": status}}

        errors = []

        product_arn = self.details.get("ProductArn", "")
        product_arn_v1 = product_arn.replace("::productv2/", "::product/")
        product_arn_v2 = product_arn.replace("::product/", "::productv2/")

        if securityhub_v2_enabled:
            try:
                response = get_securityhub().batch_update_findings_v2(
                    FindingIdentifiers=[
                        {
                            "FindingInfoUid": self.details.get("Id"),
                            "MetadataProductUid": product_arn_v2,
                            "CloudAccountUid": self.account_id,
                        }
                    ],
                    Comment=message,
                    StatusId=ASFF_TO_OCSF_STATUS.get(status, 1),
                )
                if response["UnprocessedFindings"]:
                    for unprocessed in response["UnprocessedFindings"]:
                        error_code = unprocessed.get("ErrorCode", "Unknown")
                        error_message = unprocessed.get(
                            "ErrorMessage", "No error message"
                        )
                        errors.append(
                            f"Security Hub v2 API: {error_code} - {error_message}"
                        )
            except Exception as e:
                errors.append(f"Security Hub v2 API: {e}")

        try:
            get_securityhub().batch_update_findings(
                FindingIdentifiers=[
                    {
                        "Id": self.details.get("Id"),
                        "ProductArn": product_arn_v1,
                    }
                ],
                Note={"Text": message, "UpdatedBy": inspect.stack()[0][3]},
                **workflow_status,
            )
        except Exception as e:
            errors.append(f"Security Hub v1 API: {e}")

        if errors:
            logger.warning(
                f"Failed to update Security Hub finding - {'; '.join(errors)}"
            )

    def _get_security_standard_fields_from_arn(self, arn):
        standards_arn_parts = arn.split(":")[5].split("/")
        self.standard_name = standards_arn_parts[1]
        self.standard_version = standards_arn_parts[3]
        self.standard_control = standards_arn_parts[4]

    def _get_control_remap(self):
        self.remediation_control = self.standard_control  # Defaults to self
        try:
            clean_shortname = clean_ssm(self.standard_shortname)
            clean_version = clean_ssm(self.standard_version)
            clean_control = clean_ssm(self.standard_control)

            safe_param_path = f"{SOLUTION_BASE_PATH}/{clean_shortname}/{clean_version}/{clean_control}/remap"

            local_ssm = get_ssm_connection(self.aws_api_client)
            remap = (
                local_ssm.get_parameter(Name=safe_param_path)
                .get("Parameter")
                .get("Value")
            )
            self.remediation_control = remap

        except ClientError as ex:
            exception_type = ex.response["Error"]["Code"]
            if exception_type in "ParameterNotFound":
                return
            else:
                logger.error(UNHANDLED_CLIENT_ERROR + exception_type)
                return

        except Exception as e:
            logger.error(UNHANDLED_CLIENT_ERROR + str(e))
            return

    def _get_security_standard_abbreviation_from_ssm(self):
        try:
            clean_name = clean_ssm(self.standard_name)
            clean_version = clean_ssm(self.standard_version)

            safe_param_path = (
                f"{SOLUTION_BASE_PATH}/{clean_name}/{clean_version}/shortname"
            )

            local_ssm = get_ssm_connection(self.aws_api_client)
            abbreviation = (
                local_ssm.get_parameter(Name=safe_param_path)
                .get("Parameter")
                .get("Value")
            )
            self.standard_shortname = abbreviation

        except ClientError as ex:
            exception_type = ex.response["Error"]["Code"]
            if exception_type in "ParameterNotFound":
                self.security_standard = "notfound"
            else:
                logger.error(UNHANDLED_CLIENT_ERROR + exception_type)
                return

        except Exception as e:
            logger.error(UNHANDLED_CLIENT_ERROR + str(e))
            return

    def _set_playbook_enabled(self):
        try:
            clean_name = clean_ssm(self.standard_name)
            clean_version = clean_ssm(self.standard_version)

            safe_param_path = (
                f"{SOLUTION_BASE_PATH}/{clean_name}/{clean_version}/status"
            )

            local_ssm = get_ssm_connection(self.aws_api_client)
            version_status = (
                local_ssm.get_parameter(Name=safe_param_path)
                .get("Parameter")
                .get("Value")
            )

            if version_status == "enabled":
                self.playbook_enabled = "True"
            else:
                self.playbook_enabled = "False"

        except ClientError as ex:
            exception_type = ex.response["Error"]["Code"]
            if exception_type in "ParameterNotFound":
                self.playbook_enabled = "False"
            else:
                logger.error(UNHANDLED_CLIENT_ERROR + exception_type)
                self.playbook_enabled = "False"

        except Exception as e:
            logger.error(UNHANDLED_CLIENT_ERROR + str(e))
            self.playbook_enabled = "False"


# ================
# Utilities
# ================
class InvalidValue(Exception):
    pass


class FindingInfo(TypedDict):
    finding_id: str
    finding_description: str
    standard_name: str
    standard_version: str
    standard_control: str
    title: str
    region: str
    account: str
    finding_arn: str


def get_control_id_from_finding_id(finding_id: str) -> Optional[str]:
    # Finding ID structure depends on consolidation settings
    # https://aws.amazon.com/blogs/security/consolidating-controls-in-security-hub-the-new-controls-view-and-consolidated-findings/

    # Unconsolidated finding ID pattern
    unconsolidated_pattern = r"^arn:(?:aws|aws-cn|aws-us-gov):securityhub:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:subscription\/(.+)\/finding\/.+$"
    unconsolidated_match = re.match(unconsolidated_pattern, finding_id)
    if unconsolidated_match:
        return unconsolidated_match.group(
            1
        )  # example: 'aws-foundational-security-best-practices/v/1.0.0/S3.1'

    # Consolidated finding ID pattern
    consolidated_pattern = r"^arn:(?:aws|aws-cn|aws-us-gov):securityhub:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:(.+)\/finding\/.+$"
    consolidated_match = re.match(consolidated_pattern, finding_id)
    if consolidated_match:
        return consolidated_match.group(1)  # example: 'security-control/Lambda.3'

    return None


def sanitize_control_id(control_id: str) -> str:
    non_alphanumeric_or_allowed = re.compile(r"[^a-zA-Z0-9/.-]")
    return non_alphanumeric_or_allowed.sub("", control_id)


def get_finding_type(event: dict[str, Any]) -> str:
    if "Finding" not in event:
        return ""

    finding_id = extract_finding_id(event)
    if finding_id:
        control_id_from_finding_id = get_control_id_from_finding_id(finding_id)
        if control_id_from_finding_id:
            return sanitize_control_id(control_id_from_finding_id)

    control_id = extract_security_control_id(event)
    if control_id:
        return sanitize_control_id(control_id)

    return ""


def extract_security_control_id(event: dict[str, Any]) -> str:
    if "Finding" not in event:
        return ""

    # Try to get SecurityControlId from Compliance first
    compliance = event["Finding"].get("Compliance", {})
    control_id = (
        compliance.get("SecurityControlId", "") if isinstance(compliance, dict) else ""
    )

    # If empty, fallback to ProductFields.ControlId
    if not control_id:
        product_fields = event["Finding"].get("ProductFields", {})
        control_id = (
            product_fields.get("ControlId", "")
            if isinstance(product_fields, dict)
            else ""
        )

    return str(control_id)


def extract_finding_id(event: dict[str, Any]) -> str:
    if "Finding" not in event:
        return ""

    finding_id = event["Finding"].get("Id", "")

    if not finding_id:
        product_fields = event["Finding"].get("ProductFields", {})
        finding_id = (
            product_fields.get("aws/securityhub/FindingId", "")
            if isinstance(product_fields, dict)
            else ""
        )

    return str(finding_id)


def extract_resource_id(event: dict[str, Any], resources: dict[str, Any]) -> str:
    resource_id = resources.get("Id", "") if resources else ""

    if not resource_id:
        product_fields = event.get("Finding", {}).get("ProductFields", {})
        if isinstance(product_fields, dict):
            resources_field = product_fields.get("Resources:0/Id", "")
            resource_id = str(resources_field) if resources_field else ""

    return resource_id


def extract_finding_info(
    event: dict[str, Any],
) -> tuple[Optional[Finding], Union[str, FindingInfo]]:
    if "Finding" not in event:
        return None, ""

    finding = Finding(event["Finding"])
    finding_info: FindingInfo = {
        "finding_id": finding.uuid or "",
        "finding_description": finding.description or "",
        "standard_name": finding.standard_name or "",
        "standard_version": finding.standard_version or "",
        "standard_control": finding.standard_control or "",
        "title": finding.title or "",
        "region": finding.region or "",
        "account": finding.account_id or "",
        "finding_arn": finding.arn or "",
    }
    return finding, finding_info


class ASRNotification(object):
    # These are private - they cannot be changed after the object is created
    __security_standard = ""
    __controlid = None
    __region = ""
    __stepfunctions_execution_id = ""

    severity = "INFO"
    message = ""
    remediation_output = ""
    remediation_status = ""
    remediation_account_alias = ""
    finding_link = ""
    ticket_url = ""
    logdata: Any = []
    send_to_sns = False
    finding_info: Union[dict[str, Any], str] = {}

    def __init__(self, security_standard, region, execution_id, controlid=None):
        """
        Initialize the class
        applogger_name determines the log stream name in CW Logs
        ex. ASRNotification(<string>, 'us-east-1', None) -> logs to <string>-2021-01-22
        ex. ASRNotification('FSBP', 'us-east-1', 'EC2.1') -> logs to FSBP-EC2.1-2021-01-22
        """
        self.__security_standard = security_standard
        self.__region = region
        if controlid:
            self.__controlid = controlid
        self.__stepfunctions_execution_id = execution_id
        self.applogger = self._get_log_handler()

    def _get_log_handler(self):
        """
        Create a loghandler object
        """
        from layer.applogger import LogHandler

        applogger_name = self.__security_standard
        if self.__controlid:
            applogger_name += "-" + self.__controlid

        applogger = LogHandler(applogger_name)
        return applogger

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

    def notify(self):
        """
        Send notifications to the application CW Logs stream and sns
        """
        sns_notify_json = {
            "Remediation_Status": self.remediation_status,
            "Severity": self.severity,
            "Account_Alias": self.remediation_account_alias,
            "Remediation_Output": self.remediation_output,
            "Message": self.message,
            "Finding_Link": self.finding_link,
            "Finding": self.finding_info,
            "StepFunctions_Execution_Id": self.__stepfunctions_execution_id,
        }

        if self.ticket_url:
            sns_notify_json["Ticket_URL"] = self.ticket_url

        if self.send_to_sns:
            topic = "SO0111-ASR_Topic"
            sent_id = publish_to_sns(
                topic,
                json.dumps(sns_notify_json, indent=2, default=str),
                self.__region,
            )
            print(f"Notification message ID {sent_id} sent to {topic}")
        self.applogger.add_message(self.severity + ": " + self.message)
        if self.logdata:
            for line in self.logdata:
                self.applogger.add_message(line)
        self.applogger.flush()
