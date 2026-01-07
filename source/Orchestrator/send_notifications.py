# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
from typing import Any, Optional, Union, cast

from layer import sechub_findings
from layer.cloudwatch_metrics import CloudWatchMetrics
from layer.event_transformers import (
    Event,
    extract_account_id,
    extract_region,
    extract_resources,
    extract_severity,
    extract_stepfunctions_execution_id,
    is_notified_workflow,
    is_resolved_item,
    transform_stepfunctions_failure_event,
)
from layer.history_repository import RemediationUpdateRequest
from layer.metrics import Metrics
from layer.powertools_logger import get_logger
from layer.remediation_data_service import (
    get_security_hub_console_url,
    map_remediation_status,
    update_remediation_status_and_history,
)
from layer.sechub_findings import (
    FindingInfo,
    extract_finding_id,
    extract_finding_info,
    extract_resource_id,
    extract_security_control_id,
    get_finding_type,
)
from layer.tracer_utils import init_tracer
from layer.utils import get_account_alias

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")  # MUST BE SET in global variables
AWS_PARTITION = os.getenv("AWS_PARTITION", "aws")  # MUST BE SET in global variables

logger = get_logger("send_notifications")
tracer = init_tracer()


def format_details_for_output(details: Any) -> list[str]:
    """Handle various possible formats in the details"""
    from json.decoder import JSONDecodeError

    details_formatted = []
    if isinstance(details, list):
        details_formatted = details
    elif isinstance(details, str) and details[0:6] == "Cause:":
        try:
            details_formatted = json.dumps(json.loads(details[7:]), indent=2).split(
                "\n"
            )
        except JSONDecodeError:
            details_formatted.append(details[7:])
    elif isinstance(details, str):
        try:
            details_formatted = json.loads(details)
        except JSONDecodeError:
            details_formatted.append(details)
    else:
        details_formatted.append(details)

    return details_formatted


def set_message_prefix_and_suffix(event):
    message_prefix = event["Notification"].get("SSMExecutionId", "")
    message_suffix = event["Notification"].get("AffectedObject", "")
    if message_prefix:
        message_prefix += ": "
    if message_suffix:
        message_suffix = f" ({message_suffix})"
    return message_prefix, message_suffix


def _process_metrics(
    event: dict[str, Any],
    status_from_event: str,
    control_id: str,
    custom_action_name: str,
) -> None:
    metrics = Metrics()
    metrics_data = metrics.get_metrics_from_event(event)
    metrics_data["status"], metrics_data["status_reason"] = (
        Metrics.get_status_for_metrics(status_from_event)
    )
    metrics.send_metrics(metrics_data)

    create_and_send_cloudwatch_metrics(
        status_from_event, control_id, custom_action_name
    )


def _create_notification(
    event: Event,
    status_from_event: str,
    stepfunctions_execution_id: str,
    finding: Optional[sechub_findings.Finding],
) -> sechub_findings.ASRNotification:
    notification = sechub_findings.ASRNotification(
        event.get("SecurityStandard", "ASR"),
        AWS_REGION,
        stepfunctions_execution_id,
        event.get("ControlId", None),
    )

    if status_from_event in ("SUCCESS", "QUEUED"):
        notification.severity = "INFO"
    else:
        notification.severity = "ERROR"
        if finding:
            finding.flag(event["Notification"]["Message"])

    notification.send_to_sns = True
    return notification


def _update_finding_remediation_status(
    execution_id: str,
    status_from_event: str,
    event: Event,
) -> None:
    event_dict = cast(dict[str, Any], cast(object, event))
    remediation_status = map_remediation_status(status_from_event)
    error_message = None

    if remediation_status == "FAILED":
        error_message = event["Notification"].get("Details") or event[
            "Notification"
        ].get("Message", None)

    if is_resolved_item(event):
        logger.warning(
            "Overriding remediation status to SUCCESS for resolved workflow with NOT_NEW state",
            extra={
                "findingId": extract_finding_id(event_dict),
                "originalStatus": status_from_event,
                "overriddenStatus": "SUCCESS",
            },
        )
        remediation_status = "SUCCESS"
        error_message = None

    finding_id = extract_finding_id(event_dict)
    finding_type = get_finding_type(event_dict)

    logger.debug(
        "Finding processing",
        extra={
            "finding id": finding_id,
            "finding type": finding_type,
        },
    )

    try:
        resources = extract_resources(event)

        remediation_request = RemediationUpdateRequest(
            finding_id=finding_id,
            execution_id=execution_id,
            remediation_status=remediation_status,
            finding_type=finding_type,
            error=error_message,
            resource_id=extract_resource_id(event_dict, resources),
            resource_type=resources.get("Type", ""),
            account_id=extract_account_id(event),
            severity=extract_severity(event),
            region=extract_region(event),
            lastUpdatedBy="Automated",
        )
        update_remediation_status_and_history(remediation_request)
    except Exception as e:
        logger.error(
            "Failed to update remediation status and history",
            extra={
                "finding_id": finding_id,
                "executionId": execution_id,
                "finding_type": finding_type,
                "error": str(e),
            },
        )


@tracer.capture_lambda_handler  # type: ignore[misc]
def lambda_handler(event: Union[Event, dict[str, Any]], context: Any) -> None:
    try:
        # Type narrowing: check if this is a Step Functions event (raw dict)
        if (
            isinstance(event, dict)
            and event.get("detail-type") == "Step Functions Execution Status Change"
        ):
            raw_event = cast(dict[str, Any], event)
            logger.info(
                "Processing Step Functions failure event",
                extra={
                    "executionArn": raw_event.get("detail", {}).get("executionArn", ""),
                    "status": raw_event.get("detail", {}).get("status", ""),
                },
            )
            event = transform_stepfunctions_failure_event(raw_event)
    except Exception as e:
        logger.error(
            "Failed to transform event - continuing with original",
            extra={"error": str(e)},
        )
        # Don't raise - try to process with original event structure

    # Type assertion: at this point, event should be of type Event
    event = cast(Event, event)

    message_prefix, message_suffix = set_message_prefix_and_suffix(event)
    stepfunctions_execution_id = extract_stepfunctions_execution_id(event)
    status_from_event = event.get("Notification", {}).get("State", "").upper()

    event_dict = cast(dict[str, Any], cast(object, event))
    finding, finding_info = extract_finding_info(event_dict)

    control_id = extract_security_control_id(event_dict)
    custom_action_name = event.get("CustomActionName", "")

    _process_metrics(event_dict, status_from_event, control_id, custom_action_name)

    notification = _create_notification(
        event, status_from_event, stepfunctions_execution_id, finding
    )

    build_and_send_notification(
        event, notification, message_prefix, message_suffix, finding_info
    )

    notified_workflow = is_notified_workflow(event)

    if "Finding" in event and not notified_workflow:
        _update_finding_remediation_status(
            stepfunctions_execution_id, status_from_event, event
        )

    if status_from_event == "SUCCESS" and finding:
        finding.resolve(event["Notification"]["Message"])


def build_and_send_notification(
    event: Event,
    notification: sechub_findings.ASRNotification,
    message_prefix: str,
    message_suffix: str,
    finding_info: Union[str, FindingInfo],
) -> None:
    notification.message = (
        message_prefix + event["Notification"]["Message"] + message_suffix
    )

    notification.remediation_output = event["Notification"].get("RemediationOutput", "")

    notification.remediation_status = event["Notification"]["State"]

    remediation_account_id = ""
    if isinstance(finding_info, dict):
        remediation_account_id = (
            finding_info["account"] if "account" in finding_info else ""
        )
        notification.finding_link = get_security_hub_console_url(
            finding_info["finding_arn"]
        )

    try:
        notification.remediation_account_alias = get_account_alias(
            remediation_account_id
        )
    except Exception as e:
        logger.warning(
            f"Unexpected error getting account alias for {remediation_account_id}, using account ID",
            extra={"accountId": remediation_account_id, "error": str(e)},
        )
        notification.remediation_account_alias = remediation_account_id or "Unknown"

    if (
        "Details" in event["Notification"]
        and event["Notification"]["Details"] != "MISSING"
    ):
        notification.logdata = format_details_for_output(
            event["Notification"]["Details"]
        )

    if "GenerateTicket" in event and event["GenerateTicket"]:
        generate_ticket_response = event["GenerateTicket"]
        response_reason = generate_ticket_response["ResponseReason"]
        notification.ticket_url = (
            generate_ticket_response["TicketURL"]
            if generate_ticket_response["Ok"]
            else f"Error generating ticket: {response_reason} - check ticket_generator lambda logs for details"
        )

    notification.finding_info = finding_info  # type: ignore[assignment]
    notification.notify()


def create_and_send_cloudwatch_metrics(
    event_state: str, control_id: str, custom_action_name: Union[None, str]
) -> None:
    try:
        cloudwatch_metrics = CloudWatchMetrics()

        control_id = control_id or "Unknown"

        dimensions = [
            {
                "Name": "Outcome",
                "Value": event_state,
            },
        ]
        if os.environ["ENHANCED_METRICS"].lower() == "yes":
            enhanced_metric = {
                "MetricName": "RemediationOutcome",
                "Dimensions": [*dimensions, {"Name": "ControlId", "Value": control_id}],
                "Unit": "Count",
                "Value": 1,
            }
            cloudwatch_metrics.send_metric(enhanced_metric)
        if custom_action_name:
            custom_action_metric = {
                "MetricName": "RemediationOutcome",
                "Dimensions": [
                    *dimensions,
                    {"Name": "CustomActionName", "Value": custom_action_name},
                ],
                "Unit": "Count",
                "Value": 1,
            }
            cloudwatch_metrics.send_metric(custom_action_metric)
        cloudwatch_metric = {
            "MetricName": "RemediationOutcome",
            "Dimensions": dimensions,
            "Unit": "Count",
            "Value": 1,
        }
        cloudwatch_metrics.send_metric(cloudwatch_metric)
    except Exception as e:
        logger.debug(f"Encountered error sending Cloudwatch metric: {str(e)}")
