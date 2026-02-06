### Document Name - ASR-SC_2.3.0_Lambda.2

## What does this document do?
This document configures a dead-letter queue (DLQ) on a Lambda function. It creates an SQS queue if not specified and configures the function to use it.

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output

## Documentation Links
* [AWS Security Hub Lambda.2](https://docs.aws.amazon.com/securityhub/latest/userguide/lambda-controls.html#lambda-2)
