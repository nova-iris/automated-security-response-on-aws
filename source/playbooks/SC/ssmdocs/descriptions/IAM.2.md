### Document Name - ASR-SC_2.3.0_IAM.2

## What does this document do?
This document removes direct attached policies from an IAM user. It detaches managed policies and deletes inline policies.

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output

## Documentation Links
* [AWS Security Hub IAM.2](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-2)
