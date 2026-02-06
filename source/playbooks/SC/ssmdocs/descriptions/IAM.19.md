### Document Name - ASR-SC_2.3.0_IAM.19

## What does this document do?
This document checks MFA status for IAM users. MFA setup requires user interaction and cannot be fully automated, so this provides manual remediation guidance.

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output

## Documentation Links
* [AWS Security Hub IAM.19](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-19)
