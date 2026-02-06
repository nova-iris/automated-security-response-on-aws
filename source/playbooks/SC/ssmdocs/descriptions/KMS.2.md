### Document Name - ASR-SC_2.3.0_KMS.2

## What does this document do?
This document reviews IAM principals for inline policies that grant overly permissive KMS actions. It provides guidance for removing excessive permissions.

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output

## Documentation Links
* [AWS Security Hub KMS.2](https://docs.aws.amazon.com/securityhub/latest/userguide/kms-controls.html#kms-2)
