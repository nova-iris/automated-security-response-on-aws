// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableIAMUserMFADocument(scope, id, { ...props, controlId: 'IAM.19' });
}

export class EnableIAMUserMFADocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'IAM.19',
      remediationName: 'EnableIAMUserMFA',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'IAMUserName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):iam::\d{12}:user\/([\w+=,.@-]{1,64})$`,
      updateDescription: HardCodedString.of('Checked IAM user MFA status - manual remediation required.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    return params;
  }
}
