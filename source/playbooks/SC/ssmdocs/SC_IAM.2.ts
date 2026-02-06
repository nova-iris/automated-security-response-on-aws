// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new RemoveIAMUserDirectPoliciesDocument(scope, id, { ...props, controlId: 'IAM.2' });
}

export class RemoveIAMUserDirectPoliciesDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'IAM.2',
      remediationName: 'RemoveIAMUserDirectPolicies',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'IAMUserName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):iam::\d{12}:user\/([\w+=,.@-]{1,64})$`,
      updateDescription: HardCodedString.of('Removed direct IAM policies from user.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    return params;
  }
}
