// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new RemoveKMSInlinePoliciesDocument(scope, id, { ...props, controlId: 'KMS.2' });
}

export class RemoveKMSInlinePoliciesDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'KMS.2',
      remediationName: 'RemoveKMSInlinePolicies',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'PrincipalArn',
      updateDescription: HardCodedString.of('KMS inline policies reviewed - manual remediation may be required.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    return params;
  }
}
