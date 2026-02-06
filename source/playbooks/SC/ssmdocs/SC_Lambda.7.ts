// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new UpdateLambdaRuntimeDocument(scope, id, { ...props, controlId: 'Lambda.7' });
}

export class UpdateLambdaRuntimeDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'Lambda.7',
      remediationName: 'UpdateLambdaRuntime',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'FunctionName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):lambda:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:function:([a-zA-Z0-9-_]{1,64})$`,
      updateDescription: HardCodedString.of('Lambda runtime checked - manual remediation required.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    return params;
  }
}
