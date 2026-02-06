// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ConfigureLambdaDLQDocument(scope, id, { ...props, controlId: 'Lambda.2' });
}

export class ConfigureLambdaDLQDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'Lambda.2',
      remediationName: 'ConfigureLambdaDLQ',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'FunctionName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):lambda:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:function:([a-zA-Z0-9-_]{1,64})$`,
      updateDescription: HardCodedString.of('Dead-letter queue configured on Lambda function.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    return params;
  }
}
