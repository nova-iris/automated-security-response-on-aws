// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableAPIGatewayAccessLoggingDocument(scope, id, { ...props, controlId: 'APIGateway.9' });
}

export class EnableAPIGatewayAccessLoggingDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'APIGateway.9',
      remediationName: 'EnableAPIGatewayAccessLogging',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'ApiId',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):apigateway:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d)::/apis/([a-z0-9]{10})$`,
      updateDescription: HardCodedString.of('Access logging enabled on API Gateway stage.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    return params;
  }
}
