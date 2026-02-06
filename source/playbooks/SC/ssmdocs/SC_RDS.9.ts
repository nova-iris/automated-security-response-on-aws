// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableRDSCloudWatchLogsDocument(scope, id, { ...props, controlId: 'RDS.9' });
}

export class EnableRDSCloudWatchLogsDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'RDS.9',
      remediationName: 'EnableRDSCloudWatchLogs',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'DBInstanceIdentifier',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):rds:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:db:([a-zA-Z][a-zA-Z0-9-]{0,62})$`,
      updateDescription: HardCodedString.of('CloudWatch Logs publishing enabled on RDS DB instance.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    return params;
  }
}
