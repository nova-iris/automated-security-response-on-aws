// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableVPCFlowLogsDocument(scope, id, { ...props, controlId: 'EC2.60' });
}

export class EnableVPCFlowLogsDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'EC2.60',
      remediationName: 'EnableVPCFlowLogs',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'VpcId',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:vpc\/(vpc-[0-9a-f]+)$`,
      updateDescription: HardCodedString.of('VPC Flow Logs enabled.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    return params;
  }
}
