// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableECRImageScanningDocument(scope, id, { ...props, controlId: 'EC2.56' });
}

export class EnableECRImageScanningDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'EC2.56',
      remediationName: 'EnableECRImageScanning',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'RepositoryName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ecr:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:repository/(.+)$`,
      updateDescription: HardCodedString.of('Image scanning enabled on ECR repository.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    return params;
  }
}
