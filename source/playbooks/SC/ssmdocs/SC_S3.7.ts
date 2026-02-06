// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableS3CrossRegionReplicationDocument(scope, id, { ...props, controlId: 'S3.7' });
}

export class EnableS3CrossRegionReplicationDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'S3.7',
      remediationName: 'EnableS3CrossRegionReplication',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'BucketName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])$`,
      updateDescription: HardCodedString.of('Cross-region replication enabled on S3 bucket.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    return params;
  }
}
