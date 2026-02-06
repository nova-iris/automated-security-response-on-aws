// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableFirehoseEncryptionDocument(scope, id, { ...props, controlId: 'DataFirehose.1' });
}

export class EnableFirehoseEncryptionDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'DataFirehose.1',
      remediationName: 'EnableFirehoseEncryption',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'DeliveryStreamName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):firehose:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:deliverystream/([a-zA-Z0-9_.-]{1,64})$`,
      updateDescription: HardCodedString.of('Encryption enabled on Kinesis Data Firehose delivery stream.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    return params;
  }
}
