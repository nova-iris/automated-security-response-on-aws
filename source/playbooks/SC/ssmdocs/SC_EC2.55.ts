// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new SetECRLifecyclePolicyDocument(scope, id, { ...props, controlId: 'EC2.55' });
}

export class SetECRLifecyclePolicyDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'EC2.55',
      remediationName: 'SetECRLifecyclePolicy',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'RepositoryName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ecr:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:repository/(.+)$`,
      updateDescription: HardCodedString.of('Lifecycle policy configured on ECR repository.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    return params;
  }
}
