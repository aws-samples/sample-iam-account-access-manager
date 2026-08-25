#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { Aspects } from 'aws-cdk-lib';
import { AwsSolutionsChecks, NagSuppressions } from 'cdk-nag';
import { AbacStack } from '../lib/abac-stack';
import { EntitlementStack } from '../lib/entitlement-stack';
import { MANAGEMENT_ACCOUNT_ID, REGION, TARGET_ACCOUNTS } from '../lib/config';

const app = new cdk.App();

// One per target account. These hold the roles and the tagged resources, so
// they deploy into the WORKLOAD accounts, not the management account.
const abacStacks = TARGET_ACCOUNTS.map((target) =>
  new AbacStack(app, `AbacDemo-${target.environment}`, {
    env: { account: target.accountId, region: REGION },
    description:
      `ABAC workforce roles and tagged demo buckets (environment=${target.environment})`,
    environmentName: target.environment,
  }),
);

// OPTIONAL, and in the MANAGEMENT account. Deploy only AFTER the AbacStacks:
// the entitlements reference role ARNs that must already exist.
const entitlementStack = new EntitlementStack(app, 'AbacDemo-Entitlements', {
  env: { account: MANAGEMENT_ACCOUNT_ID, region: REGION },
  description: 'IAM Identity Center groups and Account Access Manager entitlements',
});

// Runs on every synth, so a regression fails `cdk synth` instead of reaching an
// account. To prove the checks are active, delete `enforceSSL: true` from the
// demo buckets and synth again: it fails.
Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

// Two suppressions. Both are inherent to the pattern, not shortcuts.
for (const stack of abacStacks) {
  NagSuppressions.addStackSuppressions(stack, [
    {
      id: 'AwsSolutions-IAM5',
      reason:
        'ABAC requires wildcard resource ARNs. Bucket names are deliberately unknown ' +
        'at policy-authoring time, which is precisely what allows one policy document ' +
        'to serve every project. Access is constrained at request time by the ' +
        'aws:ResourceTag to aws:PrincipalTag comparison, and capped by the ' +
        'WorkforceAbacBoundary permissions boundary which limits these roles to S3 ' +
        'data actions. ARNs are scoped to the S3 namespace, not a bare wildcard.',
    },
    {
      id: 'AwsSolutions-S1',
      reason:
        'The access log destination bucket does not write access logs to itself, ' +
        'which would be circular. Every bucket holding demo data has server access ' +
        'logging enabled and targets this bucket.',
    },
  ]);
}

// No suppressions needed: neither Identity Center groups nor Account Access
// Manager entitlements have cdk-nag rules.
void entitlementStack;
