import * as cdk from 'aws-cdk-lib';
import * as identitystore from 'aws-cdk-lib/aws-identitystore';
import { Construct } from 'constructs';
import { roleNameFor } from './project-role';
import {
  AAM_APPLICATION_ID,
  IDENTITY_STORE_ID,
  MANAGEMENT_ACCOUNT_ID,
  PROJECTS,
  TARGET_ACCOUNTS,
} from './config';

/**
 * OPTIONAL. Deploy to the MANAGEMENT account, after AbacStack. The README's
 * CLI commands are an equivalent alternative.
 *
 * Per project: one Identity Center group, plus one entitlement per target
 * account mapping that group to the matching role.
 *
 * Identity Center *users* have no CloudFormation resource type, and setting a
 * password has no API at all, so users are still created by hand. README step 4.
 *
 * The AWS::AccountAccess::* types are declared with a raw CfnResource because
 * aws-cdk-lib ships no L1 constructs for them yet. `cdk synth` prints
 * "Unknown resource type" and succeeds; the CloudFormation types are real.
 */
export class EntitlementStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const applicationArn =
      `arn:${this.partition}:account-access:${this.region}:` +
      `${MANAGEMENT_ACCOUNT_ID}:application/${AAM_APPLICATION_ID}`;

    for (const project of PROJECTS) {
      // Group membership is the control plane: which role a person can assume
      // is decided by which group they are in.
      const group = new identitystore.CfnGroup(this, `Group-${project}`, {
        identityStoreId: IDENTITY_STORE_ID,
        displayName: `proj-${project}`,
        description: `Workforce users for project ${project}`,
      });

      // The role ARN is deterministic, so this stack needs no cross-account or
      // cross-stack references. `roleNameFor` is shared with the stack that
      // creates the role, because this ARN is matched exactly.
      for (const target of TARGET_ACCOUNTS) {
        const entitlement = new cdk.CfnResource(
          this,
          `Entitlement-${project}-${target.accountId}`,
          {
            type: 'AWS::AccountAccess::Entitlement',
            properties: {
              ApplicationArn: applicationArn,
              Entitlement: {
                PrincipalRole: {
                  Account: target.accountId,
                  RoleArn:
                    `arn:${this.partition}:iam::${target.accountId}:` +
                    `role/workforce/${roleNameFor(project)}`,
                  Principal: {
                    IdentityCenter: { groupId: group.attrGroupId },
                  },
                },
              },
            },
          },
        );

        // The group must exist before it can be entitled.
        entitlement.addResourceDependency(group);
      }

      new cdk.CfnOutput(this, `GroupId-${project}`, {
        value: group.attrGroupId,
        description: `Add your ${project} test users to this group`,
      });
    }
  }
}
