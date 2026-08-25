import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

/**
 * Policy documents for the ABAC workforce pattern.
 *
 * Deviations from the snippets printed in the blog post are marked HARDENED
 * and explained in the README under "Where this code deliberately differs".
 */

/**
 * Bucket names are unknown at authoring time by design, which is what lets one
 * document serve every project.
 *
 * HARDENED: the post uses `resources: ['*']`. Confining the wildcard to the S3
 * namespace keeps the blast radius to one service if a tag condition is ever
 * mis-edited.
 */
export const s3AllBuckets = `arn:${cdk.Aws.PARTITION}:s3:::*`;
export const s3AllObjects = `arn:${cdk.Aws.PARTITION}:s3:::*/*`;

export interface TrustPolicyOptions {
  /** MANAGEMENT account ID, not the account holding the role. */
  readonly managementAccountId: string;
  readonly aamApplicationId: string;
  readonly region: string;
}

/**
 * Trust policy for a workforce ABAC role. Returns exactly one statement.
 *
 * `account-access.amazonaws.com` is shared by every organization using the
 * service, so the two conditions are what stop it being a confused deputy.
 */
export function buildTrustPolicy(opts: TrustPolicyOptions): iam.PolicyDocument {
  const applicationArn =
    `arn:${cdk.Aws.PARTITION}:account-access:${opts.region}:` +
    `${opts.managementAccountId}:application/${opts.aamApplicationId}`;

  return new iam.PolicyDocument({
    statements: [
      new iam.PolicyStatement({
        sid: 'AccountAccessManagerIAMRoleTrustPolicyStatement',
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal('account-access.amazonaws.com')],
        actions: [
          'sts:AssumeRole',
          // Required: Account Access Manager injects identity context with it.
          'sts:SetContext',
          // Optional today. Forward compatibility for session tag support.
          'sts:TagSession',
        ],
        conditions: {
          StringEquals: {
            'aws:SourceAccount': opts.managementAccountId,
            // HARDENED: the post uses ArnLike. The ARN has no wildcard
            // segment, so an exact match is stricter.
            'aws:SourceArn': applicationArn,
          },
        },
      }),
    ],
  });
}

/**
 * The single ABAC policy, shared byte-for-byte by every role.
 *
 * No project name, environment name, account ID or bucket ARN appears in it.
 * That absence is the pattern: there is nothing project-specific to author.
 */
export function buildAbacPolicy(): iam.PolicyDocument {
  return new iam.PolicyDocument({
    statements: [
      // Fail closed on a mis-tagged ROLE. Without this such a role would
      // merely fail to match the Allow, which denies too but only implicitly,
      // and implicit denials are invisible in simulate-principal-policy.
      //
      // Data actions only, so console navigation survives and a tag problem
      // presents as a tag problem rather than a missing permission elsewhere.
      new iam.PolicyStatement({
        sid: 'DenyDataAccessWhenProjectTagMissing',
        effect: iam.Effect.DENY,
        actions: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject', 's3:ListBucket'],
        resources: [s3AllBuckets, s3AllObjects],
        conditions: { Null: { 'aws:PrincipalTag/project': 'true' } },
      }),

      // Defence in depth on the resource side. The Allow below already
      // withholds access on a mismatch; this makes it explicit so no later
      // policy can override it.
      //
      // The tagging actions are denied but never allowed anywhere in this
      // document. Granting PutObjectTagging under ABAC would let a user retag
      // an object into their own project and self-authorize.
      //
      // The Null condition keeps this from firing on untagged resources.
      // Remove it once tag governance is complete and you want strict
      // deny-by-default.
      new iam.PolicyStatement({
        sid: 'DenyWhenProjectMismatches',
        effect: iam.Effect.DENY,
        actions: [
          's3:GetObject',
          's3:PutObject',
          's3:DeleteObject',
          's3:GetObjectTagging',
          's3:PutObjectTagging',
        ],
        resources: [s3AllBuckets, s3AllObjects],
        conditions: {
          StringNotEquals: {
            'aws:ResourceTag/project': '${aws:PrincipalTag/project}',
          },
          Null: {
            'aws:ResourceTag/project': 'false',
          },
        },
      }),

      // The two-dimension comparison. project=phoenix/environment=dev reaches
      // resources tagged the same way and nothing else.
      new iam.PolicyStatement({
        sid: 'AllowAccessWhenTagsMatch',
        effect: iam.Effect.ALLOW,
        actions: ['s3:ListBucket', 's3:GetObject', 's3:PutObject', 's3:DeleteObject'],
        resources: [s3AllBuckets, s3AllObjects],
        conditions: {
          StringEquals: {
            'aws:ResourceTag/project': '${aws:PrincipalTag/project}',
            'aws:ResourceTag/environment': '${aws:PrincipalTag/environment}',
          },
        },
      }),

      // Unconditional, so users see bucket NAMES. Listing names is not listing
      // contents: every bucket appears, only matching ones open. Without this
      // the console shows zero buckets and a permissions error, which hides
      // the real cause.
      new iam.PolicyStatement({
        sid: 'AllowNavigation',
        effect: iam.Effect.ALLOW,
        actions: ['s3:ListAllMyBuckets', 's3:GetBucketLocation', 's3:GetBucketTagging'],
        resources: [s3AllBuckets],
      }),
    ],
  });
}

/**
 * Permissions boundary for every workforce role in one account. No counterpart
 * in the blog post.
 *
 * The ABAC policy decides which resources a role reaches; this decides what it
 * can do at all, and it wins over anything attached later. It closes the
 * escalation path created by trusting Account Access Manager: whoever can
 * create an entitlement can hand a role to any Identity Center user.
 *
 * Actions here must remain a superset of what `buildAbacPolicy` allows, or the
 * boundary silently withholds them.
 *
 * The organization perimeter is not repeated: Account Access Manager injects a
 * session policy scoping every session to aws:PrincipalOrgID.
 */
export function createWorkforceBoundary(
  scope: Construct,
  environmentName: string,
): iam.ManagedPolicy {
  return new iam.ManagedPolicy(scope, 'WorkforceBoundary', {
    managedPolicyName: `WorkforceAbacBoundary-${environmentName}`,
    description: 'Ceiling for ABAC workforce roles. Read and write S3 only, nothing else.',
    document: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: 'CeilingS3DataAccessOnly',
          effect: iam.Effect.ALLOW,
          actions: [
            's3:ListAllMyBuckets',
            's3:ListBucket',
            's3:GetBucketLocation',
            's3:GetBucketTagging',
            's3:GetObject',
            's3:PutObject',
            's3:DeleteObject',
          ],
          resources: [s3AllBuckets, s3AllObjects],
        }),
      ],
    }),
  });
}
