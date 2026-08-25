import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { buildTrustPolicy } from './abac-policy';

/**
 * The IAM role name for a project, matching the architecture diagram in the
 * blog post: `WorkforceAbacPhoenix`, `WorkforceAbacAtlas`.
 *
 * Exported and used by BOTH the stack that creates the role and the stack that
 * references it by ARN in an entitlement. Entitlement role ARNs are matched
 * exactly, and a mismatch surfaces at entitlement creation time rather than at
 * deploy time, so the two must never be able to drift.
 *
 * Note the deliberate asymmetry: the role NAME capitalizes the project, the
 * role TAG value does not. Tag values are compared with StringEquals, which is
 * case-sensitive, so a role tagged project=Phoenix would not reach a bucket
 * tagged project=phoenix. The name is cosmetic; the tag is load-bearing.
 */
export function roleNameFor(project: string): string {
  return `WorkforceAbac${project.charAt(0).toUpperCase()}${project.slice(1)}`;
}

export interface ProjectRoleSecurity {
  /**
   * Required, not optional, and that is a deliberate departure from the blog
   * snippet. Without a ceiling these roles are an escalation path, because
   * whoever can create an entitlement can hand one to any Identity Center user.
   */
  readonly permissionsBoundary: iam.IManagedPolicy;

  /**
   * The shared document from `buildAbacPolicy()`. Passed in rather than built
   * here so every role receives the same object, which is what makes the
   * documents byte-identical.
   */
  readonly abacPolicy: iam.PolicyDocument;

  /**
   * Falls back to 1 if omitted, deliberately stricter than the sample's
   * configured value. `AbacStack` always passes `MAX_SESSION_HOURS` from
   * config.ts, so this fallback only applies to a direct caller who leaves it
   * out — and a caller who has not thought about session length should get the
   * short one.
   */
  readonly maxSessionHours?: number;
}

/**
 * Create one tagged workforce role.
 *
 * Positional arguments match the blog snippet. The trailing `security`
 * argument has no counterpart there and carries the controls it omits.
 */
export function createProjectRole(
  scope: Construct,
  project: string,
  environment: string,
  managementAccountId: string,
  aamApplicationId: string,
  region: string,
  security: ProjectRoleSecurity,
): iam.Role {
  const role = new iam.Role(scope, `Role${project}`, {
    roleName: roleNameFor(project),
    path: '/workforce/',
    maxSessionDuration: cdk.Duration.hours(security.maxSessionHours ?? 1),
    // Placeholder. Required by the construct, replaced wholesale below.
    assumedBy: new iam.ServicePrincipal('account-access.amazonaws.com'),
    permissionsBoundary: security.permissionsBoundary,
    inlinePolicies: { AbacS3Access: security.abacPolicy },
  });

  // ASSIGN the trust document. Do not append to it.
  //
  // Following the blog snippet literally would introduce a real vulnerability.
  // `assumedBy` has already emitted sts:AssumeRole for this service principal
  // with NO conditions, and IAM evaluates statements independently. The
  // snippet's `role.assumeRolePolicy?.addStatements(...)` leaves that
  // statement in place, so any caller reaching account-access.amazonaws.com
  // still satisfies it and aws:SourceAccount / aws:SourceArn are bypassed for
  // AssumeRole. The conditions show in the console and enforce nothing.
  //
  // Assigning replaces the document, leaving one conditioned statement. The
  // README shows how to verify this on a deployed role.
  (role.node.defaultChild as iam.CfnRole).assumeRolePolicyDocument = buildTrustPolicy({
    managementAccountId,
    aamApplicationId,
    region,
  }).toJSON();

  // The only difference between one role and the next. Surfaces as
  // aws:PrincipalTag/* during evaluation. Lowercase throughout: StringEquals
  // is case-sensitive, and a case mismatch is a silent denial that looks like
  // a broken policy.
  cdk.Tags.of(role).add('project', project);
  cdk.Tags.of(role).add('environment', environment);

  return role;
}
