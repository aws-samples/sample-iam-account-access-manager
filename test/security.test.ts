import { createHash } from 'crypto';
import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AbacStack } from '../lib/abac-stack';
import { EntitlementStack } from '../lib/entitlement-stack';
import { roleNameFor } from '../lib/project-role';
import {
  MANAGEMENT_ACCOUNT_ID,
  MAX_SESSION_HOURS,
  PROJECTS,
  REGION,
  TARGET_ACCOUNTS,
} from '../lib/config';

/**
 * These tests guard the properties that make the pattern safe. They are not
 * coverage for its own sake: each one corresponds to a way the pattern has a
 * known failure mode, documented in the README.
 */

/** Actions that mutate tags. Granting any of them lets a user self-authorize. */
const TAG_MUTATION = [
  's3:PutObjectTagging',
  's3:DeleteObjectTagging',
  's3:PutBucketTagging',
  's3:DeleteBucketTagging',
  's3:TagResource',
  's3:UntagResource',
  's3:PutBucketAbac',
];

function stableHash(value: unknown): string {
  const sort = (v: any): any => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === 'object') {
      return Object.keys(v)
        .sort()
        .reduce((acc: any, k) => ((acc[k] = sort(v[k])), acc), {});
    }
    return v;
  };
  return createHash('sha256').update(JSON.stringify(sort(value))).digest('hex');
}

function asArray<T>(v: T | T[]): T[] {
  return Array.isArray(v) ? v : [v];
}

function synth(environmentName: string, accountId: string) {
  const app = new App();
  const stack = new AbacStack(app, `AbacDemo-${environmentName}`, {
    env: { account: accountId, region: REGION },
    environmentName,
  });
  return Template.fromStack(stack).toJSON();
}

describe.each(TARGET_ACCOUNTS)(
  'AbacStack for environment=$environment',
  ({ accountId, environment }) => {
    const template = synth(environment, accountId);
    const resources: Record<string, any> = template.Resources;
    const roles = Object.values(resources).filter((r: any) => r.Type === 'AWS::IAM::Role');
    const buckets = Object.values(resources).filter((r: any) => r.Type === 'AWS::S3::Bucket');
    const boundaries = Object.values(resources).filter(
      (r: any) => r.Type === 'AWS::IAM::ManagedPolicy',
    );

    test('creates one role per project', () => {
      expect(roles).toHaveLength(PROJECTS.length);
      const names = roles.map((r: any) => r.Properties.RoleName).sort();
      expect(names).toEqual(PROJECTS.map(roleNameFor).sort());
    });

    // The regression this repo exists to prevent. `assumedBy` emits an
    // unconditioned sts:AssumeRole; appending a conditioned statement instead
    // of assigning the document leaves it in place and the confused-deputy
    // conditions become bypassable. A second statement here means that
    // happened.
    test('trust policy is a single conditioned statement', () => {
      for (const role of roles as any[]) {
        const statements = role.Properties.AssumeRolePolicyDocument.Statement;
        expect(statements).toHaveLength(1);

        const only = statements[0];
        expect(only.Effect).toBe('Allow');
        expect(only.Principal).toEqual({ Service: 'account-access.amazonaws.com' });
        expect(only.Action).toEqual(['sts:AssumeRole', 'sts:SetContext', 'sts:TagSession']);
        expect(only.Condition.StringEquals).toBeDefined();
      }
    });

    // The condition has to name the management account, not the account
    // holding the role. Getting this wrong is the most common deployment
    // failure, and it fails at assume time rather than at deploy time.
    test('aws:SourceAccount is the management account and SourceArn is pinned', () => {
      for (const role of roles as any[]) {
        const cond = role.Properties.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals;
        expect(cond['aws:SourceAccount']).toBe(MANAGEMENT_ACCOUNT_ID);
        expect(cond['aws:SourceAccount']).not.toBe(accountId);

        const sourceArn = JSON.stringify(cond['aws:SourceArn']);
        expect(sourceArn).toContain('account-access');
        expect(sourceArn).toContain(MANAGEMENT_ACCOUNT_ID);
      }
    });

    test('every role carries the permissions boundary', () => {
      expect(boundaries).toHaveLength(1);
      expect((boundaries[0] as any).Properties.ManagedPolicyName).toBe(
        `WorkforceAbacBoundary-${environment}`,
      );
      for (const role of roles as any[]) {
        expect(role.Properties.PermissionsBoundary).toBeDefined();
      }
    });

    // The claim the blog post rests on. If these diverge, the pattern's
    // selling point is gone even though every role still works.
    test('all roles share a byte-identical policy document', () => {
      const hashes = new Set(
        (roles as any[]).map((r) => stableHash(r.Properties.Policies[0].PolicyDocument)),
      );
      expect(hashes.size).toBe(1);
    });

    test('policy names no project, environment, account or bucket', () => {
      const doc = JSON.stringify((roles[0] as any).Properties.Policies[0].PolicyDocument);
      for (const project of PROJECTS) {
        expect(doc).not.toContain(project);
      }
      expect(doc).not.toContain(environment);
      expect(doc).not.toContain(accountId);
      expect(doc).not.toContain('aam-abac');
    });

    test('no statement uses a bare wildcard resource', () => {
      for (const role of roles as any[]) {
        for (const s of role.Properties.Policies[0].PolicyDocument.Statement) {
          expect(asArray(s.Resource)).not.toContain('*');
        }
      }
      for (const b of boundaries as any[]) {
        for (const s of b.Properties.PolicyDocument.Statement) {
          expect(asArray(s.Resource)).not.toContain('*');
        }
      }
    });

    // Tag mutation is denied but never allowed. Granting it under ABAC would
    // let a user retag a resource into their own project and self-authorize.
    test('no Allow grants tag mutation', () => {
      const docs = [
        ...(roles as any[]).map((r) => r.Properties.Policies[0].PolicyDocument),
        ...(boundaries as any[]).map((b) => b.Properties.PolicyDocument),
      ];
      for (const doc of docs) {
        for (const s of doc.Statement.filter((x: any) => x.Effect === 'Allow')) {
          expect(asArray(s.Action)).not.toEqual(expect.arrayContaining(TAG_MUTATION));
          for (const action of asArray<string>(s.Action)) {
            expect(TAG_MUTATION).not.toContain(action);
          }
        }
      }
    });

    // Add an action to the ABAC policy without adding it here and the boundary
    // withholds it silently, which presents as an unexplained denial.
    test('boundary is a superset of every allowed action', () => {
      const ceiling = new Set<string>(
        asArray((boundaries[0] as any).Properties.PolicyDocument.Statement[0].Action),
      );
      const allowed = new Set<string>();
      for (const role of roles as any[]) {
        for (const s of role.Properties.Policies[0].PolicyDocument.Statement) {
          if (s.Effect === 'Allow') asArray<string>(s.Action).forEach((a) => allowed.add(a));
        }
      }
      expect([...allowed].filter((a) => !ceiling.has(a))).toEqual([]);
    });

    test('the Allow requires both ABAC dimensions', () => {
      const doc = (roles[0] as any).Properties.Policies[0].PolicyDocument;
      const allow = doc.Statement.find((s: any) => s.Sid === 'AllowAccessWhenTagsMatch');
      expect(allow.Condition.StringEquals).toEqual({
        'aws:ResourceTag/project': '${aws:PrincipalTag/project}',
        'aws:ResourceTag/environment': '${aws:PrincipalTag/environment}',
      });
    });

    test('fails closed when the role has no project tag', () => {
      const doc = (roles[0] as any).Properties.Policies[0].PolicyDocument;
      const guard = doc.Statement.find(
        (s: any) => s.Sid === 'DenyDataAccessWhenProjectTagMissing',
      );
      expect(guard.Effect).toBe('Deny');
      expect(guard.Condition).toEqual({ Null: { 'aws:PrincipalTag/project': 'true' } });
    });

    test('explicitly denies a project mismatch without catching untagged resources', () => {
      const doc = (roles[0] as any).Properties.Policies[0].PolicyDocument;
      const deny = doc.Statement.find((s: any) => s.Sid === 'DenyWhenProjectMismatches');
      expect(deny.Effect).toBe('Deny');
      expect(deny.Condition.StringNotEquals).toEqual({
        'aws:ResourceTag/project': '${aws:PrincipalTag/project}',
      });
      // Without this the Deny would also fire on untagged resources, turning an
      // implicit denial into an explicit one that no Allow can ever override.
      expect(deny.Condition.Null).toEqual({ 'aws:ResourceTag/project': 'false' });
    });

    test('roles are tagged with both dimensions, lowercase', () => {
      for (const role of roles as any[]) {
        const tags: Record<string, string> = Object.fromEntries(
          role.Properties.Tags.map((t: any) => [t.Key, t.Value]),
        );
        expect(tags.environment).toBe(environment);
        expect(PROJECTS).toContain(tags.project);
        // StringEquals is case-sensitive, so a capitalized tag is a silent denial.
        expect(tags.project).toBe(tags.project.toLowerCase());
        expect(tags.environment).toBe(tags.environment.toLowerCase());
      }
    });

    test('session length and role path match config', () => {
      for (const role of roles as any[]) {
        expect(role.Properties.MaxSessionDuration).toBe(MAX_SESSION_HOURS * 3600);
        expect(role.Properties.Path).toBe('/workforce/');
      }
    });

    // Tag-based access control is off by default on general purpose buckets.
    // Without it aws:ResourceTag never resolves bucket tags and every request
    // denies for the wrong reason, which looks like a broken policy.
    test('every demo bucket has tag-based access control enabled', () => {
      const demo = (buckets as any[]).filter(
        (b) => !String(b.Properties.BucketName).includes('-logs-'),
      );
      expect(demo.length).toBeGreaterThan(0);
      for (const b of demo) {
        expect(b.Properties.AbacStatus).toBe('Enabled');
      }
    });

    test('the control buckets are unreachable by design', () => {
      const byName = (needle: string) =>
        (buckets as any[]).find((b) => String(b.Properties.BucketName).includes(needle));

      const untagged = byName('-notags-');
      expect(untagged).toBeDefined();
      expect(untagged.Properties.Tags ?? []).toEqual([]);

      // One environment-mismatch control PER PROJECT, in the same account, so
      // every project's user can run the mismatch case rather than only the
      // first. In another account cross-account access would fail on its own
      // and prove nothing about the role tag.
      const other = environment === 'prod' ? 'dev' : 'prod';
      for (const project of PROJECTS) {
        const mismatch = byName(`-${project}-${other}-`);
        expect(mismatch).toBeDefined();
        const tags = Object.fromEntries(
          mismatch.Properties.Tags.map((t: any) => [t.Key, t.Value]),
        );
        expect(tags.project).toBe(project);
        expect(tags.environment).toBe(other);
      }
    });

    test('every project gets a reachable bucket and a mismatch control', () => {
      // 2 per project + the untagged control + the access log destination.
      expect(buckets).toHaveLength(PROJECTS.length * 2 + 2);
    });

    test('all buckets block public access, encrypt, version and require TLS', () => {
      for (const b of buckets as any[]) {
        expect(b.Properties.PublicAccessBlockConfiguration).toEqual({
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
        });
        expect(b.Properties.BucketEncryption).toBeDefined();
        expect(b.Properties.VersioningConfiguration.Status).toBe('Enabled');
        expect(b.Properties.OwnershipControls.Rules).toEqual([
          { ObjectOwnership: 'BucketOwnerEnforced' },
        ]);
      }
      // enforceSSL and minimumTLSVersion render as bucket policy Denies.
      const policies = Object.values(resources).filter(
        (r: any) => r.Type === 'AWS::S3::BucketPolicy',
      );
      expect(policies).toHaveLength(buckets.length);
      for (const p of policies as any[]) {
        const denies = p.Properties.PolicyDocument.Statement.filter(
          (s: any) => s.Effect === 'Deny',
        );
        expect(denies.length).toBeGreaterThanOrEqual(2);
      }
    });
  },
);

describe('EntitlementStack', () => {
  const app = new App();
  const stack = new EntitlementStack(app, 'AbacDemo-Entitlements', {
    env: { account: MANAGEMENT_ACCOUNT_ID, region: REGION },
  });
  const template = Template.fromStack(stack);

  test('creates one group per project', () => {
    template.resourceCountIs('AWS::IdentityStore::Group', PROJECTS.length);
  });

  test('creates one entitlement per project per target account', () => {
    template.resourceCountIs(
      'AWS::AccountAccess::Entitlement',
      PROJECTS.length * TARGET_ACCOUNTS.length,
    );
  });

  // Entitlement role ARNs are matched exactly. If the name this stack builds
  // ever diverges from the name AbacStack creates, entitlement creation fails
  // at runtime with nothing wrong at deploy time. Both call roleNameFor, and
  // this asserts the resulting ARNs really are the role names in use.
  test('entitlements point at the exact role names AbacStack creates', () => {
    const deployedNames = TARGET_ACCOUNTS.flatMap(({ accountId, environment }) => {
      const app = new App();
      const s = new AbacStack(app, `Probe-${environment}`, {
        env: { account: accountId, region: REGION },
        environmentName: environment,
      });
      return Object.values(Template.fromStack(s).toJSON().Resources as Record<string, any>)
        .filter((r: any) => r.Type === 'AWS::IAM::Role')
        .map((r: any) => r.Properties.RoleName as string);
    });

    const resources = template.toJSON().Resources as Record<string, any>;
    const entitlements = Object.values(resources).filter(
      (r: any) => r.Type === 'AWS::AccountAccess::Entitlement',
    );
    expect(entitlements.length).toBeGreaterThan(0);

    for (const e of entitlements as any[]) {
      const arn = JSON.stringify(e.Properties.Entitlement.PrincipalRole.RoleArn);
      const referenced = PROJECTS.map(roleNameFor).find((n) =>
        arn.includes(`role/workforce/${n}`),
      );
      expect(referenced).toBeDefined();
      expect(deployedNames).toContain(referenced);
    }
  });
});
