import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import { buildAbacPolicy, createWorkforceBoundary } from './abac-policy';
import { createProjectRole } from './project-role';
import {
  AAM_APPLICATION_ID,
  MANAGEMENT_ACCOUNT_ID,
  MAX_SESSION_HOURS,
  PROJECTS,
  RESOURCE_PREFIX,
} from './config';

export interface AbacStackProps extends cdk.StackProps {
  /**
   * Value of the `environment` role tag for every role in this stack, and one
   * of the two ABAC dimensions. Comes from TARGET_ACCOUNTS in config.ts.
   */
  readonly environmentName: string;
}

/**
 * Deploy once per target account.
 *
 * Creates one IAM role per project. The roles are identical in every respect
 * except their tags, and they share a single policy document that names no
 * project, environment, account or bucket.
 */
export class AbacStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: AbacStackProps) {
    super(scope, id, props);

    const { environmentName } = props;
    const managementAccountId = MANAGEMENT_ACCOUNT_ID;
    const aamApplicationId = AAM_APPLICATION_ID;
    const projects = PROJECTS;

    // Access logging records who read which object, independently of
    // CloudTrail. This bucket does not log to itself, the one accepted
    // exception.
    const logBucket = new s3.Bucket(this, 'AccessLogs', {
      bucketName: `${RESOURCE_PREFIX}-logs-${this.account}-${this.region}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      minimumTLSVersion: 1.2,
      versioned: true,
      // CDK's `serverAccessLogsBucket` is avoided throughout this stack
      // because it re-enables ACLs. The policy-based grant below is the modern
      // equivalent and keeps ACLs off.
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      lifecycleRules: [{ expiration: cdk.Duration.days(90) }],
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    logBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowS3ServerAccessLogDelivery',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('logging.s3.amazonaws.com')],
      actions: ['s3:PutObject'],
      resources: [logBucket.arnForObjects('*')],
      conditions: {
        // Confused-deputy protection on the logging service principal.
        StringEquals: { 'aws:SourceAccount': this.account },
      },
    }));

    const boundary = createWorkforceBoundary(this, environmentName);

    // Built once, outside the loop, and handed to every role. That is what
    // makes the documents byte-identical rather than merely equivalent.
    const abacPolicy = buildAbacPolicy();

    for (const project of projects) {
      const role = createProjectRole(
        this,
        project,
        environmentName,
        managementAccountId,
        aamApplicationId,
        this.region,
        {
          permissionsBoundary: boundary,
          abacPolicy,
          maxSessionHours: MAX_SESSION_HOURS,
        },
      );

      new cdk.CfnOutput(this, `Role${project}Arn`, { value: role.roleArn });
    }

    // Demo buckets, so the test matrix in the post can be run in full.
    //
    // Two per project: one this account's roles can reach, and one tagged with
    // the opposite environment that they cannot. The mismatch bucket is the
    // control that matters, and it lives in the SAME account on purpose, so the
    // role tag is the only thing that can explain a denial. In another account
    // cross-account S3 would fail on its own and prove nothing about tags.
    //
    // One per project rather than one overall: with a single control bucket
    // only the first project's user can run the environment-mismatch case.
    const otherEnvironment = environmentName === 'prod' ? 'dev' : 'prod';
    const demoBuckets: { label: string; tags?: Record<string, string> }[] = [
      ...projects.map((p) => ({
        label: `${p}-${environmentName}`,
        tags: { project: p, environment: environmentName },
      })),
      ...projects.map((p) => ({
        label: `${p}-${otherEnvironment}`,
        tags: { project: p, environment: otherEnvironment },
      })),
      { label: 'notags' }, // ABAC on, no tags. Unreachable by every role.
    ];

    for (const spec of demoBuckets) {
      const bucket = new s3.Bucket(this, `Bucket${spec.label}`, {
        // Lowercase the label only. toLowerCase() on the whole string mangles
        // the unresolved account token and breaks name validation.
        bucketName: `${RESOURCE_PREFIX}-${spec.label.toLowerCase()}-${this.account}`,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        encryption: s3.BucketEncryption.S3_MANAGED,
        enforceSSL: true,
        minimumTLSVersion: 1.2,
        versioned: true,
        objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      });

      // At L1 to avoid CDK's ACL-based logging wiring.
      (bucket.node.defaultChild as s3.CfnBucket).loggingConfiguration = {
        destinationBucketName: logBucket.bucketName,
        logFilePrefix: `${spec.label}/`,
      };

      // Tag-based access control is OFF by default on general purpose buckets.
      // Without this, aws:ResourceTag never resolves bucket tags and every
      // request denies for the wrong reason. CloudFormation uses the newer
      // tagging APIs, so setting tags and status together is safe; by CLI you
      // must tag BEFORE enabling.
      (bucket.node.defaultChild as s3.CfnBucket).abacStatus = 'Enabled';

      for (const [k, v] of Object.entries(spec.tags ?? {})) {
        cdk.Tags.of(bucket).add(k, v);
      }

      new cdk.CfnOutput(this, `Bucket${spec.label}Name`, {
        value: `${bucket.bucketName} [${
          spec.tags
            ? Object.entries(spec.tags).map(([k, v]) => `${k}=${v}`).join(' ')
            : 'no tags'
        }]`,
      });
    }
  }
}
