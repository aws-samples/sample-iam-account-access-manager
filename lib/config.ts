/**
 * EDIT THIS FILE BEFORE DEPLOYING. Nothing else needs changing.
 *
 * The five REQUIRED values are specific to your organization. The rest have
 * working defaults. The README repeats these lookups in table form.
 */

/**
 * REQUIRED. Must match your IAM Identity Center instance.
 *
 * Account Access Manager runs only in AWS Commercial Regions that are enabled
 * by default. Opt-in Regions, GovCloud (US) and China are not supported.
 */
export const REGION = 'us-east-1';

/**
 * REQUIRED. Your AWS Organizations management account, where Identity Center
 * and Account Access Manager live.
 *
 * This is the MANAGEMENT account, not the account holding the roles. It goes
 * into aws:SourceAccount on every trust policy, and has to match the account
 * inside the application ARN, which is always created in the management account.
 *
 *   aws organizations describe-organization \
 *     --query 'Organization.MasterAccountId' --output text
 */
export const MANAGEMENT_ACCOUNT_ID = '111122223333';

/**
 * REQUIRED. The part of the application ARN after "application/". It goes into
 * aws:SourceArn, pinning trust to your one application.
 *
 * Create the application BEFORE deploying; the roles cannot be built without
 * this value. See README step 1.
 *
 *   aws account-access list-applications \
 *     --query 'applications[0].applicationArn' --output text
 *
 * Delete and recreate the application and this ID changes, which means every
 * role must be redeployed.
 */
export const AAM_APPLICATION_ID = 'EXAMPLEAPPID1234';

/**
 * REQUIRED only if you deploy the optional EntitlementStack.
 *
 * CloudFormation validates this against ^d-[0-9a-f]{10}$, so the placeholder is
 * shape-valid rather than descriptive. Replace it with your own before
 * deploying that stack.
 *
 *   aws sso-admin list-instances \
 *     --query 'Instances[0].IdentityStoreId' --output text
 */
export const IDENTITY_STORE_ID = 'd-0123456789';

/**
 * REQUIRED. The accounts holding the roles and the tagged resources.
 *
 * `environment` becomes the environment role tag for every role in that
 * account, and is one of the two ABAC dimensions. One entry is enough; the
 * walkthrough uses two to show the environment dimension working across
 * account boundaries.
 */
export const TARGET_ACCOUNTS: { accountId: string; environment: string }[] = [
  { accountId: '222233334444', environment: 'dev' },
  { accountId: '333344445555', environment: 'prod' },
];

/**
 * OPTIONAL. One IAM role per project per target account. Adding a project here
 * is the entire onboarding operation: redeploy, then create one entitlement per
 * account. No policy is written or reviewed.
 *
 * Keep these lowercase. Tag values are compared with StringEquals, which is
 * case-sensitive, so project=Phoenix will NOT match project=phoenix.
 */
export const PROJECTS = ['phoenix', 'atlas'];

/**
 * OPTIONAL. Prefix for every resource created here, matching the bucket names
 * in the blog post's architecture diagram. Bucket names are globally unique, so
 * the account ID is appended automatically.
 */
export const RESOURCE_PREFIX = 'aam-abac';

/**
 * OPTIONAL. Maximum role session length. Account Access Manager permits up to
 * 12 hours.
 *
 * Shorter is stricter: session length is the window in which a leaked
 * credential stays usable, and `aws login` refreshes automatically, so lowering
 * this is not user-visible. Reduce it if your posture calls for it.
 */
export const MAX_SESSION_HOURS = 4;
