# mcp_licensing

Serverless license verification for MCP tools: API Gateway **HTTP API**,
**Python Lambda**, **DynamoDB on-demand**, SSM Parameter Store for tunables.
No servers, no always-on cost.

A hosted version runs at https://mcplicense.net (sign up, console and docs there); this repository is the
source, released under the [Apache License 2.0](LICENSE). Security reports: see [SECURITY.md](SECURITY.md);
to contribute: [CONTRIBUTING.md](CONTRIBUTING.md).

This repository is the **backend and the infrastructure**: the API, the Lambdas, the tables, the sign-up and
login service (Cognito behind a portal Lambda), the CloudFront, WAF, mail and cost templates, and the
documentation of every route (`docs/`). It ships **no website**: the pages of the hosted service are not part of
it, and building a frontend for your own deployment is up to you. [docs/login-api.md](docs/login-api.md) is the
contract such a frontend follows, and [docs/integration.md](docs/integration.md) explains how a tool checks a
license.

## Who calls what

| Prefix | Caller | Credential | Tenant comes from |
|---|---|---|---|
| `/v1/mcp/*` | the MCP tool on an end user's machine | `license_key` in the JSON body | the key itself (`<tenant_id>_...`) |
| `/v1/admin/*` | a tenant's admin | header `X-Tenant-Api-Key` (role `tenant_admin`) | the key record, never the request |
| `/v1/super/*` | the platform owner | header `X-Tenant-Api-Key` (role `super_admin`) | path parameter |

The end user only ever pastes one string: the license key.

```
POST /v1/mcp/verify   {"license_key": "acme_7K2M9-X4QPD-8WHT3-NB6RC-ZV5YA", "device_id": "..."}
```

Full route list: [`docs/openapi-tenant.yaml`](docs/openapi-tenant.yaml) (customer facing) and
[`docs/openapi-internal.yaml`](docs/openapi-internal.yaml) (includes `/v1/super`).

## Keys

* **License key** `<tenant_id>_XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` — 25 random characters (~125 bits). The
  prefix is the tenant id (generated `mcp-xxxxxx`, or a chosen 3-12 lowercase letters/digits; see
  [Tenant ids](#tenant-ids)), so the tenant is resolved from the key.
  Only a SHA-256 hash is stored, and it is shown once at creation. Lookup is a query on the
  `key_hash_index` GSI under that tenant, so a key can never match another tenant's licenses.
* **Admin API key** `mcpk_<key_id>.<secret>` — checked inside the Lambda (hash + constant-time
  compare). Revoking a key takes effect immediately.
* Unknown tenant, wrong key and malformed key all return the same `INVALID_KEY`.

## Kill switches

A verify call is denied if **any** of these applies, checked in this order:

1. **Global** (`PUT /v1/super/kill-switch`) — every tenant. Platform owner only. `GLOBAL_DISABLED`
2. **Tenant, by platform** (`PUT /v1/super/tenants/{id}/status`) — only the platform can lift it. `TENANT_DISABLED`
3. **Tenant, by tenant admin** (`PUT /v1/admin/tenant/status`) — the tenant suspends/resumes itself. `TENANT_DISABLED`
4. **License** revoked (`LICENSE_REVOKED`) or past `expires_at` (`LICENSE_EXPIRED`)
5. **Seats** full of live leases (`SEAT_LIMIT`)

Every flip is written to `mcp_audit_log`. A tenant admin sees platform actions as `actor: platform`.

Denials return HTTP 401/403. The client helper treats those as final: it clears its cache and does
**not** use the offline grace window. Only network failures (and `429 RATE_LIMITED`, see below) use the
grace window, so the kill switch takes effect on the next check after `client_cache_ttl_seconds`
(default 5 minutes).

## Tables (all `PAY_PER_REQUEST`, point-in-time recovery on, retained on stack delete)

| Table | Key | Purpose |
|---|---|---|
| `mcp_tenant_detail` | `tenant_id` | tenant, `suspended_by_tenant`, `disabled_by_platform` |
| `mcp_license_detail` | `tenant_id` / `license_id`; GSI `key_hash_index` (`tenant_id`/`key_hash`) | licenses |
| `mcp_license_seat` | `tenant_id` / `license_id#device_id` | registered devices |
| `mcp_api_key` | `key_id`; GSI `tenant_id_index` | admin API keys (hashed) |
| `mcp_audit_log` | `tenant_id` (or `PLATFORM`) / `timestamp#id` | audit trail |
| `mcp_platform_control` | `control_key` | the global kill switch |
| `mcp_rate_counter` | `bucket` (`tenant_id#minute`) | verify counts per tenant per minute, contact/sign-up/login attempt counters and locks; items expire by DynamoDB TTL. Not retained, no PITR (disposable) |
| `mcp_banned_email` | `email_hash` | hashed, normalised addresses of banned tenants' owners, checked at sign-up |
| `mcp_spam_phrase` | `scope`, `name` | the contact form's spam phrases, edited by hand (see [Spam phrases](#spam-phrases)) |

dev and prod are deployed to different regions, so table names are the same in both.

## Configuration (SSM Parameter Store)

Every setting you may want to change lives in SSM under one prefix per stage, so you tune the service
from SSM and never touch code, DynamoDB or a deploy:

```
/mcp/prod/<setting>                          platform default
/mcp/prod/tenants/<tenant_id>/<setting>      override for one tenant (limit_* settings only)
```

| Setting | Default | Meaning |
|---|---|---|
| `default_seats_max` | 1 | seats of a new license when none is asked for |
| `default_license_days` | 365 | validity of a new license when no `expires_at` is given |
| `default_lease_duration_sec` | 86400 | seat lease (24h); tenants and licenses may override it |
| `client_cache_ttl_seconds` | 300 | how long a client may reuse a successful check |
| `limit_licenses_per_tenant` | 50 | active licenses per tenant |
| `limit_seats_per_license` | 10 | seats on one license |
| `limit_seats_per_tenant` | 200 | seats across a tenant's active licenses |
| `limit_api_keys_per_tenant` | 5 | active admin API keys per tenant |
| `limit_verify_per_min` | 100 | verify requests per tenant per minute |
| `contact_ip_attempts` | 3 | contact form messages one visitor may send before the lock |
| `contact_ip_lock_seconds` | 1800 | how long that lock lasts (30 minutes) |
| `contact_daily_cap` | 100 | contact form messages accepted per day in total |
| `contact_spam_filter` | 1 | 1 drops contact form messages with a link or a sales phrase (silently); 0 switches it off |
| `signup_ip_attempts` | 3 | sign-up, resend and password-reset requests one visitor may make before the lock |
| `signup_ip_lock_seconds` | 1800 | how long that lock lasts (30 minutes) |
| `signup_email_per_hour` | 3 | emails (codes) sent to one address per hour |
| `signup_daily_cap` | 200 | sign-up requests accepted per day in total |
| `login_ip_attempts` | 20 | login attempts one visitor may make before the lock |
| `login_ip_lock_seconds` | 900 | how long a login lock lasts (15 minutes) |
| `log_level` | INFO | Lambda log level |

* **Seed and change.** `python scripts/seed_config.py --stage prod --region us-east-1` creates the missing
  ones and **never overwrites** a value you set (run it again after a release adds a setting). Change a
  value with the console or `aws ssm put-parameter --name /mcp/prod/limit_seats_per_license --value 20
  --type String --overwrite`. For one tenant:
  `python scripts/seed_config.py --stage prod --region us-east-1 --tenant mcp-k7m2x9 limit_seats_per_license=50`.
  The template deliberately does **not** create these parameters, so a deploy can never reset them.
* **Lookup order** for a limit: the tenant's override, then the platform value, then the default built into
  `src/core/config.py`. A missing, junk or unreadable parameter falls back, it never breaks the service.
* **How fresh.** The admin and super Lambdas read SSM on every request (`CONFIG_CACHE_SECONDS=0`: a change
  applies to the very next call). The verify Lambda reuses what it read for **60 seconds**: it can run 100
  times a second and SSM allows about 40 reads a second by default, so reading on every verify would fail
  under load.
* **Not in SSM:** table names (Lambda environment variables), the origin secret (SSM SecureString under
  `/mcp-licensing-secrets/`, readable only by whoever deploys), and the global kill switch (DynamoDB: it is
  read on every verify and needs an audited write).

## Limits

Defaults for every tenant are in the table above. Creating a license or API key that would pass a limit
answers `403 LIMIT_REACHED`; `GET /v1/admin/tenant` shows a tenant its `limits` and `usage`.

* They apply when something is created or enlarged, **never retroactively**: a license that was fine when
  it was made keeps working and stays editable, and shrinking or renaming it is always allowed.
* Only **active** licenses count, so revoking a license frees its place (and reinstating one is checked
  again).
* Checking then writing is not a lock: two simultaneous requests can overshoot by one. These are fair-use
  limits, not a security boundary.
* A tenant that needs more gets an override in SSM; a "request a change" workflow can come later. The
  platform owner issuing a recovery API key is not limited.

## Tenant ids

A tenant id is the prefix of every license key. Self-service tenants get a generated id,
`mcp-xxxxxx`: six random characters from the unambiguous alphabet (no `0 1 i o`), about a billion
combinations, made unique by a conditional write. They are stored lowercase and may be shown as
`MCP-XXXXXX`; license keys accept either case. The platform owner can still choose a name (3-12 lowercase
letters or digits, such as `sfs`) by passing `tenant_id` to `POST /v1/super/tenants`, or omit it to
generate one. An id never changes.

## Banning a tenant

`POST /v1/super/tenants/{id}/ban {"reason": "..."}` shuts every door at once:

* the tenant is disabled: every license answers `TENANT_DISABLED`, and its admin API keys and console
  stop working (`403 TENANT_DISABLED`);
* the owner's login is disabled and signed out (the Cognito user is addressed by its `sub`, not its email);
* the owner's email address is recorded (hashed, normalised: case, `+tag` and Gmail dots do not matter), so it
  cannot sign up again.

`POST /v1/super/tenants/{id}/unban` undoes all of it. A tenant created by hand (no owner) can be banned too: it
is simply disabled. `PUT /v1/super/tenants/{id}/status {"disabled": true}` remains for disabling a tenant
without touching its owner's login. Only the platform can lift a disable. (A tenant that merely suspends
itself keeps console and API access, because it needs it to resume.) You are told of every new sign-up by
email, with the ban call in the message.

## Self-service sign-up and the console

People sign up on the website, confirm their email address and get a tenant of their own, active at once, with the
default [limits](#limits). Nothing in this flow involves you except the email telling you someone joined.

```
POST /v1/portal/signup   email, password, company_name, accept_terms   -> a 6-digit code is emailed
POST /v1/portal/confirm  email, code     -> the address is confirmed and the tenant (mcp-xxxxxx) is created
POST /v1/portal/login    email, password -> an ID token for /v1/console/*, and a refresh cookie
POST /v1/portal/refresh  (cookie)        -> a fresh ID token          POST /v1/portal/logout
POST /v1/portal/forgot, /v1/portal/reset, /v1/portal/resend
ANY  /v1/console/...                     -> the admin operations, for a signed-in person (the same handlers)
```

* **Amazon Cognito holds the passwords and issues the tokens; browsers never talk to it.** The user pool's app
  client has a secret that only the portal Lambda holds, and the portal is the only function that can sign
  people up or in. It also enforces what Cognito cannot: per-visitor limits (3 sign-ups then a 30-minute lock;
  20 logins then 15 minutes), 3 emails per address per hour, a daily cap, a hidden honeypot field, and a ban list.
* **Nothing reveals whether an address has an account.** Sign-up, resend and forgot answer identically for
  everyone, and a wrong password and an unknown address get the same answer.
* **Tokens.** The ID token (15 minutes) lives only in the page's memory and is sent as
  `Authorization: Bearer`. The refresh token (12 hours) is an `HttpOnly; Secure; SameSite=Strict` cookie scoped to
  `/v1/portal/`, which scripts cannot read. A page reload asks `/v1/portal/refresh` for a new ID token.
  Every portal call must come from the site (`Origin`) and carry `X-Requested-With`.
* **Tenant isolation.** `/v1/console/*` is protected by API Gateway's JWT authorizer (signature, issuer, audience);
  the Lambda then takes the tenant only from the signed `custom:tenant_id` claim, which the user cannot write
  (the app client's write list excludes it). A disabled tenant is refused on every call, which also covers a
  banned person's still-valid token. The platform's `/v1/super/*` routes are not reachable from the website's
  domain at all and accept no login.
* **The pool is permanent.** Settings that cannot be changed after creation (sign-in by email, the custom
  attributes) make CloudFormation *replace* the pool, which deletes every user; the pool is retained, protected
  from deletion, and `tests/test_identity_template.py` pins those settings. Passwords: 12+ characters with a
  capital, a lower-case letter and a number. Authenticator-app MFA is enabled as optional, but there is no page to
  enrol yet.
* **Email** (the codes) is sent by Cognito through SES from `no-reply@<EmailDomain>`; an empty `EmailDomain` (dev)
  uses Cognito's own sender, capped at 50 a day.
* **The frontend is yours to build.** [docs/login-api.md](docs/login-api.md) is the contract (headers, cookie,
  tokens, errors, a minimal client that its test runs against the real handlers) and
  [docs/openapi-portal.yaml](docs/openapi-portal.yaml) describes the routes, including `/v1/console/*`.
* **Try it locally with nothing in AWS:** `python scripts/dev_server.py` and open http://localhost:8780. It runs the
  real handlers against in-memory AWS and a stand-in for Cognito, lists the emailed codes at `/__dev/codes` and
  the operator's emails at `/__dev/notifications`. `--dir <folder>` serves your static pages on the same origin,
  as in production. (Its token check does not verify signatures; the real authorizer does.)

## Emergencies

What to do when the service is being attacked or a secret has leaked. Everything here uses the default AWS
profile and is undone with one command.

**Switch things off** (`scripts/emergency.py`, which sets the Lambdas' reserved concurrency to 0, so they refuse
every call within seconds and nothing is deleted):

| Command | Stops |
|---|---|
| `python scripts/emergency.py stop --level signups` | sign-up, login and the contact form |
| `python scripts/emergency.py stop --level console` | ... and the tenant console and the admin API |
| `python scripts/emergency.py stop --level all` | ... and the license check itself |
| `python scripts/emergency.py resume` | everything back on |
| `python scripts/emergency.py status` | shows what is running |

The platform function (`/v1/super/*`) is never stopped, so you can still ban a tenant or use the kill switch
while the rest is off. Stopping the license check makes clients see a server error, and the client helper treats
that as "could not check": tools keep running on their last answer until its lease ends. To refuse every license
instead, use the global kill switch (`PUT /v1/super/kill-switch`, see [Kill switches](#kill-switches)).

**Other levers**

* One bad tenant: `POST /v1/super/tenants/{id}/ban` (disables the tenant, its owner's login, and the email).
* Slow sign-ups without stopping them: lower `signup_daily_cap` or `signup_ip_attempts` in SSM (see
  [Configuration](#configuration-ssm-parameter-store)).
* Block what the managed WAF rules only log so far: deploy `edge.yml` with `ManagedRulesMode=Block`.
* Block one address or range: add an IP set rule to the web ACL in `edge.yml` (none exists today).
* Take the whole site and API offline: disable the two CloudFront distributions (the `DistributionId` outputs of
  `edge.yml` and `site.yml`); this takes 5 to 15 minutes to propagate.

**A secret has leaked**

* *Super key:* `python scripts/rotate_super_key.py --region us-east-1` revokes every active super key and prints a
  new one once. The old ones are refused on their next request.
* *A tenant's admin API key:* revoke it in the console (API keys) or `POST /v1/super/tenants/{id}/ban` if the
  tenant itself is the problem; a revoked key is refused at once.
* *A license key:* rotate it in the console (Licenses) or with `POST /v1/admin/licenses/{id}/rotate-key`.
* *The origin secret* (`OriginSecret`): follow the rotation steps under [Edge](#edge-cloudfront--waf).
* *AWS credentials:* rotate them in IAM first; the service itself holds none.

**Cost alarm.** `guard.yml` is a monthly AWS Budget that emails at 50% and 80% of actual spend and when the
forecast passes 100%. It covers the whole AWS account, so set `MonthlyBudgetUsd` for everything in it. CloudFormation
cannot change a budget's recipients in place (it tries to create a second budget with the same name), so to
change `AlertEmail` delete the stack and deploy it again; the stack holds nothing else:

```bash
aws cloudformation deploy --stack-name mcp-licensing-guard-prod --region us-east-1 --template-file guard.yml \
  --parameter-overrides AlertEmail=<you@example.com> MonthlyBudgetUsd=30
```

## Deploy

**prod** is in **us-east-1** and **dev** in **us-east-2**. Table names are fixed (`mcp_*`), so each
region holds one stack. Prod has four stacks, deployed in this order:

1. `template.yml` — the API, Lambdas, tables and the Cognito user pool.
2. `edge.yml` — CloudFront and WAF in front of the API, its certificate and DNS (see [Edge](#edge-cloudfront--waf)).
3. `site.yml` — the distribution that serves your frontend and sends the sign-up, login, console and contact
   paths to the API, behind the same WAF (see [Website](#website)).
4. `mail.yml` — email for the domain: sending identity and inbound forwarding (see [Mail](#mail)).

```bash
# once: the secret shared by the first two stacks. Keep it in a password manager (or SSM SecureString).
python -c "import secrets; print(secrets.token_urlsafe(48))"

# 1. app stack, then the settings and the first super key
sam build
sam deploy --stack-name mcp-licensing-prod --region us-east-1 --capabilities CAPABILITY_IAM \
  --s3-bucket <deploy-bucket> --parameter-overrides Stage=prod OriginSecret=<secret> \
  SiteOrigin=https://mcplicense.net EmailDomain=mcplicense.net ContactEmail=<inbox for contact form and sign-up messages>
python scripts/seed_config.py --stage prod --region us-east-1   # creates missing SSM settings, keeps yours
python scripts/seed_spam_phrases.py --region us-east-1         # the starter spam phrases, keeps your edits
python scripts/bootstrap_super_key.py --region us-east-1        # prints your super_admin key once

# 2. edge stack (ApiId is an output of the stack above)
aws cloudformation deploy --stack-name mcp-licensing-edge-prod --region us-east-1 \
  --template-file edge.yml --parameter-overrides DomainName=api.mcplicense.net \
  HostedZoneId=<route53-zone-id> ApiId=<ApiId> OriginSecret=<secret> AlarmEmail=<you@example.com>
```

`Stage=prod` refuses to deploy without `OriginSecret`: without it the Lambdas would accept requests
that skip WAF. **dev** is the same app stack with `Stage=dev` and no secret, in us-east-2, reached
directly on its raw URL (`ApiUrl` output; the stage name is part of that path) with no WAF or domain.
The first CloudFront deployment takes roughly 10-15 minutes.

Check the result with a call that bypasses CloudFront: the raw `ApiUrl` of the prod stack must answer
`403 FORBIDDEN`, and `https://api.mcplicense.net/v1/mcp/verify` must answer normally.

## Edge (CloudFront + WAF)

AWS WAF cannot be attached to an API Gateway HTTP API, so `edge.yml` puts **CloudFront** in front of
it and attaches WAF to CloudFront. Clients use `https://api.mcplicense.net` (no stage in the path).
CloudFront-scope WAF and certificates must live in us-east-1, which is why prod is there too.

* **Origin check.** CloudFront adds `X-Origin-Verify: <OriginSecret>` to every request. With
  `ORIGIN_SECRET` set, each Lambda refuses a request without it (`403 FORBIDDEN`, constant-time
  compare), so nobody can skip WAF by calling the raw API Gateway URL.
  *Rotate:* deploy the app stack with `OriginSecret=<new>` and `OriginSecretPrevious=<old>`, then the
  edge stack with `OriginSecret=<new>`, then the app stack again with `OriginSecretPrevious` empty.
* **Rate limits, per IP address, over 5 minutes** (WAF rate-based rules, parameters in `edge.yml`):

  | Path | Default |
  |---|---|
  | `/v1/mcp/*` | 600 |
  | `/v1/admin/*` | 100 |
  | `/v1/super/*` | 50 |
  | `/v1/portal/*` (sign-up, login, reset) | 60 |
  | `/v1/console/*` | 600 |
  | all of `/v1/` together | 2000 |
  | the website (everything outside `/v1/`) | 600 |

  The website shares this web ACL, so the API and the site have separate budgets: browsing the docs cannot
  use up what an office's MCP tools need.

  They **block from day one**, answering `429` with `retry-after`, not WAF's default `403`: the client
  helper treats a 403 carrying a license `reason` as a final denial, so a shared office address that
  hits a limit must not look like a revoked license. (The helper also no longer treats a 403 *without*
  a `reason`, such as a WAF block page, as a license decision.)
* **Managed rule groups** (common, known-bad-inputs, IP reputation) start in **Count** mode
  (`ManagedRulesMode`): they only log. Review `aws-waf-logs-mcp-licensing-prod` in CloudWatch Logs for
  about two weeks, then redeploy with `ManagedRulesMode=Block`. The log redacts `x-tenant-api-key` and
  `x-origin-verify`.
* **Per tenant** limiting is not done here (WAF cannot see the tenant): see [Rate limit](#rate-limit-per-tenant).
* **Alarms** (SNS email via `AlarmEmail`): more than `RequestAlarmThreshold` requests in 5 minutes, and a
  CloudFront 5xx rate above 5 percent. AWS Budgets is account-wide and not part of this stack.
* **Cost**, roughly: WAF about $11 a month fixed plus $0.60 per million requests; CloudFront about $1 per
  million requests; certificate, alarms and DNS records are free or cents.
* HTTP is refused (`https-only`); a redirect would turn a POST into a GET.

## Website

The service ships no frontend, but `site.yml` is the infrastructure for one: a private S3 bucket served through
CloudFront at your domain (`www` redirects to it), under the **same WAF web ACL as the API** (`WebAclArn` is an
output of the edge stack), with HSTS and strict security headers. The same distribution sends exactly
`/v1/site/*`, `/v1/portal/*` and `/v1/console/*` to the API, which is what lets a frontend call the sign-up,
login and console routes on its own origin (there is no CORS; see [docs/login-api.md](docs/login-api.md)). Set
the app stack's `SiteOrigin` to that origin.

The content security policy is `default-src 'none'` plus `'self'` for scripts, styles, images and connections, no
inline script or style, no framing. Your pages must fit it, or you loosen the policy in the `ResponseHeadersPolicy`
of `site.yml` knowingly. `tests/test_site_template.py` pins what keeps the bucket private and the headers strict,
and runs the CloudFront index-page rewrite function in Node when Node is installed.

```bash
# first time only: the stack. ApiId comes from the app stack; OriginSecret is the same secret as before.
aws cloudformation deploy --stack-name mcp-licensing-site-prod --region us-east-1 --template-file site.yml \
  --parameter-overrides DomainName=<your domain> HostedZoneId=<route53-zone-id> WebAclArn=<WebAclArn> \
  ApiId=<ApiId> OriginSecret=<secret>

# every time: upload your built pages and refresh the cache
aws s3 sync <your build folder> s3://<BucketName> --delete
aws cloudfront create-invalidation --distribution-id <DistributionId> --paths "/*"
```

Write your own privacy policy and terms before opening sign-up to the public: contracts need a party, and privacy
law (GDPR, India's data protection rules and others) expects the operator to be identifiable.
### Contact form

A plain HTML form (no JavaScript) posts to `POST /v1/site/contact`, handled by `src/handlers/contact.py`. The
site distribution sends only the path `/v1/site/*` to the API, with the origin secret, and without cookies,
query strings, API keys or the viewer's Host header.

* **Delivery:** a valid message is published to an SNS topic whose email subscription is the owner
  (`ContactEmail` parameter of the app stack, given at deploy time and confirmed once by the owner). The
  visitor is redirected to `/contact/thanks/`. Nothing is stored; logs record only that a message was sent.
* **Abuse protection, in order:** the post must come from the site (`SITE_ORIGIN`: Origin or Referer); a hidden
  field that only a bot fills in (answered like success, nothing sent, but it counts as an attempt); **3 messages
  per visitor, then a 30-minute lock** (the 4th starts the lock; the count restarts after 30 idle minutes); a
  **spam filter** (a link, or a sales phrase such as "SEO" or "backlinks", in the name or message: answered like
  success, nothing sent, the log records only the reason; `contact_spam_filter=0` switches it off, see
  [Spam phrases](#spam-phrases)); a daily cap on the whole form (100); size limits; WAF rate rule `rate-contact` (10 per 10 minutes per IP) in front.
  The three numbers are SSM settings above.
* **Spam phrases** live in the `mcp_spam_phrase` table, not in code, so a new pitch needs no deploy (see below).
* **Who is "a visitor":** the IPv4 address, or the IPv6 /64 (one subscriber holds a whole /64), read from
  `CloudFront-Viewer-Address`, which CloudFront sets itself. `X-Forwarded-For` is ignored because a visitor can
  forge it.
* **Why not a WAF Challenge:** it interrupts a plain form post and loses the posted data, so the form relies on
  the limits above instead.
* **Reading and replying:** messages arrive as emails from AWS Notifications with the sender's address in the
  body. To reply from the domain, see [Mail](#mail).

### Spam phrases

A contact message is dropped (silently: the sender still sees the thank-you page) when its name or text contains a
**link** (`http://`, `https://`, `ftp://`, `www.`; fixed in code, `src/core/spam.py`) or a **phrase** from the
`mcp_spam_phrase` table. The phrases are data, read on every post, so a change applies to the next message with
no deploy.

* **Rows.** One row per group: `scope` (`contact`), `name` (any label), `phrases` (one or many, separated by
  commas or lines), `enabled` (set `false` to switch a row off without deleting it) and an optional `note`.
  Edit them in the DynamoDB console (Create item / Edit item), by CSV import, or with the helper:

  ```bash
  python scripts/spam_phrases.py list
  python scripts/spam_phrases.py add "free quote" "domain renewal" --group custom
  python scripts/spam_phrases.py remove "free quote"
  python scripts/spam_phrases.py test "Hello, we offer SEO audits"
  ```

  The rows are also kept in git, in `scripts/data/spam_phrases.json`, so the table can be rebuilt and a change
  is reviewable. Two ways round:

  ```bash
  # the file is the source: add a phrase to it (or a new row), commit, then push it to the live table
  python scripts/seed_spam_phrases.py --region us-east-1 --merge     # adds missing rows and phrases; removes nothing
  # the table is the source: you edited it live, so record it
  python scripts/spam_phrases.py export                              # rewrites the file; commit it
  ```

  Without `--merge`, `seed_spam_phrases.py` only creates rows that do not exist, so it never undoes an edit.
  `scripts/data/spam_samples.txt` keeps real spam messages (separated by `-----`); a test fails if the starter
  phrases stop catching any of them, so add each new kind of spam there when you add its phrases.
* **Plain phrases, never patterns.** Matched whole-word, case-insensitively, spaces and hyphens alike; a trailing
  `*` matches word endings (`outsourc*`). An entry that is too short or long, has odd characters, or is an
  everyday word of this service ("license", "seat", "key", ...) is skipped and logged, so a careless edit cannot
  break the form or drop ordinary mail. `add` also refuses a phrase that would block one of the legitimate
  messages in `scripts/legit_messages.txt` (`--force` overrides).
* **Fallback.** If the table cannot be read or has no usable phrase, a short built-in list applies
  (`FALLBACK_PHRASES`). Once the table has phrases it replaces that list.
* **Off switch.** `contact_spam_filter=0` in SSM switches the whole filter off; the log line
  `contact form: filtered as spam (<reason>)` shows what is being dropped, never the message.

## Mail

AWS does not give a domain a mailbox. `mail.yml` (SAM template, us-east-1) sets up what the domain needs:

* **Sending:** an SES domain identity with DKIM (2048 bit), a MAIL FROM subdomain so SPF lines up, an SPF record,
  and a DMARC policy of `quarantine`. No reporting address is published.
* **Receiving:** mail for `support@`, `abuse@` and `postmaster@` goes through SES (MX record), is virus- and
  spam-scanned, is stored in a private bucket for 30 days, and `mail/forwarder.py` forwards it to **one inbox**
  given at deploy time (`ForwardTo`). You read everything in that inbox; no other client is needed. The
  forwarded mail is *From* "<sender> via MCP Licensing" `<support@domain>` with *Reply-To* the original sender,
  attachments kept; a virus is dropped, suspected spam is marked "[Spam?]", a message already forwarded is never
  forwarded again, and one too large to send is replaced by a notice saying where it is kept.
* **Replying as the domain:** `python scripts/smtp_credentials.py --domain mcplicense.net --region us-east-1`
  creates an IAM user that can only send as `support@`, and prints SMTP credentials once. Add them in the inbox's
  "Send mail as" settings so replies show `support@mcplicense.net` and never your own address.
  `... --check --user <name>` (password in `SMTP_PASSWORD`) tests a login without sending anything.

```bash
sam build --template-file mail.yml --build-dir .aws-sam/mail
sam deploy --template-file .aws-sam/mail/template.yaml --stack-name mcp-licensing-mail --region us-east-1 \
  --capabilities CAPABILITY_IAM --s3-bucket <deploy-bucket> \
  --parameter-overrides DomainName=mcplicense.net HostedZoneId=<route53-zone-id> ForwardTo=<inbox address>

# SES allows one ACTIVE receipt rule set per region and CloudFormation cannot activate it: once, by hand
aws ses set-active-receipt-rule-set --rule-set-name mcp-licensing-inbound --region us-east-1
```

While SES is in **sandbox** it sends only to verified addresses, so the deploy sends a verification email to
`ForwardTo`: click it once, or forwarding fails. After SES production access is granted, redeploy with
`VerifyForwardTo=false`. A forwarder failure raises an email alarm and the message stays in the bucket.

**Runtime:** the code targets Python 3.11 syntax, but AWS no longer allows *creating* `python3.11`
functions (disabled 2026-07-31), so the template's `LambdaRuntime` parameter defaults to
`python3.12`.

## Customer documentation (Postman)

`docs/postman/` holds a collection plus environment for tenants
(`mcp_licensing_tenant.*`: verify + admin routes, no platform endpoints) and one for the platform
owner (`mcp_licensing_super.*`, keep internal). Regenerate everything from the route table in
`scripts/build_docs.py`:

```bash
python scripts/build_docs.py
```

Tests fail if the docs are stale or if the route table drifts from `template.yml` or the handlers.

## Client helper

[`client/mcp_auth.py`](client/mcp_auth.py) — one file, standard library only (Python 3.8+).

```python
import mcp_auth
mcp_auth.require_license()      # reads --license-key or MCP_LICENSE_KEY; exits if not licensed
```

Set `MCP_LICENSE_API_URL` (or the `API_URL` constant when you ship the tool). A random
`device_id` is created once in `~/.mcp_auth/`. Success is cached for the server's
`cache_ttl_seconds`; if the API is unreachable a previous success is honoured only until the
server's `lease_expires_at` (see Seat leases).

**Timing.** The first call after the service has been idle (a cold Lambda) takes a few seconds, so the
helper waits up to **9 seconds** for an answer and, when none comes (a timeout, a network error, a 5xx, or a
429 after the pause the service asks for), tries again up to **5 more times**, never taking more than **45
seconds** in all. A decision (valid, or a 401/403 with a `reason`) is final and never retried; repeating a
check is harmless, the same device only renews its seat. Each value is an environment variable, or the
constant of the same name at the top of the file as the default for a build you ship:

| Environment variable | Constant | Default | Allowed |
|---|---|---|---|
| `MCP_LICENSE_TIMEOUT` | `TIMEOUT_SECONDS` | 9 | 1 to 25 |
| `MCP_LICENSE_RETRIES` | `RETRIES` | 5 | 0 to 10 |
| `MCP_LICENSE_DEADLINE` | `DEADLINE_SECONDS` | 45 | 5 to 120 |

A bad value is ignored (the default is used). Keep the deadline under the time your host gives a tool to
start (a chat app allows about a minute). When a recent success can still be honoured offline, the helper asks
once and does not retry, so an offline laptop starts at once.

## Rate limit (per tenant)

Verify is limited **per tenant, per minute**: **100** requests by default, counted across all of the
tenant's licenses and devices and whatever IPs they come from. Over the limit, verify answers
`429 RATE_LIMITED` with `retry_after_seconds` and does nothing else (no seat, no lease renewal).

* **Default:** SSM `/mcp/<stage>/limit_verify_per_min` (100).
* **One tenant:** an override at `/mcp/<stage>/tenants/<tenant_id>/limit_verify_per_min`; delete it to go
  back to the default. No API route changes it, so a tenant can see its limit
  (`limits.verify_per_min` on `GET /v1/admin/tenant`) but not raise it.
* **Who is counted:** only requests with a valid key for an active license of an enabled tenant. Wrong,
  revoked or expired keys and disabled tenants are answered before the counter, so nobody without a
  working key can use up a tenant's quota and lock its real users out.
* **Order:** global kill switch, key, tenant, license status, expiry, **rate limit**, seat.
* **Window:** fixed one-minute windows, one atomic conditional write per request, so concurrent
  requests cannot pass the limit. A request refused is not counted. A tool can send up to the limit
  at the end of one minute and again at the start of the next.
* **Client:** `429` is not a denial. `mcp_auth.py` treats it like a network failure and keeps running
  on its last success until `lease_expires_at`.
* **Fails open:** if the counter table itself errors, the request goes through and the error is
  logged: the limiter protects the service, it is not a licensing check.
* A tenant's real users share its limit, so size it for the tenant: with the 5-minute client cache each
  device checks in about once per 5 minutes, so 100 per minute covers roughly 500 devices. Raise it for
  larger customers.
* Not covered here: a per-IP limit and protection against floods of invalid keys. That belongs at the
  edge (WAF in front of the API), not in the Lambda.

## Seat leases (automatic release)

A seat is a lease, not a permanent claim. Each successful verify stores
`lease_expires_at` (epoch seconds) on the device's row in `mcp_license_seat`. If the device does not
check in and `current_epoch > lease_expires_at`, the seat counts as released: the next *new* device
that asks for a seat when the license is full takes it over. No sweeper, no manual cleanup.

* **Duration**, first match wins: the license's `lease_duration_sec`, the tenant's
  `lease_duration_sec` (`PATCH /v1/admin/tenant`), then the platform default
  `default_lease_duration_sec` (SSM, **86400 = 24h**). Allowed range 300-2592000; `null` clears an override.
* **Client:** `cache_ttl_seconds` is capped at a third of the lease so a missed check does not cost
  the seat, and the client's offline window ends at `lease_expires_at`. After that the server may
  already have given the seat away, so the tool must stop.
* A device returning after expiry keeps its own seat if nobody took it; otherwise it competes for a
  seat like any new device.
* Admins see `lease_expires_at` and `active` per seat, and `seats_active` on a single license.
  `seats_used` is the number of seat *rows*, which includes expired leases nobody has taken over yet.
* DynamoDB TTL is deliberately **not** enabled on seats: TTL deletes bypass the `seats_used` counter.

## Seat registration is atomic

New devices claim a seat with one `TransactWriteItems` (seat put with `attribute_not_exists` +
`seats_used` incremented only while `seats_used < seats_max`); taking over an expired seat is a second
transaction (delete the seat only if its lease is still the expired value we read + put the new
seat). DynamoDB enforces the limit at commit, so concurrent verifies can never exceed `seats_max`
and the counter cannot drift from the rows; a device that renews first cannot be taken over.
Contention (`TransactionConflict`) is retried with jitter and then returns `503 BUSY`, which
clients treat like a network error. `tests/test_seats.py` and `tests/test_leases.py` cover the races
(the test harness serialises moto requests to model DynamoDB, since moto has no locking).

## Development

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements-dev.txt
.venv/Scripts/python -m pytest        # moto-based, no AWS account needed (Node 18+, if installed, also runs the
                                      # JavaScript examples in the docs)
sam validate --lint
```

Tests build their tables from `template.yml`, so the schema cannot drift from the infrastructure.

## Layout

```
template.yml            HTTP API, 5 Lambdas, 9 tables, a Cognito user pool, SSM parameters, log groups
edge.yml                CloudFront + WAF + certificate + DNS in front of the API (us-east-1)
site.yml                frontend hosting: private S3 bucket + CloudFront + certificate + DNS (us-east-1)
mail.yml, mail/         email for the domain: SES identity, DNS, inbound forwarding Lambda (us-east-1)
guard.yml               monthly cost budget with email alerts (us-east-1)
src/handlers/           mcp.py (verify), admin.py (tenant admin), super_admin.py (platform)
src/core/               config, keys, auth, store (DynamoDB), audit, service, http, identity, cognito, clientip
client/mcp_auth.py      client-side helper
scripts/                bootstrap_super_key.py, rotate_super_key.py, emergency.py, seed_config.py, smtp_credentials.py, build_docs.py, dev_server.py
docs/                   OpenAPI + Postman (generated), integration.md, login-api.md
tests/
```


## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
