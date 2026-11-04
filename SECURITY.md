# Security

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue.

Use GitHub's private reporting: open the repository's **Security** tab and choose **Report a vulnerability**.
If that is not available to you, use the contact form at https://mcplicense.net/contact and say it is a security
report; do not put details in the form, just ask for a private channel.

Include what you found, how to reproduce it, and what you think the impact is. We will acknowledge a report
within a few working days, keep you updated, and credit you when the fix is released if you wish.

## Scope

In scope: the code in this repository and the hosted service at `mcplicense.net` and `api.mcplicense.net`
(license checks, the tenant console, sign-up and login, the admin API).

Out of scope: denial-of-service or volume testing, social engineering, and findings that need a user's own
credentials to have been stolen already. Please do not test against other people's accounts or data.

## What the design relies on

These are the properties that matter most; a way around any of them is a vulnerability:

* a tenant can only see and change its own licenses, API keys and audit log;
* the platform (`/v1/super/*`) routes are not reachable from the website's domain and accept no login;
* API keys and license keys are stored only as hashes and shown once;
* the browser holds the short-lived ID token in memory only; the refresh token is an `HttpOnly` cookie;
* every request reaches the Lambdas through CloudFront and WAF (a shared origin secret is checked).

## Supported versions

Only the latest commit on `main` is supported.
