# Sign-up, login and the console API

This is the contract for a web frontend (sign-up, login, a console) on top of the service. The service ships the
backend only; the pages are yours to build. The machine-readable description is
[openapi-portal.yaml](openapi-portal.yaml); this page explains how the pieces fit and what a frontend must do.

```
POST /v1/portal/signup   email, password, company_name, accept_terms  -> a 6-digit code is emailed
POST /v1/portal/confirm  email, code     -> the address is confirmed and the person's tenant is created
POST /v1/portal/login    email, password -> an ID token (for /v1/console/*) and a refresh cookie
POST /v1/portal/refresh  (cookie)        -> a fresh ID token            POST /v1/portal/logout (cookie)
POST /v1/portal/resend, /v1/portal/forgot, /v1/portal/reset
ANY  /v1/console/...                     -> the admin API (docs/openapi-tenant.yaml), as a signed-in person
```

Amazon Cognito holds the passwords and issues the tokens, but **browsers never talk to Cognito**: the portal
Lambda is the only function that can sign people up or in, and it adds the limits Cognito does not have.

## What the frontend must do

1. **Be served from the same domain as the API routes.** There is no CORS: the browser must reach
   `/v1/portal/*` and `/v1/console/*` on the page's own origin. `site.yml` does this: one CloudFront distribution
   serves your static files from a private bucket and sends those paths (and `/v1/site/*`) to the API.
   The `SiteOrigin` parameter of the app stack must be exactly your pages' origin (`https://yourdomain`); the
   portal refuses a request whose `Origin` (or, failing that, `Referer`) is anything else.
2. **Send `X-Requested-With: mcp-portal` on every `/v1/portal/*` call**, with `Content-Type: application/json`.
   A browser will not add that header to a request made by another website without a CORS preflight, which this
   API never grants. Without it the answer is `403 FORBIDDEN`.
3. **Keep the ID token in memory only** (a variable), never in `localStorage`, `sessionStorage` or a cookie. It is
   valid for 15 minutes (`expires_in`). Send it as `Authorization: Bearer <id_token>` to `/v1/console/*`.
4. **Never touch the refresh cookie.** Login sets `mcp_rt` (`HttpOnly; Secure; SameSite=Strict; Path=/v1/portal/`,
   12 hours); scripts cannot read it and the browser sends it only to `/v1/portal/*`. Call
   `POST /v1/portal/refresh` on page load and shortly before the token expires; a `401 NO_SESSION` means "show the
   login page" (the service has already cleared the cookie). `POST /v1/portal/logout` revokes it.
5. **Serve a strict content security policy** (no inline script, `connect-src 'self'`). The API never returns
   markup; build the DOM with `textContent`, not `innerHTML`, when you show names or messages from the API.
6. **Add a hidden form field named `website`** to the sign-up form if you want the honeypot: leave it empty for
   people (a bot that fills it in gets a fake success and a counted attempt). It is optional.

## Flow

1. **Sign up**: `signup` with the email, a password (12 to 128 characters, a capital, a lower-case letter and a
   number), a company or project name (2 to 100 characters) and `accept_terms: true`. The answer is
   `{"status": "code_sent"}` whether or not the address already has an account (a person who lost the first code
   can simply sign up again).
2. **Confirm**: `confirm` with the 6-digit code. The first confirmation creates the tenant (active at once, id
   `mcp-xxxxxx`) and emails the operator. `resend` sends another code.
3. **Log in**: `login` returns `{"id_token", "expires_in", "email", "tenant_id"}` and sets the cookie. A wrong
   password and an unknown address both answer `401 BAD_LOGIN`.
4. **Use the console**: `/v1/console/...` mirrors `/v1/admin/...` (same operations, same bodies): licenses, API
   keys, seats, the tenant's settings and status, the audit log. The tenant comes only from the signed token, so
   a person can reach only their own. A disabled or banned tenant gets `403 TENANT_DISABLED` on every call.
5. **Forgot password**: `forgot` emails a code (same answer for every address); `reset` sets the new password.

Every error is `{"error": {"code": "...", "message": "..."}}` and the message is safe to show. Limits (all
settings, see the README): 3 sign-up, resend or forgot requests per visitor, then a 30-minute lock; 3 emails per
address per hour; a daily cap on sign-ups; 20 login attempts per visitor, then 15 minutes. They answer
`429 TOO_MANY` and the message says how long to wait.

## A minimal client

Plain browser JavaScript, no dependencies. `BASE` is empty because the page and the API share an origin.

<!-- example:login-client -->
```javascript
const BASE = "";  // same origin as the page
let idToken = null;  // in memory only: never localStorage

async function portal(path, body) {
  const response = await fetch(BASE + "/v1/portal/" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Requested-With": "mcp-portal" },
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = data.error || {};
    throw Object.assign(new Error(error.message || "Request failed"), { status: response.status, code: error.code });
  }
  return data;
}

function keepSession(session) {
  idToken = session.id_token;
  setTimeout(() => portal("refresh").then(keepSession).catch(() => { idToken = null; }),
             Math.max(1, session.expires_in - 60) * 1000);
  return session;
}

const login = (email, password) => portal("login", { email, password }).then(keepSession);
// On page load: a signed-in person still has the cookie. Resolves to null when they must log in.
const restoreSession = () => portal("refresh").then(keepSession).catch((e) => { if (e.status === 401) return null; throw e; });

async function api(method, path, body) {  // the admin API as the signed-in person, e.g. api("GET", "licenses")
  const response = await fetch(BASE + "/v1/console/" + path, {
    method,
    headers: { "Authorization": "Bearer " + idToken, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error((data.error || {}).message || "Request failed"), { status: response.status });
  return data;
}
```

## Trying it without AWS

`python scripts/dev_server.py` runs the real handlers against in-memory AWS and a stand-in for Cognito, on
http://localhost:8780. Pass `--dir <your frontend folder>` to serve your pages from the same origin, as in
production. The emailed codes are listed at `/__dev/codes` and the operator's notifications at
`/__dev/notifications`. Its token check does not verify signatures; the real API Gateway authorizer does.
