# Integrating the license check

Everything a tool needs to check a license, and what to do with the answer. The examples use the hosted address
`https://api.mcplicense.net`; if you run your own deployment, use its public API address instead.

## Concepts

* **Tenant**: the provider. Everything a tenant creates belongs to it and is invisible to others. A generated
  tenant id looks like `mcp-k7m2x9`.
* **License**: what a provider sells to one customer. It has a key, a number of seats, and an expiry date.
* **License key**: `<tenant id>_XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`. The prefix names the tenant, so a customer only
  ever pastes one string. Upper or lower case both work. The key is shown once when it is created; only a hash is
  stored.
* **Seat**: one device using a license. A license with 3 seats works on 3 devices.
* **Device id**: any stable string the tool chooses for an installation, up to 128 characters. A random id saved
  on first run is ideal. Do not use anything that identifies a person.
* **Lease**: each successful check holds the device's seat for the lease time (24 hours by default). A device
  that stops checking in loses its seat when the lease ends, and the seat can go to a new device.

## The verify request

```
POST https://api.mcplicense.net/v1/mcp/verify
Content-Type: application/json

{"license_key": "mcp-k7m2x9_ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2", "device_id": "laptop-7f3a"}
```

No other credentials are needed. Send it when your tool starts, and again whenever the cached answer is older
than `cache_ttl_seconds`.

## Responses and reason codes

A valid license answers `200`:

```json
{
  "valid": true,
  "reason": "OK",
  "tenant_id": "mcp-k7m2x9",
  "license_id": "9f1c2ab34d5e",
  "seats_used": 1,
  "seats_max": 3,
  "expires_at": "2027-12-31",
  "lease_duration_sec": 86400,
  "lease_expires_at": 1793243644,
  "cache_ttl_seconds": 300
}
```

Anything else is a refusal with `"valid": false`, a `reason` and a `message`:

| HTTP | reason | Meaning | What your tool should do |
|---|---|---|---|
| 401 | `INVALID_KEY` | The key is malformed or unknown. | Stop. |
| 403 | `LICENSE_REVOKED` | The license was revoked. | Stop. |
| 403 | `LICENSE_EXPIRED` | Past its expiry date. | Stop. |
| 403 | `SEAT_LIMIT` | Every seat is held by a device with a live lease. | Stop and tell the user. |
| 403 | `TENANT_DISABLED` | The provider (or the platform) has suspended the tenant. | Stop. |
| 403 | `GLOBAL_DISABLED` | Licensing is switched off platform-wide. | Stop. |
| 429 | `RATE_LIMITED` | Too many requests for this tenant. The body has `retry_after_seconds`. | Not a denial. Keep running on your last good answer and retry later. |

A malformed request (a missing field, say) answers `400` with `{"error": {"code": ..., "message": ...}}`. A `5xx`
or a network failure means the check could not be made.

**Timeouts and retries.** The first check after the service has been idle can take a few seconds, so give each
request about 9 seconds (the examples below do), and when the check could not be made, try again a few times with
short pauses (half a second, then one, two, four) before you give up. Repeating a check is safe: the same device
only renews its seat. For a `429`, wait the `retry_after_seconds` the answer names (but no more than about ten
seconds). The Python helper `client/mcp_auth.py` does all of this and lets you change the numbers
(`MCP_LICENSE_TIMEOUT`, `MCP_LICENSE_RETRIES`, `MCP_LICENSE_DEADLINE`).

**The rule to follow:** a `401` or `403` that carries a `reason` is a decision about the license: stop, and discard
anything you cached. Everything else (a network error, a `429`, a `5xx`, a block page from a proxy) means "could
not check", and you decide whether to keep running.

## Python example

Standard library only.

<!-- example:python -->
```python
import json
import os
import sys
import urllib.error
import urllib.request

API_URL = "https://api.mcplicense.net"


def check_license(license_key, device_id):
    """Return (True, info) for a valid license and (False, info) for a refusal.

    Raises when the check could not be made (network error, 429, 5xx)."""
    request = urllib.request.Request(
        API_URL + "/v1/mcp/verify",
        data=json.dumps({"license_key": license_key, "device_id": device_id}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=9) as response:
            return True, json.load(response)
    except urllib.error.HTTPError as error:
        try:
            body = json.load(error)
        except ValueError:
            body = {}
        if error.code in (401, 403) and body.get("reason"):
            return False, body  # a decision about the license
        raise


ok, info = check_license(os.environ["MCP_LICENSE_KEY"], "my-device-id")
if not ok:
    sys.exit("License check failed ({}): {}".format(info["reason"], info["message"]))
print("License OK")
```

## Node example

Node 18 or later, as an ES module (`.mjs`).

<!-- example:node -->
```javascript
const API_URL = "https://api.mcplicense.net";

// Resolves to { ok, info }, or throws when the check could not be made.
async function checkLicense(licenseKey, deviceId) {
  const response = await fetch(`${API_URL}/v1/mcp/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ license_key: licenseKey, device_id: deviceId }),
    signal: AbortSignal.timeout(9000),
  });
  const body = await response.json().catch(() => ({}));
  if (response.ok && body.valid) return { ok: true, info: body };
  if ([401, 403].includes(response.status) && body.reason) return { ok: false, info: body };
  throw new Error(`License check could not be made (HTTP ${response.status})`);
}

const { ok, info } = await checkLicense(process.env.MCP_LICENSE_KEY, "my-device-id");
if (!ok) {
  console.error(`License check failed (${info.reason}): ${info.message}`);
  process.exit(2);
}
console.log("License OK");
```

## Add it to your MCP server

Check the license once, before the server starts answering. A server that talks to its client over standard input
and output (the usual kind) must never print anything else to standard output, so the checks below write only to
standard error.

**Python** (with the official `mcp` package and the [mcp_auth.py](../client/mcp_auth.py) helper saved next to your
server):

<!-- example:mcp-python -->
```python
from mcp.server.fastmcp import FastMCP
import mcp_auth

# Reads MCP_LICENSE_KEY, checks it, and exits with a clear message when it is not valid.
mcp_auth.require_license(api_url="https://api.mcplicense.net")

mcp = FastMCP("my-tool")


@mcp.tool()
def hello(name: str) -> str:
    mcp_auth.require_license(api_url="https://api.mcplicense.net")  # optional: cached, so cheap on every call
    return "Hello, " + name


if __name__ == "__main__":
    mcp.run()
```

**Node** (with `@modelcontextprotocol/sdk`; `checkLicense` is the function from the Node example above):

<!-- example:mcp-node -->
```javascript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const { ok, info } = await checkLicense(process.env.MCP_LICENSE_KEY, "my-device-id");
if (!ok) {
  console.error(`License check failed (${info.reason}): ${info.message}`);  // stderr, never stdout
  process.exit(2);
}

const server = new McpServer({ name: "my-tool", version: "1.0.0" });
server.tool("ping", async () => ({ content: [{ type: "text", text: "pong" }] }));
await server.connect(new StdioServerTransport());
```

**Your customer** puts the key you gave them in the server's environment. In Claude Desktop's configuration file:

<!-- example:claude-desktop -->
```json
{
  "mcpServers": {
    "my-tool": {
      "command": "python",
      "args": ["server.py"],
      "env": { "MCP_LICENSE_KEY": "your-license-key" }
    }
  }
}
```

In Claude Code, the same thing on one line:

<!-- example:claude-code -->
```
claude mcp add my-tool --env MCP_LICENSE_KEY=your-license-key -- python server.py
```

The Python helper also accepts `--license-key` on the command line. A device is identified by a random id the
helper stores once under `~/.mcp_auth/`; in Node, pass any stable id of your own choosing for that machine.

## Caching and outages

You do not need to call the API on every use of your tool.

* After a valid answer, reuse it for `cache_ttl_seconds` (5 minutes by default). Then check again; each
  successful check renews the device's lease.
* If a later check *cannot be made*, you may keep running on your last valid answer until `lease_expires_at`
  (epoch seconds). After that the seat may already belong to another device, so stop.
* If a check returns a decision (`401`/`403` with a `reason`), stop and throw the cache away, whatever the lease
  says. That is how revocation and the kill switches take effect.
* Never store the license key in the cache file; store a hash if you need to tell keys apart.

A ready-made Python helper that does all of this is the single file [mcp_auth.py](../client/mcp_auth.py)
(standard library, Python 3.8+):

<!-- example:helper -->
```python
import mcp_auth
mcp_auth.require_license()   # reads MCP_LICENSE_KEY; exits with a clear message when not licensed
```

Set `MCP_LICENSE_API_URL=https://api.mcplicense.net`, or the `API_URL` constant in the file.

## Managing licenses

A provider can use the console (see [login-api.md](login-api.md) if you are building one) or script it with the
HTTPS API: create an admin API key and send it in the `X-Tenant-Api-Key` header. Create a license:

```
curl -X POST https://api.mcplicense.net/v1/admin/licenses \
  -H "X-Tenant-Api-Key: $MCP_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"label": "Jane laptop", "seats_max": 2, "expires_at": "2027-12-31"}'
```

The response contains the `license_key`. It is shown once, so hand it to the customer straight away. You can also
list licenses, change seats or expiry, revoke or reinstate one, rotate its key, see and free seats, suspend the
whole tenant, create more API keys, and read the audit log.

* [OpenAPI description](openapi-tenant.yaml) of every route above
* Postman: [collection](postman/mcp_licensing_tenant.postman_collection.json) and
  [environment](postman/mcp_licensing_tenant.postman_environment.json)

## Limits

These defaults apply to every tenant. They protect the service and keep costs predictable. A creation that would
pass one answers `403` with `LIMIT_REACHED`, and `GET /v1/admin/tenant` shows the limits and how much is used.
They are SSM settings, see the README.

| Limit | Default |
|---|---|
| Verify requests per minute, per tenant | 100 (more get `429 RATE_LIMITED`) |
| Active licenses | 50 |
| Seats per license | 10 |
| Seats across all active licenses | 200 |
| Active admin API keys | 5 |

With the 5-minute cache above, 100 requests a minute covers roughly 500 devices.
