# Writing Policies

Policies are JavaScript modules. One default export, three arguments, one rule: return a `Response` or the request is denied.

```js
export default async function intercept(request, env, ctx) {
  // return a Response, or the request gets a 403
}
```

## The Signature

| Argument | Type | Contents |
|---|---|---|
| `request` | Web `Request` | The original request, body stream intact |
| `env` | Object | Process env vars + `env.KV` |
| `ctx` | Object | Per-request context |

`ctx` fields:

```js
ctx.requestId    // unique string per request
ctx.host         // "api.github.com:443"
ctx.hostname     // "api.github.com"
ctx.clientAddr   // "127.0.0.1:54321"
ctx.containerId  // OUTGATE_CONTAINER_ID env var, or null
```

## Return Values

```text
Response          → sent to the client as-is
fetch(...)        → upstream response sent to the client
anything else     → 403 Forbidden
```

Fail closed. Forgetting a return, returning `true`, returning `undefined` — all deny.

## Forwarding With Changes

Inject a credential the agent never holds:

```js
export default async function intercept(request, env, ctx) {
  const headers = new Headers(request.headers);
  headers.set("authorization", `Bearer ${env.API_TOKEN}`);
  return fetch(request, { headers, redirect: "manual" });
}
```

`redirect: "manual"` preserves redirect responses as-is. Use `"follow"` if you want the policy to chase them.

## Allowing Some Hosts, Denying Others

```js
const ALLOWED = new Set(["api.github.com", "api.linear.app"]);

export default async function intercept(request, env, ctx) {
  const { hostname } = new URL(request.url);

  if (!ALLOWED.has(hostname)) {
    return new Response(`${hostname} is not allowed\n`, { status: 403 });
  }

  const headers = new Headers(request.headers);
  headers.set("authorization", `Bearer ${env.API_TOKEN}`);
  return fetch(request, { headers, redirect: "manual" });
}
```

## Reading the Request Body

The body arrives as a native Web stream. Reading it consumes it — pass the text or buffer to `fetch` explicitly if you want to forward it:

```js
export default async function intercept(request, env, ctx) {
  const body = await request.text();

  // Deny requests that mention a sensitive repo name in the body
  if (body.includes("production-db")) {
    return new Response("denied\n", { status: 403 });
  }

  return new Response(body, {
    status: 200,
    headers: { "content-type": "text/plain" },
  });
}
```

To read and forward:

```js
const body = await request.text();
return fetch(request.url, {
  method: request.method,
  headers: request.headers,
  body,
});
```

## Rate Limiting

`env.KV` is a shared in-memory store. See [Shared KV store](kv.md) for the full API.

```js
export default async function intercept(request, env, ctx) {
  const { hostname } = new URL(request.url);
  const window = Math.floor(Date.now() / 60_000); // 1-minute bucket

  const count = await env.KV.update(`rate:${hostname}:${window}`, n => (n ?? 0) + 1);

  if (count > 60) {
    return new Response("rate limited\n", { status: 429 });
  }

  return fetch(request, { redirect: "manual" });
}
```

## Policy Directories

`--intercept` can point at a directory. Outgate supports two ways to map agent IDs to policy files.

### agents.json / agents.yaml manifest (recommended)

Drop an `agents.json` (or `agents.yaml`) file in the directory. It maps agent IDs to policy filenames:

```json
{
  "github": "github.mjs",
  "linear": "linear.mjs"
}
```

```bash
outgate --intercept ./policies
```

Launch an agent with the matching ID via Membrane:

```bash
membrane --agent-id github http://127.0.0.1:9191 -- claude
```

Or set the proxy username directly:

```bash
curl --proxy http://github:x@127.0.0.1:9191 https://api.github.com/user
```

If both `agents.json` and `agents.yaml` exist, Outgate refuses to start. Only one manifest is allowed.

### Filename-based (no manifest)

Without a manifest, every `.js`, `.mjs`, `.ts`, `.tsx` file in the directory becomes an available policy. The proxy username must match the full filename including extension:

```bash
# uses policies/github.mjs
curl --proxy http://github.mjs:x@127.0.0.1:9191 https://api.github.com/user
```

The password is ignored but should be non-empty for client compatibility.

### Hot reload

Outgate watches the directory and reloads when files or the manifest are added, changed, or removed. Running workers finish their current request; new requests pick up the new list.

## Runtime Surface

Policies run inside a Deno runtime worker. Available globals:

- `fetch`, `Request`, `Response`, `Headers`, `URL`, `URLSearchParams`
- `crypto`, `TextEncoder`, `TextDecoder`, `Blob`, `FormData`
- `setTimeout`, `clearTimeout`, `setInterval`, `clearInterval`
- `console`, `Deno.env`

Standard Web Fetch semantics apply. `import` works for local relative modules and URLs.

## Examples

- [`examples/intercept.mjs`](../examples/intercept.mjs) — host allow-list with credential injection
- [`examples/github_safe_agent.mjs`](../examples/github_safe_agent.mjs) — GitHub action policy
