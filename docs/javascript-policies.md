# JavaScript Policy Runtime

Outgate can run a JavaScript policy module before a request leaves the proxy:

```bash
cargo run -- --intercept examples/intercept.mjs
```

The same path can be supplied with `INTERCEPT`:

```bash
INTERCEPT=examples/intercept.mjs cargo run
```

The module must export one default async function. It receives `request`, `env`,
and `ctx`; it can return `fetch(...)` with whatever request changes it needs:

```js
export default async function intercept(request, env, ctx) {
  const url = new URL(request.url);

  if (url.hostname === "api.example.test") {
    const headers = new Headers(request.headers);
    headers.set("authorization", `Bearer ${env.API_TOKEN}`);
    headers.set("x-outgate-request-id", ctx.requestId);
    return fetch(request, { headers, redirect: "manual" });
  }

  if (url.pathname === "/_deny") {
    return new Response("denied\n", { status: 403 });
  }

  return fetch(request, { redirect: "manual" });
}
```

The interceptor runs inside Deno's runtime worker from the `deno_runtime` crate.
That gives JavaScript the usual Deno runtime surface, including `Deno`, Web
APIs, `fetch`, timers, `Request`, `Response`, `Headers`, `URL`, and friends.

Outgate passes a native Web `Request` to the interceptor. Rust does not consume
or print the request body before this call; the body is exposed as
`request.body`, so JavaScript can read it through the normal Web APIs:

```js
const body = await request.text();
const contentType = request.headers.get("content-type");
```

Interceptors also receive a process-local `env.KV` store shared by every request
handled by the running proxy:

```js
const count = await env.KV.update("rate:example.com", (current) => {
  return (current ?? 0) + 1;
});

if (count > 60) {
  return new Response("rate limited\n", { status: 429 });
}
```

`env.KV.get(key)` resolves to the stored JSON value, or `undefined` when the key
is absent. `env.KV.put(key, value)` stores a JSON value; `undefined` is rejected
there. `env.KV.update(key, fn)` is an atomic read-modify-write: the callback
runs synchronously while the key-value store write lock is held, receives the
current value or `undefined`, and returns the new value. Returning `null` stores
`null`; returning `undefined` deletes the key. The store is in-memory only and
is cleared when the proxy process exits.

If the interceptor returns `fetch(...)`, Deno performs the upstream request and
Outgate returns that `Response` to the client. If it returns any non-`Response`
value, including `true`, `false`, `undefined`, `null`, a `Request`, or an action
object, Outgate denies the request with a default `403`.

Outgate streams proxied bodies in both modes. Without an interceptor, the Rust
path streams the client request body into `reqwest` and streams the upstream
response body back to the client. With an interceptor, headers and status are
sent as soon as JavaScript returns a `Response`, then `Response.body` chunks flow
from the Web stream through a Hyper channel. If policy code calls
`request.text()`, `request.arrayBuffer()`, `response.text()`,
`response.arrayBuffer()`, or similar before returning a new `Response`, that
JavaScript code is choosing to buffer.

The Rust-to-Deno body bridge passes byte chunks as op buffers, so JavaScript sees
normal `Uint8Array` chunks rather than base64 strings.

`fetch(...)` keeps normal Web Fetch semantics. Redirects are followed by
default, unlike `curl` without `-L`. To preserve an upstream redirect response
itself, opt into manual redirect handling:

```js
return fetch(request, { redirect: "manual" });
```

To make redirect following explicit at a policy callsite:

```js
return fetch(request, { redirect: "follow" });
```

The return value is intentionally fail-closed:

```text
Response          respond with that Web Response
fetch(...)        respond with that upstream Web Response
anything else     deny with a default 403
```

For request rewriting, the most idiomatic form is to fetch and return the
response:

```js
const headers = new Headers(request.headers);
headers.set("x-api-key", Deno.env.get("SERVICE_API_KEY"));
return fetch(request, { headers, redirect: "manual" });
```

See `examples/intercept_inject.mjs` for a focused secret-injection policy and
`examples/github_safe_agent.mjs` for a concrete agent action policy.

## Policy Directories

`--intercept` may also point at a directory. In that mode, every `.js`, `.mjs`,
`.cjs`, `.ts`, `.mts`, `.cts`, `.jsx`, and `.tsx` file in that directory is an
available interceptor, and the proxy username selects which file runs:

```bash
cargo run -- --intercept examples
curl \
  --proxy http://intercept_deno.mjs:x@127.0.0.1:9191 \
  http://example.invalid/_deno
```

The username must match the interceptor file name, including the extension. The
password is ignored, but keep it non-empty for better client compatibility.

The policy surface is Cloudflare-Worker-shaped at the edge of the API, while the
runtime inside is Deno rather than a hand-rolled Web API shim. The current
implementation creates a fresh Deno worker per request, keeping request
isolation straightforward and policy execution independent.
