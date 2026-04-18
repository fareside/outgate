# Shared KV Store

`env.KV` is an in-memory key-value store shared across all policy invocations. Use it for rate limiting, counters, caches, and any state that needs to survive across requests.

## API

```js
await env.KV.get(key)           // returns the stored value, or undefined
await env.KV.put(key, value)    // stores any JSON-serialisable value
await env.KV.update(key, fn)    // atomically read-modify-write
```

All keys are strings. Values are any JSON-serialisable type: numbers, strings, booleans, objects, arrays, or `null`.

## `get(key)`

Returns the stored value, or `undefined` if the key does not exist.

```js
const n = await env.KV.get("counter");
// n is a number, or undefined
```

## `put(key, value)`

Stores a value. Overwrites any existing value. Passing `null` stores a `null`; to delete a key, use `update`.

```js
await env.KV.put("flag", true);
await env.KV.put("config", { limit: 60 });
```

## `update(key, callback)`

Atomically reads the current value, passes it to `callback`, then writes the return value back.

```js
const next = await env.KV.update(key, current => {
  return (current ?? 0) + 1;
});
// next is the value that was written
```

Return semantics:

| Callback returns | Effect |
|---|---|
| any JSON value | stored as the new value |
| `null` | stored as `null` |
| `undefined` | key is **deleted** |
| a `Promise` | **error** — callback must be synchronous |

The callback is called synchronously while the write lock is held. No concurrent `get`, `put`, or `update` on any key can run until the callback returns. This makes `update` the safe path for counters and rate-limit windows.

## Concurrency

The store is protected by a single read-write lock:

- Multiple concurrent `get` calls proceed in parallel.
- Any `put` or `update` call takes an exclusive write lock.
- `update` holds the write lock for the duration of the callback.

State is visible to all policy workers immediately — there is no per-worker cache or transaction isolation.

## Persistence

The store is **in-memory only**. All state is lost when Outgate restarts. Do not use it as a durable database.

## Rate Limiting Example

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

Each minute bucket is a separate key. Old buckets are never deleted — for a short-lived process this is fine. If you need cleanup, track keys explicitly and delete them in a separate update pass.

## Deduplication Example

```js
const seen = new Set();

export default async function intercept(request, env, ctx) {
  const id = request.headers.get("x-request-id");

  if (id) {
    const already = await env.KV.update(`seen:${id}`, v => {
      if (v) return v;  // already set — no change, keep old value
      return true;      // first time — mark it
    });

    if (already === true && (await env.KV.get(`seen:${id}`)) !== true) {
      // already was the previous value — duplicate
      return new Response("duplicate\n", { status: 409 });
    }
  }

  return fetch(request, { redirect: "manual" });
}
```

Simpler: since `update` returns the value **written**, a first-time write returns `true` and a repeat write also returns `true`. Track whether it was newly set by checking the previous value:

```js
let isNew;
await env.KV.update(`seen:${id}`, v => {
  isNew = v === undefined;
  return true;
});
if (!isNew) return new Response("duplicate\n", { status: 409 });
```
