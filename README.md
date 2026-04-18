# Outgate

**Programmable action boundary for AI agents.**

Your agent can open a GitHub issue. It cannot delete a repo. That's not a setting — that's policy. Every action an agent takes on the internet runs through JavaScript you control. What isn't explicitly allowed is blocked.

The agent never touches real credentials. Destructive actions never reach the upstream service. Works with any agent, any framework, any cloud — no code changes required.

Outgate is a Rust proxy with embedded JavaScript policy execution. It intercepts HTTP and HTTPS traffic, runs your policy function, and either forwards the request or blocks it.

## Deploy agents your security team can approve

Agents with unconstrained API access are a hard sell internally. Outgate gives you the controls that make deployment possible: explicit action boundaries, credential isolation, and a full audit trail. The conversation changes from "we can't let an agent touch production" to "here's exactly what it's allowed to do."

## What you get

**Agents that can't go rogue.**
Define exactly what each agent is allowed to do — which services, which operations, which payloads. Anything outside that boundary is blocked before it leaves your machine.

**Credentials that stay yours.**
Your API keys, tokens, and secrets live in Outgate. The agent never sees them. They're injected only into requests that pass policy — and only at the moment they're needed.

**Full visibility into what agents actually did.**
Every outbound call runs through policy code you control. Log what matters, in whatever format your team needs. No black boxes.

## Try it in 90 seconds

Start Outgate with the built-in GitHub safe-agent policy:

```bash
export GITHUB_TOKEN=ghp_yourtoken

docker run --rm \
  -p 9191:9191 \
  -v outgate-data:/data \
  -e GITHUB_TOKEN \
  -e INTERCEPT=/usr/local/share/outgate/examples/github_safe_agent.mjs \
  ghcr.io/fareside/outgate:latest
```

Run any agent or tool through it:

```bash
npx outgate http://127.0.0.1:9191 -- claude
npx outgate http://127.0.0.1:9191 -- node agent.js
```

The agent runs normally. All outbound calls go through Outgate. `GITHUB_TOKEN` is injected only into requests the policy allows — the agent never sees it.

Try it directly:

```bash
# Allowed — reads a repo
npx outgate http://127.0.0.1:9191 -- curl -s https://api.github.com/repos/fareside/outgate

# Blocked — DELETE is never allowed
npx outgate http://127.0.0.1:9191 -- curl -s -X DELETE https://api.github.com/repos/fareside/outgate
# → {"blocked":true,"reason":"destructive GitHub deletes are blocked",...}
```

## Write policy in JavaScript

```js
export default async function intercept(request, env, ctx) {
  const url = new URL(request.url);

  if (url.hostname !== "api.github.com") return deny();
  if (request.method === "DELETE") return deny();

  // Inject real token — agent never sees it
  const headers = new Headers(request.headers);
  headers.set("authorization", `Bearer ${env.GITHUB_TOKEN}`);
  return fetch(request, { headers, redirect: "manual" });
}
```

Policy is JavaScript. It can read the request body, call a secrets manager, check a rate limit, log to your audit system — anything.

## What's next

JavaScript policy is enforcement by convention — code that makes the right decision, as long as nothing goes wrong.

What we're building toward is enforcement by design. The real credential stays locked inside Outgate, unreachable to anything outside it. The agent holds a token that defines exactly what it's allowed to do — not as a list of rules to follow, but as a constraint the math enforces. Prompt injection, a compromised package, a manipulated model: none of them can exceed those bounds. The math won't allow it.

The deeper property is delegation. An agent can issue a narrower version of its own token to a subagent or a partner's system. That derived token can only do less — never more. Which means you can give another team's agent exactly the capability it needs to act on your behalf, with a hard guarantee it cannot do anything else.

Credentials never travel. Capability does.

## Docs

- [Writing policies](docs/policies.md)
- [Launching agents with outgate](docs/outgate.md)
- [Per-agent policies](docs/outgate.md#per-agent-policies-with---agent-id)
- [Security model](docs/security.md)
- [Docker reference](docs/docker.md)
- [Building from source](docs/development.md)

Found a security issue? See [SECURITY.md](SECURITY.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
