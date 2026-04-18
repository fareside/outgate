const GITHUB_API_HOST = "api.github.com";

const CREATE_ISSUE = /^\/repos\/[^/]+\/[^/]+\/issues$/;
const COMMENT_ON_ISSUE_OR_PR = /^\/repos\/[^/]+\/[^/]+\/issues\/\d+\/comments$/;

const SAFE_REPO_READ_PATHS = [
  /^\/repos\/[^/]+\/[^/]+$/,
  /^\/repos\/[^/]+\/[^/]+\/contents(?:\/.*)?$/,
  /^\/repos\/[^/]+\/[^/]+\/issues(?:\/.*)?$/,
  /^\/repos\/[^/]+\/[^/]+\/pulls(?:\/.*)?$/,
  /^\/repos\/[^/]+\/[^/]+\/commits(?:\/.*)?$/,
  /^\/repos\/[^/]+\/[^/]+\/branches(?:\/[^/]+)?$/,
];

const BLOCKED_REPO_ADMIN_PATHS = [
  /^\/repos\/[^/]+\/[^/]+$/,
  /^\/repos\/[^/]+\/[^/]+\/actions\/secrets(?:\/.*)?$/,
  /^\/repos\/[^/]+\/[^/]+\/deployments(?:\/.*)?$/,
  /^\/repos\/[^/]+\/[^/]+\/hooks(?:\/.*)?$/,
  /^\/repos\/[^/]+\/[^/]+\/keys(?:\/.*)?$/,
  /^\/repos\/[^/]+\/[^/]+\/collaborators(?:\/.*)?$/,
  /^\/repos\/[^/]+\/[^/]+\/branches\/[^/]+\/protection(?:\/.*)?$/,
];

const outboundByHost = {
  [GITHUB_API_HOST]: handleGitHub,
};

export default async function intercept(request, env, ctx) {
  const url = new URL(request.url);
  const handler = outboundByHost[url.hostname] ?? handleDefault;
  return handler(request, env, ctx);
}

async function handleGitHub(request, env, ctx) {
  const url = new URL(request.url);
  const decision = decideGitHub(request.method, url);

  audit(ctx, request, decision, "github_safe_agent");

  if (!decision.allow) {
    return Response.json(
      {
        blocked: true,
        reason: decision.reason,
        requestId: ctx.requestId,
      },
      {
        status: decision.status,
        headers: { "x-outgate-request-id": ctx.requestId },
      },
    );
  }

  const token = env.GITHUB_TOKEN;
  if (!token) {
    return Response.json(
      {
        blocked: true,
        reason: "GITHUB_TOKEN is not set in the Outgate process",
        requestId: ctx.requestId,
      },
      {
        status: 500,
        headers: { "x-outgate-request-id": ctx.requestId },
      },
    );
  }

  const headers = new Headers(request.headers);
  headers.delete("authorization");
  headers.set("authorization", `Bearer ${token}`);
  headers.set("accept", "application/vnd.github+json");
  headers.set("x-github-api-version", "2022-11-28");
  headers.set("x-outgate-request-id", ctx.requestId);

  return fetch(request, {
    headers,
    redirect: "manual",
  });
}

async function handleDefault(request, _env, ctx) {
  audit(
    ctx,
    request,
    allow("passthrough"),
    "default_passthrough",
  );

  return fetch(request, {
    redirect: "manual",
  });
}

function decideGitHub(method, url) {
  if (url.hostname !== GITHUB_API_HOST) {
    return deny(403, "this profile only permits GitHub API requests");
  }

  if (method === "DELETE") {
    return deny(403, "destructive GitHub deletes are blocked");
  }

  if (
    method === "GET" &&
    SAFE_REPO_READ_PATHS.some((pattern) => pattern.test(url.pathname))
  ) {
    return allow("repo read");
  }

  if (method === "POST" && CREATE_ISSUE.test(url.pathname)) {
    return allow("create issue");
  }

  if (method === "POST" && COMMENT_ON_ISSUE_OR_PR.test(url.pathname)) {
    return allow("comment on issue or pull request");
  }

  if (
    ["POST", "PUT", "PATCH"].includes(method) &&
    BLOCKED_REPO_ADMIN_PATHS.some((pattern) => pattern.test(url.pathname))
  ) {
    return deny(403, "repository administration endpoints require human approval");
  }

  if (["POST", "PUT", "PATCH"].includes(method)) {
    return deny(403, "mutating GitHub requests must be explicitly allowed");
  }

  return deny(403, "request is outside this agent capability profile");
}

function allow(reason) {
  return { allow: true, reason, status: 200 };
}

function deny(status, reason) {
  return { allow: false, reason, status };
}

function audit(ctx, request, decision, profile) {
  const url = new URL(request.url);

  console.log(
    JSON.stringify({
      outgate: profile,
      requestId: ctx.requestId,
      method: request.method,
      host: url.host,
      path: url.pathname,
      decision: decision.allow ? "allow" : "block",
      reason: decision.reason,
    }),
  );
}
