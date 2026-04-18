export default async function intercept(request, env, ctx) {
  const url = new URL(request.url);

  if (url.pathname === "/_deny") {
    return new Response("denied by examples/intercept.mjs\n", {
      status: 403,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  if (url.hostname === "api.example.test") {
    const headers = new Headers(request.headers);
    headers.set("authorization", `Bearer ${env.EXAMPLE_API_TOKEN ?? "dev-token"}`);
    headers.set("x-outgate-request-id", ctx.requestId);
    return fetch(request, { headers, redirect: "manual" });
  }

  return fetch(request, { redirect: "manual" });
}
