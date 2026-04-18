export default async function intercept(request, env, ctx) {
  const url = new URL(request.url);

  if (url.host === "127.0.0.1:9500") {
    const headers = new Headers(request.headers);
    headers.set("x-outgate-secret", env.OUTGATE_SECRET ?? "dev-secret");
    headers.set("x-outgate-request-id", ctx.requestId);
    return fetch(request, { headers, redirect: "manual" });
  }

  return fetch(request, { redirect: "manual" });
}
