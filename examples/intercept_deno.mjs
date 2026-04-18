export default async function intercept(request, env, ctx) {
  const url = new URL(request.url);

  if (url.pathname === "/_deno") {
    return Response.json({
      deno: Deno.version.deno,
      v8: Deno.version.v8,
      typescript: Deno.version.typescript,
    });
  }

  if (url.pathname === "/_echo") {
    return new Response(await request.text(), {
      headers: { "content-type": request.headers.get("content-type") ?? "text/plain" },
    });
  }

  return fetch(request, { redirect: "manual" });
}
