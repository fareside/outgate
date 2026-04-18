// ext:core/ops is compiled into the startup snapshot and only includes ops
// registered at snapshot time. Our custom ops are registered at runtime, so we
// pull them from Deno.core.ops which is always a live reflection of all ops.
const {
  op_outgate_body_next,
  op_outgate_response_send,
  op_outgate_response_start,
  op_outgate_kv_get,
  op_outgate_kv_put,
  op_outgate_kv_update,
} = Deno.core.ops;

function createOutgateBodyStream() {
  return new ReadableStream({
    async pull(controller) {
      const chunk = await op_outgate_body_next();
      if (chunk === null) {
        controller.close();
        return;
      }

      controller.enqueue(chunk);
    },
  });
}

Object.defineProperty(globalThis, Symbol.for("outgate.createBodyStream"), {
  value: createOutgateBodyStream,
});

Object.defineProperty(globalThis, Symbol.for("outgate.startResponse"), {
  value: op_outgate_response_start,
});

Object.defineProperty(globalThis, Symbol.for("outgate.sendResponseChunk"), {
  value: op_outgate_response_send,
});

Object.defineProperty(globalThis, Symbol.for("outgate.kv"), {
  value: Object.freeze(createKvApi()),
});

function createKvApi() {
  async function get(key) {
    const result = await op_outgate_kv_get(String(key));
    return result.found ? result.value : undefined;
  }

  async function put(key, value) {
    if (value === undefined) {
      throw new TypeError("env.KV.put value must not be undefined; use update(key, () => undefined) to delete");
    }

    await op_outgate_kv_put(String(key), value);
  }

  async function update(key, callback) {
    if (typeof callback !== "function") {
      throw new TypeError("env.KV.update requires a callback");
    }

    return await op_outgate_kv_update(String(key), callback);
  }

  return {
    get,
    put,
    update,
  };
}
