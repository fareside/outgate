import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildChildEnv,
  downloadPublicCa,
  normalizeProxyUrl,
  parseCliArgs,
  runMembrane
} from "../dist/index.js";

const TEST_PEM = [
  "-----BEGIN CERTIFICATE-----",
  "MIIDDzCCAfegAwIBAgIUci5nfNoumj7uZfc5Vjt7V9ZiJwkwDQYJKoZIhvcNAQEL",
  "BQAwFzEVMBMGA1UEAwwMb3V0Z2F0ZS10ZXN0MB4XDTI2MDQxNzE3NDg1NFoXDTI2",
  "MDQxODE3NDg1NFowFzEVMBMGA1UEAwwMb3V0Z2F0ZS10ZXN0MIIBIjANBgkqhkiG",
  "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvQsFx7S2W9m2sduoCyxAX9Q6maiQuP3SrsjE",
  "uzu48URvBi+8OFqDBR18jaSxK8wkMd9FhvONJNQkMgoNfAul0z4MHwD0QMtqVqd5",
  "+FMHEmOWCE3Cm0ZP35Xz+B5gaNLD/xNZcDA6r72T3cpgWalWzYsiieUHGdwSzymT",
  "uakmsuso8utYCm4clWKskB/Vipw8PUF+06egc5wBDsim+Vi05JE3dEecPsTuonF8",
  "D4Om/pRmX1ashFu6v9nl/eO/qb3wv5npjwGTkizAyo5ZEQHUlh2CfmhNqXSek0Ji",
  "TqvKLQRrkaPCW/DPY1eII7zH/aHExC6p5kyFdb9MwzmvnF49fwIDAQABo1MwUTAd",
  "BgNVHQ4EFgQUGJGiFnFUUWqGaQK56vFdEeg9Bv0wHwYDVR0jBBgwFoAUGJGiFnFU",
  "UWqGaQK56vFdEeg9Bv0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC",
  "AQEALiiCHh53F16iPdJkz8BDeeuU8XIORXjXw1VpRjQJ9S/aL9daRcHez8yrVI4S",
  "cLz5dlq6tLpNu9zWQeB5zYEe2mBL12Yfzv4NeviZA9T+U1SUrcWkOEVtT/YQrtK7",
  "AX/2kfGuBvwEsBESit8KSzcNuGTG9uw32NL6jSKpks+di5qLFLWBuQvvdXHUzInw",
  "U6dLXJTHcV9Gywbn0bzWKtvQOzpm+NA03PFn+FP6GQk9V3lDEyY+27ya8jLkzBlL",
  "o12beBRgIxTR/f5jHjZBo+SMMaxzica5MwoHcLPsY+OItqlHrQlGi31g4a3wqd9r",
  "NvXKOhAGpb6UeJHoY+MpT2XaJA==",
  "-----END CERTIFICATE-----",
  ""
].join("\n");

test("parseCliArgs requires proxy, separator, and command", () => {
  assert.deepEqual(parseCliArgs(["http://127.0.0.1:9191", "--", "curl", "https://example.com"]), {
    proxyUrl: "http://127.0.0.1:9191",
    command: ["curl", "https://example.com"]
  });

  assert.throws(() => parseCliArgs(["http://127.0.0.1:9191", "curl"]), /usage/);
  assert.throws(() => parseCliArgs(["http://127.0.0.1:9191", "--"]), /usage/);
});

test("normalizeProxyUrl preserves credentials and strips path, query, and fragment", () => {
  const url = normalizeProxyUrl("http://user:pass@127.0.0.1:9191/path?x=1#frag");
  assert.equal(url.href, "http://user:pass@127.0.0.1:9191/");
  assert.throws(() => normalizeProxyUrl("ftp://127.0.0.1:9191"), /unsupported proxy URL protocol: ftp/);
  assert.throws(() => normalizeProxyUrl("not a url"), /invalid proxy URL/);
});

test("buildChildEnv injects proxy and CA variables", () => {
  const url = normalizeProxyUrl("http://127.0.0.1:9191");
  const env = buildChildEnv({ EXISTING: "1" }, url, "/tmp/ca.pem");

  assert.equal(env.EXISTING, "1");
  assert.equal(env.http_proxy, "http://127.0.0.1:9191/");
  assert.equal(env.https_proxy, "http://127.0.0.1:9191/");
  assert.equal(env.HTTP_PROXY, "http://127.0.0.1:9191/");
  assert.equal(env.HTTPS_PROXY, "http://127.0.0.1:9191/");
  assert.equal(env.all_proxy, "http://127.0.0.1:9191/");
  assert.equal(env.ALL_PROXY, "http://127.0.0.1:9191/");
  assert.equal(env.NODE_USE_ENV_PROXY, "1");
  assert.equal(env.NODE_EXTRA_CA_CERTS, "/tmp/ca.pem");
  assert.equal(env.CURL_CA_BUNDLE, "/tmp/ca.pem");
  assert.equal(env.SSL_CERT_FILE, "/tmp/ca.pem");
});

test("downloadPublicCa strips credentials and validates PEM", async () => {
  const seen = [];
  const server = await startServer((request, response) => {
    seen.push({
      url: request.url,
      authorization: request.headers.authorization
    });
    response.writeHead(200, { "content-type": "application/x-pem-file" });
    response.end(TEST_PEM);
  });

  try {
    const pem = await downloadPublicCa(new URL(`http://user:pass@127.0.0.1:${server.port}/ignored?x=1#frag`));
    assert.equal(pem, TEST_PEM);
    assert.deepEqual(seen, [{ url: "/_outgate/ca.pem", authorization: undefined }]);
  } finally {
    await server.close();
  }
});

test("downloadPublicCa rejects oversized, non-UTF-8, and non-PEM responses", async () => {
  await withServer((_request, response) => {
    response.writeHead(200);
    response.end(Buffer.alloc(1024 * 1024 + 1));
  }, async (port) => {
    await assert.rejects(downloadPublicCa(new URL(`http://127.0.0.1:${port}`)), /more than 1048576 bytes/);
  });

  await withServer((_request, response) => {
    response.writeHead(200);
    response.end(Buffer.from([0xff]));
  }, async (port) => {
    await assert.rejects(downloadPublicCa(new URL(`http://127.0.0.1:${port}`)), /non-UTF-8 body/);
  });

  await withServer((_request, response) => {
    response.writeHead(200);
    response.end("hello");
  }, async (port) => {
    await assert.rejects(downloadPublicCa(new URL(`http://127.0.0.1:${port}`)), /did not return a PEM certificate/);
  });
});

test("runMembrane writes a private CA file and launches command with injected env", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "outgate-membrane-test-"));
  const outputPath = join(workspace, "env.json");

  await withServer((_request, response) => {
    response.writeHead(200);
    response.end(TEST_PEM);
  }, async (port) => {
    const code = await runMembrane({
      proxyUrl: `http://user:pass@127.0.0.1:${port}/ignored?x=1#frag`,
      command: [
        process.execPath,
        "-e",
        [
          "const fs = require('node:fs');",
          "const out = process.argv[1];",
          "const ca = process.env.NODE_EXTRA_CA_CERTS;",
          "const stat = fs.statSync(ca);",
          "fs.writeFileSync(out, JSON.stringify({",
          "  http_proxy: process.env.http_proxy,",
          "  https_proxy: process.env.https_proxy,",
          "  all_proxy: process.env.all_proxy,",
          "  NODE_USE_ENV_PROXY: process.env.NODE_USE_ENV_PROXY,",
          "  NODE_EXTRA_CA_CERTS: ca,",
          "  CURL_CA_BUNDLE: process.env.CURL_CA_BUNDLE,",
          "  SSL_CERT_FILE: process.env.SSL_CERT_FILE,",
          "  caExists: fs.existsSync(ca),",
          "  caText: fs.readFileSync(ca, 'utf8'),",
          "  mode: process.platform === 'win32' ? null : (stat.mode & 0o777).toString(8)",
          "}));"
        ].join(" "),
        outputPath
      ]
    });

    assert.equal(code, 0);
  });

  try {
    const result = JSON.parse(await readFile(outputPath, "utf8"));
    const expectedProxy = result.http_proxy;

    assert.match(expectedProxy, /^http:\/\/user:pass@127\.0\.0\.1:\d+\/$/);
    assert.equal(result.https_proxy, expectedProxy);
    assert.equal(result.all_proxy, expectedProxy);
    assert.equal(result.NODE_USE_ENV_PROXY, "1");
    assert.equal(result.CURL_CA_BUNDLE, result.NODE_EXTRA_CA_CERTS);
    assert.equal(result.SSL_CERT_FILE, result.NODE_EXTRA_CA_CERTS);
    assert.equal(result.caExists, true);
    assert.equal(result.caText, TEST_PEM);
    assert.equal(result.mode, process.platform === "win32" ? null : "600");
    assert.equal(existsSync(result.NODE_EXTRA_CA_CERTS), false);
  } finally {
    await rm(workspace, { force: true, recursive: true });
  }
});

test("runMembrane returns the child exit code", async () => {
  await withServer((_request, response) => {
    response.writeHead(200);
    response.end(TEST_PEM);
  }, async (port) => {
    const code = await runMembrane({
      proxyUrl: `http://127.0.0.1:${port}`,
      command: [process.execPath, "-e", "process.exit(7)"]
    });

    assert.equal(code, 7);
  });
});

async function withServer(handler, callback) {
  const server = await startServer(handler);

  try {
    await callback(server.port);
  } finally {
    await server.close();
  }
}

function startServer(handler) {
  const server = createServer(handler);

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      assert.equal(typeof address, "object");
      assert.notEqual(address, null);

      resolve({
        port: address.port,
        close: () => new Promise((closeResolve, closeReject) => {
          server.close((error) => {
            if (error) {
              closeReject(error);
              return;
            }

            closeResolve();
          });
        })
      });
    });
  });
}
