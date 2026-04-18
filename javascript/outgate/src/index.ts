import { constants as osConstants, tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";

const ADMIN_CA_PATH = "/_outgate/ca.pem";
const MAX_CA_BYTES = 1024 * 1024;
const CA_FILENAME = "outgate-root-ca-public.pem";

export interface MembraneOptions {
  proxyUrl: string;
  command: string[];
  agentId?: string;
  env?: NodeJS.ProcessEnv;
  cwd?: string | URL;
}

export interface ParsedCli {
  proxyUrl: string;
  command: string[];
  agentId?: string;
}

export class MembraneUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MembraneUsageError";
  }
}

export function parseCliArgs(argv: string[]): ParsedCli {
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
    throw new MembraneUsageError(formatUsage());
  }

  // Strip --agent-id <value> from argv before positional parsing.
  let agentId: string | undefined;
  const rest: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--agent-id") {
      if (i + 1 >= argv.length) {
        throw new MembraneUsageError("--agent-id requires a value");
      }
      agentId = argv[++i];
    } else {
      rest.push(argv[i]);
    }
  }

  const separator = rest.indexOf("--");

  if (separator !== 1 || rest.length <= separator + 1) {
    throw new MembraneUsageError("usage: membrane [--agent-id <id>] <proxy-url> -- <command> [args...]");
  }

  return {
    proxyUrl: rest[0],
    command: rest.slice(separator + 1),
    agentId,
  };
}

export function formatUsage(): string {
  return [
    "Run a command through a running Outgate proxy",
    "",
    "Usage:",
    "  membrane [--agent-id <id>] <proxy-url> -- <command> [args...]",
    "",
    "Options:",
    "  --agent-id <id>  Set proxy auth username to select an agent policy",
    "",
    "Injected env:",
    "  http_proxy, https_proxy, HTTP_PROXY, HTTPS_PROXY",
    "  all_proxy, ALL_PROXY, NODE_USE_ENV_PROXY",
    "  NODE_EXTRA_CA_CERTS, CURL_CA_BUNDLE, SSL_CERT_FILE"
  ].join("\n");
}

export function normalizeProxyUrl(raw: string): URL {
  let url: URL;

  try {
    url = new URL(raw);
  } catch {
    throw new Error(`invalid proxy URL: ${raw}`);
  }

  const protocol = url.protocol.endsWith(":") ? url.protocol.slice(0, -1) : url.protocol;
  if (protocol !== "http" && protocol !== "https") {
    throw new Error(`unsupported proxy URL protocol: ${protocol}`);
  }

  url.pathname = "/";
  url.search = "";
  url.hash = "";

  return url;
}

export async function downloadPublicCa(proxyUrl: URL): Promise<string> {
  const caUrl = new URL(proxyUrl.href);
  caUrl.pathname = ADMIN_CA_PATH;
  caUrl.search = "";
  caUrl.hash = "";
  caUrl.username = "";
  caUrl.password = "";

  const response = await fetch(caUrl.href);

  if (!response.ok) {
    const status = `${response.status} ${response.statusText}`.trim();
    throw new Error(`${caUrl.href} returned HTTP ${status}`);
  }

  const body = await readLimitedBody(response, MAX_CA_BYTES, caUrl.href);
  const pem = decodeUtf8(body, caUrl.href);

  if (!pem.includes("-----BEGIN CERTIFICATE-----")) {
    throw new Error(`${caUrl.href} did not return a PEM certificate`);
  }

  return pem;
}

export function buildChildEnv(
  baseEnv: NodeJS.ProcessEnv,
  proxyUrl: URL,
  caPath: string
): NodeJS.ProcessEnv {
  const proxy = proxyUrl.href;

  return {
    ...baseEnv,
    http_proxy: proxy,
    https_proxy: proxy,
    HTTP_PROXY: proxy,
    HTTPS_PROXY: proxy,
    all_proxy: proxy,
    ALL_PROXY: proxy,
    NODE_USE_ENV_PROXY: "1",
    NODE_EXTRA_CA_CERTS: caPath,
    CURL_CA_BUNDLE: caPath,
    SSL_CERT_FILE: caPath
  };
}

export async function runMembrane(options: MembraneOptions): Promise<number> {
  if (options.command.length === 0) {
    throw new Error("command is required");
  }

  const proxyUrl = normalizeProxyUrl(options.proxyUrl);

  if (options.agentId !== undefined) {
    proxyUrl.username = options.agentId;
    proxyUrl.password = "x";
  }

  const tempDir = await mkdtemp(join(tmpdir(), "outgate-membrane-"));
  const caPath = join(tempDir, CA_FILENAME);

  try {
    const pem = await downloadPublicCa(proxyUrl);
    await writeFile(caPath, pem, "utf8");

    if (process.platform !== "win32") {
      await chmod(caPath, 0o600);
    }

    return await runCommand(options.command, {
      cwd: options.cwd,
      env: buildChildEnv(options.env ?? process.env, proxyUrl, caPath)
    });
  } finally {
    await rm(tempDir, { force: true, recursive: true });
  }
}

export async function runMembraneFromArgv(argv: string[]): Promise<number> {
  const parsed = parseCliArgs(argv);
  return runMembrane(parsed);
}

async function readLimitedBody(response: Response, limitBytes: number, source: string): Promise<Uint8Array> {
  if (response.body === null) {
    return new Uint8Array();
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const result = await reader.read();
    if (result.done) {
      break;
    }

    total += result.value.byteLength;
    if (total > limitBytes) {
      await reader.cancel();
      throw new Error(`${source} returned more than ${limitBytes} bytes`);
    }

    chunks.push(result.value);
  }

  const body = new Uint8Array(total);
  let offset = 0;

  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return body;
}

function decodeUtf8(body: Uint8Array, source: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw new Error(`${source} returned non-UTF-8 body`);
  }
}

function runCommand(
  command: string[],
  options: { env: NodeJS.ProcessEnv; cwd?: string | URL }
): Promise<number> {
  const [program, ...args] = command;

  return new Promise((resolve, reject) => {
    const child = spawn(program, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: "inherit"
    });

    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (signal !== null) {
        resolve(128 + signalNumber(signal));
        return;
      }

      resolve(code ?? 1);
    });
  });
}

function signalNumber(signal: NodeJS.Signals): number {
  return osConstants.signals[signal] ?? 0;
}
