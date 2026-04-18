#!/usr/bin/env node
import { formatUsage, MembraneUsageError, runMembraneFromArgv } from "./index.js";

try {
  if (process.argv.length === 3 && (process.argv[2] === "--help" || process.argv[2] === "-h")) {
    console.log(formatUsage());
    process.exit(0);
  }

  const code = await runMembraneFromArgv(process.argv.slice(2));
  process.exit(code);
} catch (error) {
  if (error instanceof MembraneUsageError) {
    console.error(error.message);
    process.exit(2);
  }

  const message = error instanceof Error ? error.message : String(error);
  console.error(`membrane: ${message}`);
  process.exit(1);
}
