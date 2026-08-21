#!/usr/bin/env node

"use strict";

const { spawn } = require("node:child_process");
const path = require("node:path");

const supported = new Map([
  ["linux-x64", "linux-x64"],
  ["linux-arm64", "linux-arm64"],
]);
const platformKey = `${process.platform}-${process.arch}`;
const artifactDirectory = supported.get(platformKey);

if (artifactDirectory === undefined) {
  console.error(
    `heimdall-egress does not provide a binary for ${platformKey}; ` +
      "supported targets are linux-x64 and linux-arm64",
  );
  process.exit(1);
}

const nativeBinary = path.join(
  __dirname,
  "..",
  "vendor",
  artifactDirectory,
  "heimdall",
);

if (
  path.basename(process.argv[1]).startsWith("heimdall-egress") &&
  process.argv[2] === "--print-native-path"
) {
  process.stdout.write(`${nativeBinary}\n`);
  process.exit(0);
}

const child = spawn(nativeBinary, process.argv.slice(2), {
  stdio: "inherit",
});
const forwardedSignals = ["SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM"];
const handlers = new Map();

for (const signal of forwardedSignals) {
  const handler = () => {
    if (!child.killed) {
      child.kill(signal);
    }
  };
  handlers.set(signal, handler);
  process.on(signal, handler);
}

function removeSignalHandlers() {
  for (const [signal, handler] of handlers) {
    process.off(signal, handler);
  }
}

child.on("error", (error) => {
  removeSignalHandlers();
  console.error(`failed to start ${nativeBinary}: ${error.message}`);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  removeSignalHandlers();
  if (signal !== null) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
});
