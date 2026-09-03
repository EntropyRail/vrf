#!/usr/bin/env node
import { lstatSync, readFileSync } from "node:fs";
import process from "node:process";
import { parseArgs } from "node:util";
import { isMain } from "./entrypoint.mjs";

export function validateHealth(payload, { maximumAgeSeconds, now = Date.now() }) {
  if (!payload || payload.status !== "healthy") throw new Error("operator is not healthy");
  const updatedAt = Date.parse(payload.updatedAt);
  if (!Number.isFinite(updatedAt)) throw new Error("health timestamp is invalid");
  const ageMs = now - updatedAt;
  if (ageMs < -60_000) throw new Error("health timestamp is in the future");
  if (ageMs > maximumAgeSeconds * 1_000) {
    throw new Error(`health record is stale by ${Math.floor(ageMs / 1_000)} seconds`);
  }
  if (!/^0x[0-9a-f]{40}$/i.test(payload.coordinator)
      || !/^0x[0-9a-f]{64}$/i.test(payload.keyHash)) {
    throw new Error("health identity is invalid");
  }
  for (const field of ["head", "cursor", "pending"]) {
    if (!Number.isSafeInteger(payload[field]) || payload[field] < 0) {
      throw new Error(`health ${field} is invalid`);
    }
  }
  if (payload.cursor > payload.head + 1) throw new Error("health cursor is ahead of the chain");
  return { status: "healthy", ageSeconds: Math.floor(ageMs / 1_000) };
}

async function main() {
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
      file: { type: "string" },
      "maximum-age-seconds": { type: "string", default: "30" },
    },
    strict: true,
  });
  if (!values.file) throw new Error("--file is required");
  const maximumAgeSeconds = Number(values["maximum-age-seconds"]);
  if (!Number.isSafeInteger(maximumAgeSeconds) || maximumAgeSeconds < 5) {
    throw new Error("--maximum-age-seconds must be an integer of at least 5");
  }
  const metadata = lstatSync(values.file);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error("health file must be a regular file, not a symlink");
  }
  const result = validateHealth(JSON.parse(readFileSync(values.file, "utf8")), {
    maximumAgeSeconds,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (isMain(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exitCode = 1;
  });
}
