import { lstatSync, readFileSync } from "node:fs";

function validateSecretFileMetadata(metadata, name) {
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${name}_FILE must reference a regular file, not a symlink`);
  }
  if ((metadata.mode & 0o077) !== 0) {
    throw new Error(`${name}_FILE must not be readable or writable by group/other users`);
  }
  if (metadata.size > 65_536) throw new Error(`${name}_FILE is unexpectedly large`);
}

export function readSecret(name, { required = false } = {}) {
  const direct = process.env[name];
  const path = process.env[`${name}_FILE`];
  if (direct && path) throw new Error(`configure only one of ${name} or ${name}_FILE`);
  let value = direct;
  if (path) {
    const metadata = lstatSync(path);
    validateSecretFileMetadata(metadata, name);
    value = readFileSync(path, "utf8");
  }
  if (value?.includes("\0")) throw new Error(`${name} contains a NUL byte`);
  value = value?.trim();
  if (required && !value) throw new Error(`${name} or ${name}_FILE is required`);
  return value;
}

export const internals = Object.freeze({ validateSecretFileMetadata });
