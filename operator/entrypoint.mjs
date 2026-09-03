import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

export function isMain(importMetaUrl, argvPath = process.argv[1]) {
  if (!argvPath) return false;
  try {
    return realpathSync(fileURLToPath(importMetaUrl)) === realpathSync(argvPath);
  } catch {
    return false;
  }
}
