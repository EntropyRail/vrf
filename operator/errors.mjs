// Deliberately allowlist error fields: never serialize request headers, RPC params,
// database connection objects, transaction bodies, or arbitrary nested objects.
export function redactText(value) {
  return String(value)
    .replace(/(?:https?|wss?|postgres(?:ql)?):\/\/[^\s"'<>]+/gi, "[redacted-url]")
    .replace(/Bearer\s+[^\s"',;}]+/gi, "Bearer [redacted]")
    .replace(/((?:private[_-]?key|password|token|api[_-]?key|authorization)\s*[=:]\s*)[^\s"',;}]+/gi, "$1[redacted]")
    .replace(/0x[0-9a-f]{64,}/gi, "[redacted-hex]")
    .slice(0, 1_200);
}

export function errorDetails(error) {
  const details = {};
  const seen = new Set();
  function visit(value, depth = 0) {
    if (!value || typeof value !== "object" || seen.has(value) || depth > 3) return;
    seen.add(value);
    for (const field of ["code", "shortMessage", "message", "reason", "errno", "syscall"]) {
      if (["string", "number"].includes(typeof value[field])) {
        const key = depth === 0 ? field : `cause${depth}_${field}`;
        if (details[key] === undefined) details[key] = redactText(value[field]);
      }
    }
    const method = value.payload?.method || value.info?.payload?.method;
    if (typeof method === "string" && /^[a-zA-Z][a-zA-Z0-9_]{0,79}$/.test(method)) details.rpcMethod = method;
    visit(value.error, depth + 1);
    visit(value.info?.error, depth + 1);
    visit(value.cause, depth + 1);
  }
  visit(error);
  if (!Object.keys(details).length) details.message = redactText(error);
  return details;
}

export function errorMessage(error) {
  return [...new Set(Object.entries(errorDetails(error))
    .filter(([key]) => /message|reason/i.test(key)).map(([, value]) => value))].join(" | ")
    || redactText(error?.code || "unknown error");
}
