const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

export function normalizeRpcUrls(values, {
  minimum = 1,
  label = "RPC",
  allowSharedOrigin = false,
} = {}) {
  const items = (Array.isArray(values) ? values : String(values || "").split(","))
    .map((value) => value?.trim())
    .filter(Boolean);
  if (items.length < minimum) {
    throw new Error(`${label} requires at least ${minimum} independent RPC endpoints`);
  }

  const parsed = items.map((value) => {
    let url;
    try {
      url = new URL(value);
    } catch {
      throw new Error(`${label} RPC URL is invalid`);
    }
    if (url.protocol !== "https:"
        && !(url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))) {
      throw new Error(`${label} RPC endpoints must use HTTPS`);
    }
    return url;
  });

  if (new Set(parsed.map((url) => url.href)).size !== parsed.length) {
    throw new Error(`${label} RPC endpoint URLs must be distinct`);
  }
  if (!allowSharedOrigin && new Set(parsed.map((url) => url.origin)).size !== parsed.length) {
    throw new Error(`${label} independent RPC endpoints must use distinct origins`);
  }
  return parsed.map((url) => url.href);
}

export function rpcOriginCount(rpcUrls) {
  return new Set(rpcUrls.map((value) => new URL(value).origin)).size;
}
