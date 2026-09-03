function addressBoundUrl(url, address) {
  const normalized = address.toLowerCase();
  const queryAddress = url.searchParams.get("address")?.toLowerCase();
  return queryAddress === normalized || url.pathname.toLowerCase().split("/").includes(normalized);
}

function parseEvidence(payload) {
  if (payload?.status === "1" && String(payload?.message).toUpperCase() === "OK") {
    const result = Array.isArray(payload.result) ? payload.result[0] : payload.result;
    const sourceCode = result?.SourceCode;
    return {
      verified: typeof sourceCode === "string"
        && sourceCode.trim().length > 0
        && !/not verified/i.test(sourceCode)
        && typeof result?.CompilerVersion === "string",
      contractName: result?.ContractName || null,
      compilerVersion: result?.CompilerVersion || null,
      api: "blockscout-v1",
    };
  }
  if (typeof payload?.is_verified === "boolean" || typeof payload?.is_fully_verified === "boolean") {
    return {
      verified: payload.is_fully_verified === true
        && payload.is_changed_bytecode !== true
        && typeof payload.source_code === "string"
        && payload.source_code.trim().length > 0
        && typeof payload.compiler_version === "string",
      contractName: payload.name || null,
      compilerVersion: payload.compiler_version || null,
      api: "blockscout-v2",
    };
  }
  return { verified: false, contractName: null, compilerVersion: null, api: "unknown" };
}

export async function verifySources(path, contracts, readJson, options = {}) {
  if (!path) return { pass: false, entries: {}, error: "source verification file is required" };
  const configured = readJson(path);
  const entries = {};
  await Promise.all(Object.entries(contracts).map(async ([name, deployed]) => {
    const value = configured[name];
    const rawUrl = typeof value === "string" ? value : value?.url;
    if (!rawUrl) {
      entries[name] = { status: "missing", url: null };
      return;
    }
    try {
      const url = new URL(rawUrl);
      if (url.protocol !== "https:") throw new Error("verification URL must use HTTPS");
      if (options.allowedHosts && !options.allowedHosts.includes(url.hostname)) {
        throw new Error("verification URL is not hosted by the configured chain explorer");
      }
      if (!addressBoundUrl(url, deployed.address)) {
        throw new Error("verification API URL is not bound to the deployed address");
      }
      const response = await fetch(url, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) throw new Error(`verification API returned HTTP ${response.status}`);
      const body = await response.text();
      if (body.length > 2_000_000) throw new Error("verification API response is too large");
      const evidence = parseEvidence(JSON.parse(body));
      const compilerMatches = typeof evidence.compilerVersion === "string"
        && evidence.compilerVersion.includes(options.expectedCompiler || "0.8.24");
      entries[name] = {
        status: evidence.verified && compilerMatches ? "verified" : "unconfirmed",
        url: url.href,
        api: evidence.api,
        contractName: evidence.contractName,
        compilerVersion: evidence.compilerVersion,
        compilerMatches,
      };
    } catch (error) {
      entries[name] = { status: "error", url: rawUrl, error: error.message || String(error) };
    }
  }));
  return {
    pass: Object.keys(entries).length === Object.keys(contracts).length
      && Object.values(entries).every((entry) => entry.status === "verified"),
    entries,
  };
}

export const internals = Object.freeze({ addressBoundUrl, parseEvidence });
