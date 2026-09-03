import { FetchRequest, JsonRpcProvider } from "ethers";

export function rpcProvider(url, timeoutMs = 8_000) {
  const request = new FetchRequest(url);
  request.timeout = timeoutMs;
  return new JsonRpcProvider(request, undefined, { cacheTimeout: -1 });
}

// A cached/quorum-one pending nonce may lag after an archive or failover. Never
// choose a nonce from a stale minority, and do not hide disagreement with max().
export async function pendingNonceConsensus(providers, address) {
  const values = await Promise.all(providers.map(async (provider) => {
    const raw = await provider.send("eth_getTransactionCount", [address, "pending"]);
    if (!/^0x[0-9a-f]+$/i.test(String(raw))) throw new Error("InvalidRpcNonce");
    const nonce = Number(BigInt(raw));
    if (!Number.isSafeInteger(nonce) || nonce < 0) throw new Error("InvalidRpcNonce");
    return nonce;
  }));
  if (!values.length || values.some((value) => value !== values[0])) throw new Error("RpcNonceDisagreement");
  return values[0];
}
