# Proof VRF Protocol v0.2

> Historical technical document. Current release status and standalone integration instructions: [STATUS.md](STATUS.md) and [QUICKSTART.md](QUICKSTART.md). Example infrastructure settings are not live configuration.

> `ProofVRFCoordinator` 与 `ProofVRFRouter` 是保留的 V1 direct-funded 兼容路径。公共服务主线是
> `VRFServiceCoordinatorV2`；订阅、Sponsor 与实际成本结算规范见
> [SERVICE_V2.md](./SERVICE_V2.md)。

## 1. 目标

协议向 EVM Consumer 提供可在链上验证的随机数。当前使用单个 `secp256k1` ECVRF 密钥；
V2 通过 `IVRFProofVerifier` 保持 Subscription/Consumer API 稳定；实验 threshold 路径只新增 verifier
和 group key。

本版本优化三个属性：

1. **Uniqueness**：固定 public key 与 seed 只能验证一个 VRF 输出。
2. **Public verifiability**：任何链上参与者都能执行 proof verification。
3. **Failure isolation**：proof 验证、Router 记录和应用结算互相分离。

单 Operator v0.1 不提供抗拒绝服务能力。阈值升级要求见 [THRESHOLD_ROADMAP.md](./THRESHOLD_ROADMAP.md)。

## 2. 合约角色

### `ProofVRFCoordinator`

- 保存已登记 public key、Operator、固定 ETH fee 和 active 状态。
- 接收 direct-funded 请求。
- 根据请求所在 block 的 hash 计算最终 seed。
- 验证 ECVRF proof 并展开 `1–32` 个随机 word。
- 采用 pull-credit 记录 Operator 收入或 Consumer 退款。
- proof 验证成功后先持久化结果，再尝试 callback。

### `ProofVRFRouter`

- 保存一次性 `keyHash → coordinator + runtime code hash` 绑定。
- 绑定只能停用，不能覆盖、换绑或接受 runtime bytecode 变化。
- 为 Consumer 生成独立 request ID，并固定底层 provider request ID。
- 底层 callback 只记录 words，不执行应用逻辑。
- 通过单独的 permissionless `retryCallback()` 交付应用。
- 可登记 threshold group key，而无需修改已有 Consumer。

### Operator

- 监听 `RandomWordsRequested`。
- 等待链上要求的 L2 confirmations。
- 调用 `requestSeed()` 获得实际 seed。
- 用独立 VRF 私钥生成 proof。
- 使用独立 relayer 钱包提交 proof。

## 3. 请求与 seed

Coordinator 先生成：

```text
preSeed = keccak256(
  REQUEST_DOMAIN,
  chainId,
  coordinator,
  consumer,
  subscriptionId,
  nonce,
  keyHash
)
```

达到 confirmations 后，最终 proof seed 为：

```text
actualSeed = keccak256(bytes32(preSeed) || blockhash(requestBlock))
```

绑定 `chainId` 和 Coordinator 地址可防止跨链、跨部署重放；Consumer 和 nonce 防止同一调用者重复 seed；请求 block hash 使 Operator 在请求被确认前不能预计算输出。

Robinhood Chain 基于 Arbitrum。V2 不依赖 Solidity `block.number/blockhash` 的语义，而通过固定 codehash
的 `ArbitrumBlockContext` 调用 ArbSys `arbBlockNumber/arbBlockHash`，从请求、confirmation、expiry 到
归档都使用同一个 L2 context。Operator 必须读取 `requestSeed()`，不能从事件日志和普通 RPC block
字段自行拼 seed。

## 4. ECVRF proof

链上 verifier 使用 vendored `contracts/vendor/chainlink/VRF.sol`：

- curve：`secp256k1`；
- hash：Keccak-256；
- proof：`pk, gamma, c, s` 加 Solidity 验证所需 witnesses；
- output：`keccak256(domain || gamma)`。

该实现源自早期 ECVRF draft 并针对 EVM 做过特定优化，不是 RFC 9381 ciphersuite 的字节级实现。协议不得把二者描述成完全相同。

## 5. 状态机

```text
REQUESTED
   ├─ valid proof ───────► VERIFIED ─► CALLBACK_SUCCEEDED
   │                          └──────► CALLBACK_FAILED ─► retry
   └─ blockhash expired ─► REFUNDED
```

约束：

- 请求不能取消或重新选择 Operator。
- Key 停用只影响新请求。
- Public key、Operator payee、fee 和 Coordinator 在请求时固定。
- 任何人可 relay proof，但无法改变 proof 输出或领取 Operator fee。
- 过期退款仅退还 VRF 服务费，不决定上层业务本金如何处理。

## 6. Callback

Coordinator 使用固定 gas 上限调用 Consumer，且不复制 returndata，避免 returndata bomb。状态在外部调用前写入，因此 callback revert 不会回滚 proof verification。

通过 Router 时有两段 callback：

1. Coordinator → Router：只保存随机 words。
2. Router → Consumer：独立交易，任何人可重试。

高价值 Consumer 应优先使用 Router 路径。

## 7. 费用

v0.1 使用每个 key 的固定 ETH fee。请求必须精确支付；proof 验证成功后 fee 记入请求时固定 Operator 的 pull-credit。超出 256-block BLOCKHASH 窗口仍未完成时，fee 记入 Consumer 的 pull-credit。

固定费用只适合测试网与早期低波动阶段。生产版需要把 callback gas、L1 data fee、目标 gas price ceiling 和 Operator margin 纳入报价，同时保持请求时价格快照。

上述是 V1 规则。V2 已实现最大费用预留、实际 execution/L1 fee 结算、premium 分成、客户
Subscription、Consumer allowlist 和 Sponsor policy；不再要求每个请求附带 ETH。

## 8. 治理

Coordinator 和 Router 自身不使用 proxy。Owner 只能：

- 登记新的 public/group key；
- 停用 key 的新请求；
- 调整未来请求费率；
- 调整未来请求的 Operator payout 地址；
- 在 Router 登记一个从未出现过的新 keyHash。

Owner 不能覆盖 Router 中已有 keyHash、替换 pending request、注入随机数、删除结果或重抽。生产 owner 必须是带延迟的多签 Timelock。

## 9. 兼容承诺

V1 Router 兼容层仍使用：

```solidity
requestRandomWords(keyHash, confirmations, callbackGasLimit, numWords)
retryCallback(requestId)
refundExpired(requestId)
withdrawCredits(recipient, amount)
keyFee(keyHash)
```

新 group key 使用新 `keyHash`，在 Router 中形成新的不可变绑定。旧 ECVRF 请求与旧 key 不受影响。

V2 threshold verifier 必须实现 `IVRFProofVerifier.validateKey/verify/proofLength`。每个 key 在登记时固定
exact proof length，Coordinator 同时拒绝内层 proof padding 和外层 calldata padding，避免 Fulfiller
扩大 L1 data fee。新 group key 使用包含 scheme domain 的新 `keyHash`；旧 ECVRF 请求已固定 verifier
地址、code hash 与 proof length，不受影响。
