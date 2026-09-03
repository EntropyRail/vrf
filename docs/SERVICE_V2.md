# VRF Service V2：公共服务、收费与 Sponsor 白名单

> Historical technical document. Current release status and standalone integration instructions: [STATUS.md](STATUS.md) and [QUICKSTART.md](QUICKSTART.md). Example infrastructure settings are not live configuration.

## 结论

V2 是当前应继续演进的主线。它保留真实 proof verification，但把 V1 的固定单次付费改为：

```text
Consumer
  └─ request
      ▼
VRFServiceCoordinatorV2
  ├─ Subscription / Consumer allowlist
  ├─ Sponsor policy / quotas
  ├─ maximum-cost reservation
  ├─ verifier code-hash pinning
  └─ actual-cost settlement
      ▼
IVRFProofVerifier
  ├─ Secp256k1ECVRFVerifier（当前）
  └─ ThresholdBLSVerifier（实验性 3-of-5 shadow）
```

订阅、计费和 Consumer 接口不依赖具体 proof scheme。Threshold group 使用新的
domain-separated `keyHash` 和 verifier，不需要迁移余额或重新设计收费系统。Threshold 路径的
DKG/resharing/在线份额协议已实现，但在密码学审计与 shadow soak 前仍属于实验功能。

## 本地存储优化版本（尚未部署）

2026-09-03 两轮实现将每请求内部存储由 13 slots 减为 7、再减为 5 slots。key service 与 pricing
都使用只追加的版本快照；每请求 reserve 和 expiry 从原版本精确派生，Subscription 的资金预留
仍正常记账。旧请求固定原 verifier、code hash、Fulfiller、payee、gas lane、价格与 timeout。
`getRequest` 拼回原 tuple，公开 ABI、事件和 Operator 读法不变。旧快照不得修改、删除或重用。

本地相同证明输入对照中，普通单词请求累计 gas 降 47.0%，请求加履约总 gas 降 32.6%；第二轮
相对第一轮总 gas 再降 9.8%。部分成本转移到履约、配置与退款，完整代价不能省略。
这不是主网实测，也没有降低收费参数。**需要新部署，不兼容旧 Coordinator 的原位存储升级**；
当前测试网合约不会自动获得此优化。见
[第二轮方法、代价与测试](./GAS_OPTIMIZATION_ROUND2_2026-09-03.md)。

## V3 紧凑候选（尚未部署）

另有 [V3 请求状态承诺实验候选](./GAS_OPTIMIZATION_ROUND3_2026-09-03.md)：每请求一个状态哈希，
本地普通单词请求＋履约比第二轮 V2 再降 22.1%。请求和 callback ABI 保留，但查询、事件与
履约接口不同，依赖完整 witness 历史；常驻 Operator/Archiver/线上 Threshold resolver 尚未完整适配。
**不是 V2 的直接替换，也没有部署或改线上费率。**

## 两层授权，不能合并

### Consumer allowlist

每个 Subscription owner 明确添加可消费余额的合约，并分别设置：

- 最大 callback gas；
- 最大 pending requests；
- 是否 active。

这防止 Subscription ID 泄露后被任意合约盗用余额。EOA 不能直接成为 Consumer。

### Sponsor policy

协议治理可把一个已获 Subscription owner 授权的 Consumer 加入 Sponsor policy。Consumer
请求时传 `subscriptionId = 0`，Coordinator 自动选择 Sponsor Subscription，并执行：

- 有效期；
- 每日请求数；
- Sponsor pending 上限；
- callback gas 上限；
- Sponsor 专属 premium；
- 是否免除最低服务费。

“自己的项目免费”表示最终用户和 Adapter 不付费，不表示链上执行没有成本。推荐自己的
GRID Adapter 设置 `premiumBps = 0`、`waiveMinimumFee = true`，实际证明和 callback 成本仍从
Sponsor Subscription 扣除并补偿 Operator。

## 费用公式

请求阶段先锁定最大费用，不立即扣款：

```text
maxNetworkCost =
  (verificationGasLimit
   + callbackGasLimit
   + fulfillmentOverheadGas
   + perWordGas × numWords)
  × key.maxGasPriceWei
  + l1FeeReserveWei

reservedPayment = max(
  minimumRequestFeeWei,
  maxNetworkCost × (10_000 + premiumBps) / 10_000
)
```

Sponsor 可选择免最低服务费，但不能免实际 network cost。Consumer 传入 `maxPayment` 作为
报价滑点上限；报价超过该值时请求回滚。Subscription 只能提取 `balance - reserved`，不能
抽走 pending request 的预算。

履约后按实际交易结算：

```text
networkCost =
  (measuredFulfillmentGas + pinnedOverheadGas) × tx.gasprice
  + ArbGasInfo.getCurrentTxL1GasFees()

charge = max(pinnedMinimumFee, networkCost × (10_000 + pinnedPremiumBps) / 10_000)
```

`charge` 不得超过请求时的 `reservedPayment`。余额只扣实际 `charge`，其余预留自动释放。
定价、Operator payee、gas lane、verifier code hash 和费用分成在请求时固定，管理员修改只影响
未来请求。

协议收入分配：

```text
premium = charge - networkCost
operatorPayment = networkCost + premium × operatorPremiumShareBps / 10_000
treasuryPayment = charge - operatorPayment
```

Operator 与 Treasury 都使用 pull withdrawal，callback 或收款地址失败不会锁死请求。

Verifier 在 key 登记时返回并固定 exact `proofDataLength`。履约同时要求动态 bytes 长度和整笔
`msg.data.length` 精确匹配，Fulfiller 不能通过追加内层或外层 padding 人为抬高 ArbGasInfo L1 poster
fee。该检查发生在 proof 和扣费之前。

## 初始收费标准

以下是 testnet 和低限额 mainnet canary 的起点，不是永久价格：

| 类型 | premium | minimum fee | 资金来源 | 额外限制 |
| --- | ---: | ---: | --- | --- |
| GRID 自用 Sponsor | 0% | 免除 | 协议 Sponsor Subscription | 每日额度、pending 上限 |
| 生态合作伙伴 | 10% | 保留 | 合作方 Subscription | 独立额度、到期复审 |
| 公共 Subscription | 20% | 保留 | 客户预付 | Consumer allowlist |

建议先把 `minimumRequestFeeWei` 设为约 0.01 USD 对应的 ETH 数量，并每周根据 Robinhood Chain
真实 fulfillment 样本校准。合约使用 ETH，不内置价格预言机，因此“美元价格”只能由治理在
延迟生效后更新，不能假装永久锚定美元。

V2 暂不提供 direct funding。公共客户先创建并充值 Subscription；这比每次附带 ETH 更易于
准确预留 callback gas 和 L1 data fee。后续 direct-funding wrapper 应作为独立合约实现，不能
绕过 Coordinator 的 Consumer 授权与计费。

## 客户接入流程

普通客户按以下顺序操作：

1. 调用 `createSubscription()`，从 `SubscriptionCreated` 取得 ID；
2. 调用 payable `fundSubscription(id)` 预充 ETH；
3. 部署继承 `VRFServiceConsumerBaseV2` 的 Consumer；
4. Subscription owner 调用 `addConsumer(id, consumer, maxCallbackGas, maxPending)`；
5. Consumer 先读 `quoteMaxPayment(...)`，再把报价作为 `maxPayment` 请求；
6. 监听 `ProofVerified`、`CallbackAttempted` 和 `RequestSettled`；
7. 只提取 `balance - reserved`，退出前等待或 expire 所有 pending requests，再调用
   `cancelSubscription`。

Consumer 请求示例：

```solidity
uint256 quote = coordinator.quoteMaxPayment(
    keyHash,
    address(this),
    subscriptionId,
    callbackGasLimit,
    1
);

requestId = coordinator.requestRandomWords(
    IVRFServiceCoordinatorV2.RandomWordsRequest({
        keyHash: keyHash,
        subscriptionId: subscriptionId,
        requestConfirmations: 3,
        callbackGasLimit: callbackGasLimit,
        numWords: 1,
        maxPayment: quote
    })
);
```

协议自用项目仍需先完成上述 Subscription funding 和 Consumer allowlist，然后由 Timelock 调用
`setSponsorPolicy`。白名单只对特定 Consumer 合约生效，不对白名单 EOA、前端用户或任意调用者
开放。

## 请求生命周期

```text
PENDING
  ├─ valid proof ─► FULFILLED ─► callback success
  │                         └──► callback failed ─► permissionless retry
  └─ timeout ─────► EXPIRED（释放 reservation，不扣余额）
```

- Fulfiller 在请求时固定，防止第三方用高 gas price 抢跑证明并让客户承担费用。
- `BlockhashStore` 可在 256-block opcode 窗口关闭前归档 request block hash。
- 默认 Operator 在延迟达到 128 blocks 时主动归档；正常快速履约不额外写入。
- 请求超时后任何人可释放 reservation；不能改 seed、取消后重抽或切换另一把 key。
- Finalized request 在长延迟后可 prune，完整审计记录保留在事件中。

## 治理

- Coordinator 不使用 proxy。
- Owner 使用 `Ownable2Step`，公共网络部署脚本拒绝 EOA owner。
- `VRFAdminTimelock` 的最短延迟为 12 小时；推荐 24 小时并由多签持有。
- Guardian 只能立即暂停新请求；不能恢复、改价、改 key、取款或影响 pending fulfillment。
- 恢复请求只能由 timelocked owner 执行。

## 尚未满足的主网上线门槛

代码完成不等于可售卖。公开收费前仍必须完成：

1. Solidity verifier、Coordinator、Operator 各自的独立安全审计；
2. Robinhood testnet 至少 30 天 soak，以及 RPC split、reorg、gas spike、callback OOG 演练；
3. 用真实数据确定 `verificationGasLimit`、`l1FeeReserveWei` 和最低收费；
4. Operator 证明密钥进入 HSM/KMS 或等价隔离，至少两个热备 relayer；
5. 公开状态页、成功率、P95/P99 延迟、余额告警和事故处理流程；
6. 客户协议、责任上限、退款范围、税务和博彩/RWA 等高风险用途限制的法律审查；
7. 单 Operator 阶段设置请求价值上限，并明确披露 selective withholding；
8. 已实现的 Threshold DKG/resharing 通过专项审计和第二实现互操作后，才解除高价值限制。

## 成熟网络设计来源

- [Chainlink VRF v2.5 Subscription](https://docs.chain.link/vrf/v2-5/overview/subscription)
- [Chainlink VRF v2.5 Billing](https://docs.chain.link/vrf/v2-5/billing)
- [Chainlink VRF Security Considerations](https://docs.chain.link/vrf/v2-5/security)
- [Chainlink Arbitrum cost estimation](https://docs.chain.link/vrf/v2-5/arbitrum-cost-estimation)
- [Supra dVRF subscription model](https://docs.supra.com/dvrf/build-third-party-evm-networks/vrf-subscription-model)
- [Pyth Entropy fees](https://docs.pyth.network/entropy/fees)
- [Arbitrum `ArbGasInfo` precompile](https://github.com/OffchainLabs/nitro-precompile-interfaces/blob/main/ArbGasInfo.sol)
- [Robinhood Chain network documentation](https://docs.robinhood.com/chain/connecting/)
- [Dice Entropy](https://github.com/diceprotocol/dice-entropy)
- [Quiver](https://quiver.foundation/)
- [drand threshold network](https://github.com/drand/drand)
