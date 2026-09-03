# Threat Model v0.2

> Historical technical document. Current release status and standalone integration instructions: [STATUS.md](STATUS.md) and [QUICKSTART.md](QUICKSTART.md). Example infrastructure settings are not live configuration.

## 安全结论

V1/V2 都是真实 proof-based VRF。首个拟部署基线仍是单 Operator ECVRF：它提供结果完整性、唯一性
和链上可验证性，但不能阻止 Operator 在看到结果后拒绝提交。仓库已有实验性 3-of-5 DKG/
resharing/BLS 多节点路径，可容忍少数节点离线；它尚未完成独立审计、第二实现互操作或真实多组织
ceremony，不能把“代码存在”宣传成生产 threshold network。

在独立审计、Robinhood testnet 长期演练和 threshold 上线前，不应用于承载高价值彩票、博彩、清算或不可逆 RWA 分配。

## 信任假设

必须信任：

- `secp256k1`、Keccak-256、ECRECOVER 与 MODEXP 预编译的安全性；
- 编译器和 Robinhood Chain EVM 执行正确；
- Operator VRF 私钥在 threshold 前不泄露；
- Timelocked Owner 只登记经过审查的 key、verifier 和计费参数；
- Consumer 正确处理异步交付、退款和长时间停顿。

无需信任：

- proof 内容本身；V2 仍授权固定 Fulfiller 以防止计费抢跑；
- 调用 `retryCallback()` 或 `refundExpired()` 的账户；
- Consumer callback 一定成功；
- Operator payout 地址一定能接收 ETH。

## 已处理威胁

| 威胁 | 控制 |
| --- | --- |
| Operator 伪造随机数 | ECVRF proof 必须在链上通过固定 public key 验证 |
| 跨链/跨部署 replay | seed 绑定 `chainId` 和 Coordinator |
| Proof 对错请求 replay | seed 绑定 Consumer、nonce、keyHash 与 request block hash |
| 管理员重抽 | 没有 cancel、replace、manual fulfill 或第二 Provider fallback |
| Relayer 窃取费用 | 费用固定记给请求时的 Operator，不记给 `msg.sender` |
| Callback revert | 随机数先持久化，callback 可重试 |
| Returndata bomb | callback assembly 不复制 returndata |
| 收款地址 revert | Operator 与 Consumer 都使用 pull-credit |
| Key rotation 改写 pending | 请求固定 keyHash、Operator 和 fee；停用只影响新请求 |
| Router provider swap | 同一个 keyHash 禁止重新绑定，并固定 Coordinator runtime code hash |
| Proof 长期不交付 | V1 退服务费；V2 到期释放 reservation，不扣余额 |
| Subscription ID 被盗用 | Subscription owner 必须逐个授权 Consumer 合约 |
| 免费白名单无限消耗 | Sponsor policy 有有效期、每日额度、pending 和 callback gas 上限 |
| 提款抽走 pending 预算 | 请求先 reserve 最大费用，只能提取可用余额 |
| 管理员临时提价影响 pending | 最低费、premium、分成、gas lane 和 overhead 在请求时固定 |
| 第三方高 gas 抢跑 proof | 请求固定 authorized Fulfiller，实际 gas price 受 lane 上限约束 |
| L1 data fee 漏计 | Robinhood/Arbitrum `ArbGasInfo.getCurrentTxL1GasFees()` 计入实际成本 |
| L1 fee padding grief | 每个 key 固定 exact proof length，内层 proof 与外层 calldata padding 均提前拒绝 |
| L1/L2 block 语义混用 | 请求、确认、过期、归档统一使用 codehash-pinned ArbSys L2 context |
| Owner 即时改价或换 key | 公共部署要求合约 Owner，并提供最短 12 小时 Timelock；Guardian 只能暂停 |

## 未处理风险

### Selective withholding

单 Operator 能提前计算唯一输出，然后选择不提交。退款只减少服务费损失，不能消除其对业务结果的拒绝偏差。

因此：

- 不允许在超时后向第二个独立 key 重抽；
- 不把多个 single-key Provider fallback 描述成 threshold；
- 高价值场景必须等到同一 group public key 的 threshold proof。

### 私钥泄露

泄露 VRF 私钥后，攻击者能生成所有未来 proof。Operator 启动时会拒绝与 proof key 相同的 relayer transaction key；部署流程仍需检查 Operator payout、owner 和 relayer 属于不同的运维权限域。

缓解：离线生成、加密落盘、最小权限主机、备份封存、公开 key rotation 流程。发生泄露时只能停用旧 key 的新请求；已有请求仍使用旧 key，必须根据事件时间和泄露时间制定应急处理。

### 请求 block reorg

低 confirmations 可能使 Operator 针对最终未采用的 block hash 出 proof。Consumer 应按价值选择 confirmations，Operator 只通过链上 `requestSeed()` 获取最终输入。测试网必须演练 sequencer/L1 延迟。

### Blockhash expiry

V2 Operator 应在 256-block 窗口内写入 `BlockhashStore`。如果 Operator 和归档 keeper 同时失效，
旧 request block hash 仍会不可恢复，请求只能到期释放 reservation，不允许用新 block hash 重建 seed。

### 恶意 Consumer

Consumer 可消耗其 callback gas、revert 或反复失败，但不能撤销已验证 randomness。Router 把应用交付拆为单独交易，避免恶意 Consumer 消耗 Operator proof fulfillment。

### Governance

Owner 可登记恶意的新 key 或 Coordinator，但不能覆盖现有 Router keyHash。Consumer 应在前端和合约配置中明确允许的 keyHash，不应自动采用“最新 key”。

Router 固定的是 Coordinator runtime code hash，不能识别代理背后的 implementation 变化。因此生产 Provider Coordinator 禁止使用 proxy；登记前必须检查部署字节码和存储槽。

V2 Coordinator 本身也不使用 proxy。Owner 仍能为未来请求登记恶意 verifier、设置不合理价格或
提取已结算 Treasury 收入，因此生产 Owner 必须是多签控制的 Timelock，并公开排队操作。Guardian
只能 pause 新请求，不能 unpause 或改变 pending request。

### 商业计费与偿付

`l1FeeReserveWei` 是治理配置的最大费用预留，不是链上可证明的未来上界。如果实际 L1 poster fee
加执行成本超过 reservation，fulfillment 会回滚，Operator 必须先归档 blockhash 并等待 gas 回落；
管理员不能扩大已有请求的 reservation。最低费和 Operator premium 分成必须覆盖归档、监控、坏账
和备用基础设施成本，不能只按正常交易 gas 定价。

本地原子 JSON 只适合单进程开发。多实例路径已使用 PostgreSQL scan/request lease、`SKIP LOCKED`、
session advisory nonce lock 和广播 journal/reconciliation；目标环境仍必须演练数据库 failover、连接
中断与进程 `SIGKILL`。PgBouncer transaction pooling 会破坏 session lock，禁止使用。

### Threshold 第一实现

3-of-5 只在少于三个节点被攻破或合谋时保护不可预测性；三个恶意节点仍可提前签名或 collectively
withhold。DKG bulletin board split view、假投诉、audit-log 截断、错误 reshare handoff、BLS
encoding/subgroup 缺陷和同一控制人伪装多个 Operator 都是剩余高风险。代码通过本仓库测试不等于
密码协议经过审计，正式收费前必须完成第二实现交叉验证与密码学专项审计。

### 上层经济与法律风险

VRF proof 只能证明随机输出，不能证明应用分配规则公平、资产有足额背书或产品符合法律。GRID 等涉及输家资金再分配的应用仍需独立审计与法律审查。

## 上主网前的硬门槛

1. Solidity verifier、Coordinator、Router 和 Operator 独立第三方审计。
2. 使用 `.nvmrc` 固定的 Node 22、锁定依赖和可复现构建。
3. 至少 30 天 testnet soak，持续公开成功率和 P95 延迟。
4. Key compromise、Operator outage、RPC split、callback OOG 和 refund 演练。
5. Owner 转给多签 Timelock，Guardian 使用独立权限域，proof key 与 relayer key 分离。
6. 完成 threshold 方案审查后，高价值应用才可取消单 Operator 限额。
