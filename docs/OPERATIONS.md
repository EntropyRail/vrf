# Operator Runbook

> Historical technical document. Current release status and standalone integration instructions: [STATUS.md](STATUS.md) and [QUICKSTART.md](QUICKSTART.md). Example infrastructure settings are not live configuration.

## 运行边界

Proof key 和 transaction relayer key 必须分离。当前 proof nonce 由 HMAC-SHA256 基于私钥、
actual seed 和 domain 确定性生成，避免依赖运行时随机数质量；proof key 仍应放入 HSM/KMS
或隔离主机，不能以明文环境变量长期运行。

`run-v2` 提供：

- Robinhood 公网至少两路独立 RPC，并在 proof 前比较完整 request/seed fingerprint；
- 磁盘持久化 cursor 和 pending requests；
- 可配置 reorg lookback 重扫；
- 事件确认深度；
- 同 nonce gas replacement，并受请求 gas lane 限制；
- 延迟请求的 blockhash 主动归档；
- JSON health file 和结构化 stdout/stderr。

JSON 状态文件使用临时文件加原子 rename 更新，只适合单进程本地开发和 canary。生产
active-active 使用 PostgreSQL：扫描器有短租约，请求领取使用 `FOR UPDATE SKIP LOCKED`，失败任务
指数退避，同一 chain/relayer 的交易通过 session advisory lock 串行化。锁覆盖首次广播和同 nonce
replacement；实例崩溃后 PostgreSQL 自动释放连接级锁。交易 journal 会在再次广播前跨全部 RPC
对账 mined、pending、replaced、dropped/consumed nonce。Operator 先本地签名并把确定的 transaction
hash 写入 journal，成功后才广播 raw transaction，缩小“已广播但未记账”的崩溃窗口，避免进程
`SIGKILL` 后错误复用 nonce。

nonce 在持锁区间内从所有 RPC 重新读取 `pending` 并要求一致，不依赖 provider 缓存。签名后、
journal 后分别检查持锁连接仍然存活；连接丢失就拒绝广播。这不是跨数据库 split-brain 的 fencing
协议，也不能消除最后一次检查与外部广播之间的竞态。journal 保存 hash/nonce 元数据，**没有**保存
可重播的 signed raw transaction；恢复时通过链上 receipt/nonce 对账，不能宣称原始交易已可靠备份。

错误日志保留允许的 code、内层 RPC 原因、方法名和 syscall；URL/token、认证头、params 和长 hex
不输出。`could not coalesce error` 不再覆盖内层原因，但历史缺失日志无法事后恢复根因。

服务器 systemd、加密 credentials、readiness gate 和目录权限见
[公开配置模板说明](../deploy/README.md)。CLI 的 secret 均可用对应的 `*_FILE` 传入，例如
`VRF_TX_PRIVATE_KEY_FILE`、`VRF_KEY_PASSWORD_FILE` 和 `VRF_DATABASE_URL_FILE`，生产服务不需要把
secret 直接放入环境变量。

## 启动

### 单实例本地模式

```bash
VRF_KEY_PASSWORD='...' \
VRF_TX_PRIVATE_KEY='0x...' \
npm run operator -- \
  run-v2 \
  --keystore /secure/vrf-key.json \
  --rpc-urls https://rpc-a.example,https://rpc-b.example \
  --coordinator 0x... \
  --from-block 123456 \
  --state /var/lib/vrf/operator-state.json \
  --health-file /var/lib/vrf/health.json \
  --event-confirmations 2 \
  --reorg-lookback 32 \
  --archive-after-blocks 128 \
  --replacement-ms 45000 \
  --replacement-attempts 3
```

### PostgreSQL active-active

每个实例使用相同的 `VRF_DATABASE_URL`、Coordinator、proof key 和 relayer。数据库 URL 放环境变量，
不要放命令行或日志；数据库账号只授予该 schema 的 DDL/DML 权限。

```bash
VRF_DATABASE_URL='postgresql://vrf_operator:...@db.internal/vrf' \
VRF_RPC_URLS='https://rpc-a.example,https://rpc-b.example' \
VRF_KEY_PASSWORD='...' \
VRF_TX_PRIVATE_KEY='0x...' \
npm run operator -- \
  run-v2 \
  --keystore /secure/vrf-key.json \
  --coordinator 0x... \
  --from-block 123456 \
  --health-file /var/lib/vrf/health.json \
  --event-confirmations 2 \
  --reorg-lookback 32 \
  --scan-lease-seconds 60 \
  --request-lease-seconds 360 \
  --work-limit 25
```

数据库自动建立四张表：instance heartbeat、scan state、pending request 和 transaction journal。
建议数据库本身使用跨可用区高可用，连接池前不要启用会破坏 session advisory lock 的 transaction
pooling；PgBouncer 必须使用 session pooling。
请求租约必须大于两笔最坏情况交易（blockhash archive + fulfillment）的全部 replacement 等待时间
再加 60 秒；Operator 会在启动时拒绝过短配置。

### 独立测试网归档进程

`proof-vrf-archiver.service` 在 op-b 独立运行；op-b 的 Operator 平时仍 disabled/inactive。归档进程
没有 proof key、prover token 或 mTLS client key，不领取 Operator 的 scan/request 租约。它使用两路
独立 RPC 核对最近 512 个区块中的请求、区块边界和 L2 context，在请求达到 32 个区块时尽早调用
permissionless `BlockhashStore.store()`，并共享 PostgreSQL relayer nonce 锁。

当前部署只允许 chain 46630；启动时绑定 manifest 的 Coordinator/BlockhashStore runtime codehash。
它**仍依赖同一数据库、relayer 及双 RPC**，不是可抵抗所有依赖故障的独立网络；standby Operator
接管目前需要人工操作，不是自动 HA。高负载下反复扫描/归档的吞吐与 RPC 配额尚未验收。

- 预算文件：`/var/lib/proof-vrf/archiver-state.json`，health：`/var/lib/proof-vrf/archiver-health.json`。
- 总归档预算：`10,000,000,000,000 wei`（0.00001 测试网 ETH），不是每日额度；重启不重置。
- 每次广播前按 gas limit × gas price 持久化保守预留，未知结果/失败尝试不自动退回预算。
- gas price 上限：`15,000,000 wei`，同时受请求原 gas lane 约束；relayer 余额下限 0.002 ETH。
- 单次 checkpoint 高度间隔超过 192 区块、未保护请求超过 256 区块或预算耗尽会留下粘性异常。
- 不得删除/修改 state 来清除告警或绕过预算；先核查受影响请求，再经明确授权处理。
- 同一预算文件只允许一个归档实例；不能直接横向扩容后仍声称总费用有此上限。

内部故障演练记录未随公开快照发布。公开状态与证据范围见
[STATUS.md](./STATUS.md)；不得把内部测试描述当作公开可用性 SLA。

### 隔离 prover / HSM 边界

普通 KMS 的 secp256k1 ECDSA `Sign` 接口不能生成 ECVRF，因为 ECVRF 需要对 hash-to-curve 点做私钥
标量乘法。可用做法是把 `operator/proof.mjs` 的等价实现放入隔离 prover（HSM 自定义应用、Nitro
Enclave 或隔离主机），交易 Operator 只调用 HTTPS API：

```bash
VRF_DATABASE_URL='postgresql://...' \
VRF_RPC_URLS='https://rpc-a.example,https://rpc-b.example' \
VRF_PROVER_URL='https://prover.internal' \
VRF_PROVER_BEARER_TOKEN='...' \
VRF_TX_PRIVATE_KEY='0x...' \
npm run operator -- \
  run-v2 \
  --proof-key-hash 0x... \
  --coordinator 0x... \
  --from-block 123456
```

Prover 必须实现 `GET /v1/status` 和 `POST /v1/proofs`。请求只包含 requestId、Coordinator、chain 和
key commitment，不接受 Operator 自报 seed；Prover 从两路 RPC 独立解析链上 request。仓库内
`operator/prover-server.mjs` 已强制生产 TLS 1.3/mTLS。Operator 仍核对 actual/pre-seed、公钥、
keyHash 和 proof；无效 proof 会在交易 gas estimate 阶段被链上 verifier 拒绝。

### Threshold 3-of-5

五个 signer 分别运行 `proof-vrf-threshold-node.service`，Aggregator 运行
`proof-vrf-threshold-aggregator.service`。节点只接受 requestId，自行通过两个 RPC 调用
`requestSeed()` 和 adapter `messageFor()`；每个 partial 同时带 BLS share 和 Ed25519 identity
signature。Aggregator 验证达到 threshold 的 share 后聚合，复用 PostgreSQL nonce 协调和 relayer。

节点的加密 share、TLS key、identity key、状态和 audit log 不得复制给其他运营方。具体 DKG、
complaint、resharing、manifest attestation 和启动命令见 [DKG_RUNBOOK.md](./DKG_RUNBOOK.md)。

## Gas 与价格校准

至少积累 100 个真实 fulfillment 后运行：

```bash
VRF_RPC_URLS_FILE=/secure/rpc-urls \
npm run calibrate -- \
  --coordinator 0x... \
  --from-block 123456 \
  --minimum-samples 100 \
  --target-minimum-usd 0.01 \
  --eth-usd 4500 \
  --out /var/lib/vrf/calibration.json
```

`/secure/rpc-urls` 应为已有的 0600 凭据文件，内容为两个独立 HTTPS origin 的逗号分隔 URL；不要把
真实 token 放进命令行参数或版本库。采样器默认留出 12 个确认区块，并交叉核对两路 RPC 的边界、
settlement、receipt 和请求 reserve；不同结果会直接失败。

报告用 settlement 事件和原始 receipt 计算 P50/P95/P99。`maxGasPriceWei` 建议值是实际 gas price
P99 的 125%，`l1FeeReserveWei` 是 receipt L1 fee P99 的 150%。Robinhood/Nitro 的原始 receipt 使用
`gasUsedForL1 * effectiveGasPrice` 推导 parent-chain fee（优先使用直接给出的 `l1Fee`）；
`gasUsedForL1` 已含在总 `gasUsed` 中，不能重复加到总交易 gas 费用。依据见
[Arbitrum gas and fees](https://docs.arbitrum.io/how-arbitrum-works/deep-dives/gas-and-fees)。
缺少两种 L1 字段时保留 `null`，不猜测。报告还保留逐笔来源与真实交易费，检查 reserve 与
Operator 收款是否覆盖履约 gas；独立的 blockhash archive/retry 成本仍需单独计入运维预算。

不足 100 笔不能标记 `readyForGovernanceReview`，小样本统计不是可上线的费率校准。
ETH/USD 是人工快照输入，按整数向上取整；治理前必须复核并走 timelock。上述 USD 数字仅是命令
示例，不代表已批准的收费标准。采样器不会发交易或修改链上价格。

## 30 天 testnet soak

部署前先生成并保存 deployment manifest、source/runtime/ownership verification report 和 canary
manifest。`deployment:verify` 要求每个合约的 HTTPS explorer/source URL 可访问、与地址绑定且页面
声明 source verified；`canary:start:testnet` 只允许 chain 46630，并要求 verification report 已通过。
Operator 履约后生成端到端报告：

```bash
VRF_RPC_URLS='https://rpc-a.example,https://rpc-b.example' \
npm run smoke:report -- \
  --manifest /secure/deployment.json \
  --verification-report /secure/deployment-verification.json \
  --request-id 123 --consumer 0x... \
  --out /secure/smoke.json
```

报告要求两路 RPC 状态一致、runtime codehash 匹配、request 已 fulfilled、callback 成功且链上只出现
一份 proof/settlement 事件。当前 smoke 工具将状态固定在两路最小高度减 12 的同一确认区块，
核对区块哈希和双方完整 proof/callback/settlement 事件（按 2,000 区块分段），拒绝遗漏、重复或
内容不一致。报告默认以 0600 写入；不应把仅一路事件查询称作双路事件验证。

从通过 smoke 的区块开始生成可重复的链上证据。两个 RPC 必须来自不同运营商，并对边界区块哈希、
L2 context 及全部请求/证明/callback/结算/过期事件完全一致：

```bash
VRF_RPC_URLS='https://rpc-a.example,https://rpc-b.example' \
npm run soak:report -- \
  --coordinator 0x... \
  --manifest /secure/deployment.json \
  --verification-report /secure/deployment-verification.json \
  --smoke-report /secure/smoke.json \
  --from-block <smoke-checked-through-block> \
  --expected-days 30 \
  --minimum-requests 1000 \
  --out /var/lib/vrf/soak-day-30.json
```

不足 30 天、请求量不足、履约/最终 callback 低于 99.9%，或存在已过期但未终结请求时不会通过。
报告只证明链上结果；RPC split、reorg、gas spike、数据库 failover、备用 relayer 和 prover 故障演练
必须另附签名记录。

目录必须预先存在并只允许 Operator 用户读写。不要把 keystore、状态文件或 health file 提交到仓库。

## 告警

至少监控：

- pending request 最老年龄；
- request 到 fulfillment 的 P50/P95/P99；
- Sponsor/客户 Subscription 可用余额与已预留余额；
- proof revert、callback failure、replacement exhaustion；
- gas price 超过 key lane 的持续时间；
- RPC head 分叉和事件回滚；
- blockhash archive 距离 256-block 上限的余量；
- relayer ETH 和 proof-key host 健康状态。

当前每日 10:00（Asia/Shanghai）的本地 Codex 巡检只读既有自然流量，不发新请求、不调整费率，
仅在异常、恢复或需要授权时通知。巡检依赖本机开机和应用运行，不能替代服务器侧秒级告警；
独立 archiver 本身运行在服务器上，不依赖本机在线。正式 soak 尚未启动。

## 故障处理

- RPC 故障：保持 pending 状态，切换备用 RPC，不根据本地 RPC block hash 自行构造 seed。
- Gas lane 过低：先确保 request block hash 已归档，再由 timelock 只调整未来请求的 key lane；旧请求
  仍受原 lane 保护。
- Callback 失败：proof 和计费已完成；任何账户可调用 `retryCallback` 捐赠 gas，不再收费。
- Operator proof key 疑似泄露：Guardian 暂停新请求，timelock 停用 key，保存日志；已有请求不能
  自动换 key 或重抽，按公开 incident policy 处理。
- Operator outage：单 Operator 阶段无法由管理员伪造结果；保留请求到 timeout，随后释放客户预留。

## 上线顺序

1. 本地与 fork 测试；
2. Robinhood testnet 单实例 canary；
3. 两个备用 RPC、一个 standby relayer 的故障演练；
4. 30 天测试网 soak；
5. 独立审计与修复复审；
6. 主网低额度 allowlist canary；
7. 达到 SLO 后逐步扩大公共 Subscription。
