# Threshold Network Roadmap

> Historical technical document. Current release status and standalone integration instructions: [STATUS.md](STATUS.md) and [QUICKSTART.md](QUICKSTART.md). Example infrastructure settings are not live configuration.

## 原则

Threshold 的目标不是“有多个备用随机数源”，而是：

- 所有节点共享一个 group public key；
- 任意达到阈值的合法 share 集合重建同一个唯一 proof；
- 少于阈值的节点无法预测或生成输出；
- 节点子集变化不会改变最终输出；
- DKG 过程中没有任何参与方得到完整 group private key。

多个独立 ECVRF key 加 timeout fallback 不满足这些条件。最后一个参与者可以根据已观察结果选择是否触发另一条输出路径。

## Phase 1 — 单 Operator ECVRF（实现完成，待部署）

- `secp256k1` proof 与链上验证已工作。
- Proof key 与 transaction relayer key 分离。
- V2 Subscription、Sponsor、计费和 Consumer 接口与 proof scheme 解耦。
- Verifier 地址及 runtime code hash 在每个请求中固定。
- Blockhash 归档、持久化 Operator cursor、RPC failover 和 gas replacement 已实现。
- 公开 selective-withholding 风险，不接受高价值生产负载。

退出门槛：独立审计、testnet soak、监控和故障演练。

## Phase 2 — 多 Operator shadow network（代码完成，待真实运营方）

先不影响生产输出，运行 5 个独立节点：

- 不同云、地区和运营主体；
- 对同一测试输入运行 DKG、share generation 和 aggregation；
- 记录 share 到达时间、错误率、节点分叉和恢复时间；
- 主链仍由 Phase 1 ECVRF 结算，threshold 结果只做对照。

这一阶段不把独立 ECVRF 输出 XOR，也不把多数投票当作 threshold proof。

## Phase 3 — Threshold BLS testnet

优先评估 drand 风格的 `t-of-n` threshold BLS：

- 初始配置 `t=3, n=5`，阈值必须大于 50%；
- Feldman-VSS DKG，任何节点都拿不到完整私钥；
- 每个节点产生 partial signature；
- 聚合后得到与参与子集无关的唯一 BLS signature；
- 随机数为聚合签名的 domain-separated hash；
- Robinhood 合约只验证 group public key 与聚合 proof。

Curve 选择必须由链上能力测试和审计共同决定：

2026-09-02 已通过 public RPC 确认 testnet/mainnet 均为 ArbOS 61，并用动态 RFC 9380 G1
signature/G2 public-key vector 验证 EIP-2537 pairing 可用，
因此 Phase 3 选择 BLS12-381。`BLS12381Backend` 已通过 RFC 9380 独立固定向量，但 vendored
Solidity 库仍被上游标注 experimental/unaudited，只允许本地和 testnet shadow。ArbOS 每次升级
都要重跑 precompile probe。off-chain share verifier/Lagrange aggregator、Feldman public commitment、
group manifest、分布式 DKG、X25519 加密 share transport、签名 complaint/resolution、保持 group key
不变的 resharing、mTLS online signer 和 anti-equivocation log 均已实现。Phase 3 的剩余门槛是第二实现
互操作、密码学专项审计和五家独立 Operator 的公开 testnet ceremony。

参考：

- [drand protocol specification](https://docs.drand.love/docs/specification/)
- [drand cryptography](https://docs.drand.love/docs/cryptography/)
- [RFC 9381 VRF](https://www.rfc-editor.org/rfc/rfc9381.html)
- [Experimental drand-compatible Solidity BLS verifier](https://github.com/randa-mu/bls-solidity)

## Phase 4 — 双轨迁移

- 部署新的不可升级 `ThresholdBLSVerifier`，实现 `IVRFProofVerifier`。
- DKG 完成后登记新的 group `keyHash`。
- 在 `VRFServiceCoordinatorV2` 登记 group keyHash、新 verifier code hash 和 threshold fulfiller。
- ECVRF 与 threshold key 并行运行至少 30 天。
- Consumer 显式选择 group keyHash；Coordinator 不自动切换。
- 已有 ECVRF 请求继续由原 public key 完成，不能迁移或重抽。

## Phase 5 — Production threshold network

生产开放前必须满足：

- 至少 5 个法律和运维上独立的 Operator；
- DKG、resharing、成员加入/退出和灾难恢复均完成演练；
- 任何人都能收集足够 shares 重建唯一 proof；付费 fulfillment 仍需通过防 gas-price grief
  的 authorized fulfiller/relayer policy，不能把开放提交等同于开放计费；
- 节点身份、group file、public commitments 和部署字节码公开；
- 链上 verifier 与节点实现通过两家独立审查；
- 主网设置单请求价值上限和逐步放量机制；
- 公开 SLO、告警、事后报告和 key ceremony 记录。

## 不做的捷径

- 不用 `block.prevrandao`、timestamp、sequencer hash 或价格 feed 伪装 VRF。
- 不由多签直接提交随机数。
- 不在超时后让管理员选择另一个 seed。
- 不把 XOR 多个可拒绝输出当作 threshold VRF。
- 不在 group key 未经 DKG 的情况下由一个人生成再手工拆成 shares。
