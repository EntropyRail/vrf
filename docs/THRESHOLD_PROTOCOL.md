# Threshold BLS 协议冻结项

> Historical technical document. Current release status and standalone integration instructions: [STATUS.md](STATUS.md) and [QUICKSTART.md](QUICKSTART.md). Example infrastructure settings are not live configuration.

## 当前结论

`ThresholdBLSVerifierAdapter` 已完成 Coordinator 接口、key commitment、消息 domain、输出 domain
和 backend runtime code-hash pinning。`BLS12381Backend` 已使用 RFC 9380 hash-to-curve 和
EIP-2537 pairing 通过独立固定向量及动态 3-of-5 聚合向量；group key 注册时用一对互相抵消的
pairing 同时完成曲线与 subgroup 校验。仓库里的 `MockThresholdBLSBackend` 仍只验证集成路径，部署
mock 等同于没有 proof，严禁部署到公共网络。

`operator/threshold-crypto.mjs` 已实现 partial signature 验证、公开 share commitment 验证、零点
Lagrange interpolation 和最终 group key 验证。不同合法 3-of-5 子集已测试得到相同签名，并由链上
EIP-2537 backend 验证。`operator/threshold-group.mjs` 冻结 group manifest，要求严格多数阈值、连续
index、HTTPS endpoint、Feldman public coefficients、阈值数量的 Ed25519 roster 签名；resharing 还
要求旧委员会阈值签名、上一份 manifest 的外部可信 hash，并强制 group public key 不变。

`operator/threshold-dkg.mjs` 已实现可执行的 Feldman-VSS DKG、X25519/HKDF/AES-GCM share transport、
Ed25519 签名 deal/response/complaint/resolution、qualification、manifest 绑定和保持 group key 的
resharing。`operator/threshold-node.mjs` 已实现双 RPC 独立取 seed、anti-equivocation state、mTLS
partial API、身份签名与 hash-chained audit log；Aggregator 已接入生产 relayer 路径。它们仍是本项目
第一实现，未经过密码学专项审计，只能用于 testnet/shadow。

2026-09-02 对 Robinhood public RPC 的只读探测结果：

- testnet chain 46630：ArbSys raw version 116（ArbOS 61），EIP-2537 G1ADD 返回 128 bytes，
  动态 RFC 9380 G1 signature/G2 public-key pairing 返回 true；
- mainnet chain 4663：同样为 raw 116 / ArbOS 61，G1ADD 与真实 pairing vector 均通过；
- 两条链的 BN254 empty pairing 也返回 32-byte true。

可用 `npm run probe:precompiles -- --rpc-url <URL>` 重跑。Phase 3 曲线因此选择
BLS12-381；任何 ArbOS 升级后必须重跑 capability probe 和链上固定向量。BN254 不进入当前主线。

真实 backend 仍有以下 gate：

- 还需为无穷点、非曲线点、非规范编码和错误 subgroup 增加第二实现交叉向量与模糊测试；
- vendored `randa-mu/bls-solidity` 固定在 commit
  `11af179a8287d978659aae07adb66aa60f64b8a6`，上游明确标为 experimental/unaudited，必须专项
  审计，不能因固定向量通过或“兼容 drand”跳过。

## 固定 wire format

Coordinator 调用 adapter 时：

```text
keyData   = groupPublicKey bytes
proofData = abi.encode(groupPublicKey, aggregateSignature)
keyHash   = keccak256(abi.encode(SCHEME_ID, keccak256(groupPublicKey)))

messageDigest = keccak256(abi.encode(
  MESSAGE_DOMAIN,
  chainId,
  verifierAdapter,
  keyHash,
  actualSeed,
  preSeed
))

randomness = keccak256(abi.encode(
  OUTPUT_DOMAIN,
  messageDigest,
  keccak256(aggregateSignature)
))
```

签名方案必须是 unique signature；任意达到阈值的合法 share 子集对同一消息聚合出同一个签名。
否则最后聚合者可以通过选择 share 子集选择随机输出。

Group manifest 和 share-set 的机器可验证格式见 [THRESHOLD_GROUP_SCHEMA.md](./THRESHOLD_GROUP_SCHEMA.md)。

## DKG ceremony（3-of-5 起步）

1. 五家独立 Operator 分别生成长期 identity key 和一次性 DKG transport key；禁止一个实体代生成。
2. 公布 participant ID、identity public key、软件 commit、容器 digest 和网络 endpoint。
3. 在冻结的 epoch、chain ID、adapter 地址和 scheme ID 上运行仓库内 Feldman-VSS DKG；所有 packet
   必须进入统一 append-only bulletin board。
4. 每个节点验证 dealer commitments、complaints 和 resolutions；不接受私下跳过 complaint。
5. 达到 `t=3` 后生成 group public key；没有任何进程或备份出现完整 group secret。
6. 所有参与方签署 transcript hash 和 group file；至少三方签名一致才可登记 keyHash。
7. 对固定消息集生成 partial/aggregate proof，由两套独立实现和链上 backend 交叉验证。
8. Group key 先进入 shadow network；ECVRF 仍负责生产输出，至少 30 天比对后才双轨开放。

阈值必须严格大于成员数的一半。3-of-5 可容忍两台离线，但三个合谋节点仍能提前生成或拒绝
签名；该信任假设必须公开。

## 在线签名

1. 节点从两个独立 RPC 读取 Coordinator request 和 `requestSeed`，不接受 aggregator 自报消息。
2. 节点校验 request status、keyHash、confirmation、blockhash 和消息 domain 后产生 partial signature。
3. Aggregator 校验每个 partial 对应的 manifest share public key、index 和消息，拒绝重复 index；这部分
   已由 `threshold-crypto.mjs` 实现。
4. 收集任意三份合法 share 后做 Lagrange interpolation，得到唯一 aggregate signature；本地实现和
   Solidity backend 已通过动态互操作测试。
5. Aggregator 在本地验证后由 gas estimation 执行等价链上验证，再由请求时固定的 authorized
   Fulfiller 发送交易；CLI 已接受 threshold manifest 并生成固定 416-byte `proofData`。
6. 节点把签名 requestId/message/share signature 写入 fsync、hash-chained audit log；绝不记录
   secret share。拒绝和网络延迟仍应进入外部可观测系统。

## Resharing

- 成员变更必须保持 group public key 不变；否则是 key rotation，不是 resharing。
- 旧委员会以旧阈值授权新 roster/epoch，新旧 roster 和承诺同时进入 transcript。
- 新成员只接收加密 share contribution，任何单个 dealer 不能决定新 share。
- 新 manifest 必须引用外部可信的旧 manifest hash，由旧委员会达到旧阈值的身份签名确认 handoff，
  并由新委员会达到新阈值的身份签名确认接收；本规则已在 manifest validator 实现。
- 在新委员会完成固定向量签名并由旧委员会签署 handoff 前，旧 epoch 继续服务。
- Coordinator 中已存在的 keyHash 不变；如果 group public key 变化，必须登记新 keyHash，旧 pending
  request 仍由旧 key 完成，不能迁移或重抽。
- 演练必须覆盖一名恶意 dealer、一名离线成员、complaint、恢复、重复 index 和 split-brain roster。

## 上线 gate

实验 backend、share verifier/aggregator、group manifest、DKG、complaint/resolution、resharing 和
在线多节点份额协议均已实现并有 3-of-5 自动化测试。下一 gate 不是继续补接口，而是对这套第一实现
做密码学专项审计、接入第二套独立实现交叉验证 transcript/share/aggregate，并完成 testnet shadow
soak。代码完成不代表主网许可。

完整 ceremony 命令与失败规则见 [DKG_RUNBOOK.md](./DKG_RUNBOOK.md)，与 Dice、Quiver、drand 的
设计边界对照见 [REFERENCE_COMPARISON.md](./REFERENCE_COMPARISON.md)。
