# 第三轮：V3 请求状态承诺，继续降低 gas

> Historical technical document. Current release status and standalone integration instructions: [STATUS.md](STATUS.md) and [QUICKSTART.md](QUICKSTART.md). Example infrastructure settings are not live configuration.

状态：**本地实验候选，未部署，未修改服务器、密钥、线上费率或 CI/CD，未提交 Git**。
不是主网准入报告。V2 继续可用，V3 是独立地址、独立订阅的新版本，不能原位升级或直接替换
现有 Operator 的 Coordinator 地址。完整测试与基准命令见文末。

## 同条件结果

固定证明输入、requestId、测试公钥、gas price、Consumer、回调上限、调用次序、20% premium、
150,000 fulfillment overhead，比较前一轮 V2 与新增 V3。不是靠减少验证或调低收费参数获得节省。
普通单随机数、常态请求（非首次初始化）：

| 指标 | 最初版本 | 第二轮 V2 | 第三轮 V3 | V3 相对第二轮 |
| --- | ---: | ---: | ---: | ---: |
| 请求 gas | 381,754 | 202,424 | 141,913 | 降 29.9% |
| 履约 gas（含验证和回调） | 176,685 | 173,794 | 151,235 | 降 13.0% |
| 两笔总 gas | 558,439 | 376,218 | 293,148 | **降 22.1%** |
| 调用方总支出，ETH（1 gwei、零 L1 费） | 0.0007009924 | 0.0005192804 | 0.0004325386 | **降 16.7%** |

相对最初版本，总 gas 累计降 **47.5%**，调用方支出累计降 **38.3%**。
调用方支出指 request 交易费 + Subscription 被扣的服务费；服务费已含 Operator 的网络补偿，
不能再次加一遍 fulfillment 交易费。部署、充值、归档、提现、服务器、RPC 和审计不计入该表。
Sponsor 免服务加价不等于免网络费，仍然由项目的 Sponsor Subscription 承担成本。

### 其他路径与代价

| 场景 | 第二轮 V2 gas | V3 gas |
| --- | ---: | ---: |
| 首次公共单词请求＋履约 | 486,646 | 403,588 |
| 公共 3 词请求＋履约 | 440,408 | 357,367 |
| 公共 32 词请求＋履约 | 1,057,937 | 975,007 |
| Sponsor 单词常态请求＋履约 | 387,194 | 303,866 |
| 首次回调失败，请求＋履约，不含重试 | 442,134 | 357,675 |
| 额外 callback retry | 89,481 | **106,874** |
| 过期释放 | 60,905 | **67,578** |
| prune | 49,334 | 42,807 |
| getRequest 的 eth_call gas 估算 | 52,786 | 36,250 |
| setPricing，相同参数 | 84,632 | 84,669 |
| setKeyService，相同参数 | 162,904 | 162,963 |
| Coordinator 单体部署 | 4,894,132 | **5,224,097** |

失败重试增加约 19.4%，过期释放增加约 11.0%，单体部署增加约 6.7%；不能只宣传请求路径。
32 词 Consumer 回调会写入大量 storage，证明部分节省被业务写入稀释，整体仅再降约 7.8%。
不要把 32 个词自动视为 32 笔独立业务：一份证明的全部输出一旦公开，后续业务不能再把它们当作
尚不可预测的新随机数。若做批量业务，必须先固定全部参与者、输入与结果映射，再请求随机数。

## 设计与安全边界

V2 每请求 5 slots，其中 pending 通常 4 个非零；V3 每请求仅存 **一个完整 256-bit 状态哈希**：

`keccak256(abi.encode(domain, chainId, coordinatorAddress, fullRequestWitness))`

完整 27 字段通过 `CompactRequestState` 事件公开，在履约、读取、重试、过期和清理时提交。
合约先比对整个哈希，验证通过后才使用其中的地址、价格、预留资金、确认数、状态和 randomness。
这不是截断哈希，不是信任 Operator 自报字段，也**不是把 proof-based VRF 改成 commit-reveal RNG**。
订阅余额、真实资金预留、Consumer/Sponsor pending、nonce 与收益负债仍正常存储和记账。

主要约束：

- ECVRF 验证器、证明长度、确认窗口、L2 blockhash、Verifier/L1 calculator codehash、gas lane 和授权不变。
- 当前状态哈希包含唯一 randomness 和 callbackAttempts；成功、失败、过期均发出完整状态事件。
- 旧 witness 无法在新状态上重放，伪造字段无法履约或释放余额。prune 后旧 witness 不能恢复请求。
- 回调前写入 fulfilled 的临时状态承诺，所有生命周期写方法受同一个防重入锁保护。
- 履约严格检查 proof 长度、整个 calldata 长度和动态 proof 偏移，拒绝尾部加料与重叠 ABI 数据。
- 完整状态事件位于 measured-gas 计费区间内；没有把新增的大事件成本藏到计费测量之外。
- 重试仍然 permissionless、无第二次服务扣费；重试交易费由执行者承担。
- 同一 proof verifier 抽象仍可用；已本地验证真实 EIP-2537 3-of-5 BLS aggregate。

参考了 [Dice 的 Request 存储结构](https://raw.githubusercontent.com/diceprotocol/dice-entropy/main/contracts/src/sdk/DiceStructsV2.sol)
将多个值绑定到 commitment 来节省存储的做法。但这里承诺的是完整请求状态，随机性仍来自原 ECVRF/BLS
验证路径；不能据此认为两套协议具有相同安全假设，也没有得出比 Dice/Quiver 更便宜的结论。

## 接口与运行条件确实有变化

请求 API `requestRandomWords(params)` 与 `rawFulfillRandomWords(requestId, words)` callback ABI 保持一致。
但不能声称所有接口兼容：

| V2 | V3 |
| --- | --- |
| `getRequest(requestId)` | `getRequest(witness)` |
| `requestSeed(requestId)` | `requestSeed(witness)` |
| `fulfillRandomWords(requestId, proof)` | `fulfillRandomWords(witness, proof)` |
| `retryCallback / expireRequest / pruneRequest / randomWords(requestId)` | 对应方法均传完整 witness |
| `RandomWordsRequested` | 每次状态迁移发出 `CompactRequestState`；不再发出旧请求事件 |

不能只凭 requestId 从链上 storage 取回原始字段或 randomness，需要可靠的事件历史或保存的最新 witness。
依赖旧查询接口的 Consumer、Indexer、Dashboard、Router 或审计脚本都必须逐一检查；callback ABI
不变不代表回调过程中依赖旧 `getRequest(requestId)` 的业务仍兼容。

`operator/compact-protocol.mjs` 已提供只读 SDK：

1. 严格的 27 字段 JSON 规范化、位宽/类型检查、与 Solidity 一致的 domain hash。
2. 从受信任的部署块开始分段查事件，验证创建与每次状态迁移；创建、中间重试或最终事件缺失均拒绝。
3. 至少两个独立 RPC，在共同的 block number/hash 上比对事件和当前 commitment，读后复查 anchor 防重组。
4. `prepareCompactTransaction` 生成并在两个 RPC 上模拟履约/重试/过期/prune 交易；**不签名、不广播**。
5. `RemoteProofProvider` / `prover-server` 可选传递 compactWitness；隔离 Prover 自行通过两个 RPC 认证
   当前 commitment，并调用合约取得 actualSeed，不使用客户端随意提交的 seed。V2 的原请求格式保留。

URL 模式默认要求不同 origin；直接注入 provider 对象仅用于集成/测试，调用方必须保证来源独立。
同一个 dRPC 的不同 token 不是独立故障域。当前 SDK 查询的是共同已知区块，不宣称该区块已达最终性；
链上仍按原 L2 confirmations 策略执行，长期索引必须另做重组回退与 canonical checkpoint。

### 尚未完成，禁止直接切流

- V3 的常驻 all-request Indexer、持久化 witness 缓存、重组回退、PostgreSQL lease/nonce journal
  与现有 `run-v2` daemon 尚未接成发布级流程。SDK 是单请求恢复/交易准备模块，不能冒充完整 Operator。
- 现有独立 Archiver、calibrate、soak、manifest/deploy/smoke/验证脚本仍以 V2 为准，需要 V3 适配。
- 现有在线 Threshold 节点仍用 V2 链上 resolver；新 SDK 对 `threshold-bls` 模式明确报错，
  避免把“合约能验 BLS”误当成“V3 多节点网络已上线”。DKG/resharing 代码没有因本次改动而完成新一轮审计。
- 需要新地址、重新创建/充值订阅、配置 Consumer/Sponsor、治理与 key，旧请求应在旧 Coordinator 排空。
  不迁移进行中的 request，不把旧地址的 witness 复用到新地址。实际部署/切换须另行授权。
- 第三方密码学/合约审计、真实链校准、故障恢复演练和充分 canary/soak 仍是上线条件。

## L1 数据费：不能用零 L1 基准直接报主网价格

ECVRF 履约 calldata **516 → 1,348 bytes，增加 832 bytes**；完整状态事件也增大。
事件执行成本已经进入本地 gas，但链上事件数据不是等量的交易 calldata，不能直接按事件大小另收一次 L1 费。
Nitro 的 parent-chain 成本取决于交易的压缩大小与动态 data price，不是固定每原始字节价格。
[Arbitrum Gas and fees](https://docs.arbitrum.io/how-arbitrum-works/deep-dives/gas-and-fees)

本轮没有采样主网或假装执行 Robinhood fork。基于本地差额的模型（非报价）：

- 普通单词网络节省 ≈ `83,070 × L2 gasPrice − 新增 parent-chain 费用`。
- 同样 20% premium 且不触发最低收费时，客户节省约为 `86,741.8 × gasPrice` 减去新增请求数据费及
  `1.2 × 新增履约数据费`；准确值必须用整数公式与真实 receipts 校准。

需要对 V3 的真实交易重新计算 L1 reserve、billing overhead 和最低费，保证 Operator 不倒贴。
没有降低验证 gas 上限或预留金额来制造便宜报价，也没有自动改线上费率。

## 代码、回归与证据

共同订阅/授权/收费逻辑提取到 `VRFServiceCoordinatorBase.sol`，V2 生命周期仍保留在 V2 合约。
机械提取后 V2 的全部 7 行 gas、部署 gas、runtime 字节数与规范化公开 ABI 都与第二轮完全一致。
源码组织变更可能改变 metadata/codehash，部署验证必须重新计算，不能沿用旧 codehash。

- `contracts/VRFServiceCoordinatorV3.sol`：V3 生命周期与状态承诺。
- `operator/compact-protocol.mjs`：恢复、RPC 校验、可选远端 Prover 与交易准备。
- `test/CompactCoordinator.test.cjs`：全字段篡改、重放、付款与非零 L1 费用、授权/轮换、防重入、
  过期/prune、blockhash archive、Sponsor、12 笔乱序会计不变量及真实阈值 BLS。
- `test/CompactProtocol.test.cjs`：字段边界、两 RPC HTTP resolver、canonical seed、缺失/重复事件、
  中间重试遗漏、分叉与 mid-read reorg、模拟后状态竞争及无密钥的过期/prune。
- `test/CompactGasBenchmark.test.cjs`：7 场景与第二轮精确 proofHash/requestId 对照；每场景总 gas
  至少少 75,000，同时约束重试、过期、prune 与部署开销。旧基线不覆盖。
- [V3 原始基准](./evidence/gas-compact-v3-2026-09-03.json)
- [共享基类提取后的 V2 原始基准](./evidence/gas-v2-shared-base-2026-09-03.json)
- [第二轮历史基准](./evidence/gas-optimized-v2-round2-2026-09-03.json)

V3 runtime 为 **21,497 bytes**，小于 EIP-170 上限 24,576。SHA-256：

- V3：`d7fe98371a879be14ebc107308cdaa8e23bc72e17543d02ac9105c7ee2d76a30`
- Base：`86913b6f5326d71e60ef2eaa74414a554b56b1f37d6cca629f98ea0598e478c5`
- 提取后的 V2：`99edf091e5e6906e160009a7391dd48294d82023e85bcabc61eba38a47e201a6`

Node 22.13+，在 `vrf` 目录执行，不需网络钱包：

```bash
npx hardhat --config hardhat.config.js test test/CompactCoordinator.test.cjs test/CompactProtocol.test.cjs test/CompactGasBenchmark.test.cjs test/GasBenchmark.test.cjs
env -u VRF_TEST_DATABASE_URL -u VRF_RUN_ROBINHOOD_FORK -u VRF_DEPLOYER_PRIVATE_KEY npx hardhat --config hardhat.config.js test
```

最后一次完整本地回归为 **106 passing（Hardhat 汇总，包含 runner 自动收集的两个 helper/fixture 文件）**，
退出码 0。外部 PostgreSQL 和 Robinhood fork 未在这次本地回归启用，不能把跳过项当作已验证。
