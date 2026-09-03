# V2 gas 优化：版本化配置与紧凑请求

> Historical technical document. Current release status and standalone integration instructions: [STATUS.md](STATUS.md) and [QUICKSTART.md](QUICKSTART.md). Example infrastructure settings are not live configuration.

这是第一轮历史结果，数据与基线保留不覆盖。当前代码已进一步优化，见
[第二轮报告](./GAS_OPTIMIZATION_ROUND2_2026-09-03.md)。

状态：仅本地完成，未部署到测试网或主网，未改任何线上费率、凭据、服务、CI/CD 或 Git 历史。
旧测试网 Coordinator 不会因修改本地源码自动改变。本报告不是审计认证或主网报价。

## 结论

正常、已初始化的单随机数回调场景，本地对照测得请求 gas 降低 **35.7%**，
请求与履约总 gas 降低 **25.3%**；保留原有 20% premium 和 150,000 overhead 时，
调用方支出（请求 gas + subscription 服务扣费）降低 **20.3%**。

完整本地测试报告为 **81 passing**。PostgreSQL 外部数据库和 Robinhood fork 测试本轮未启用，
不能把本地通过解释成完成线上集成、故障演练、第三方审计或主网准入。

## 参考了什么，没有照搬什么

- Dice 将 Request 的小字段紧凑排列为四个 storage slots，并用一个 commitment 代替两个原始值。
  它也把 provider 数据独立保存。本次借鉴的是减少每请求重复持久化和紧凑存储的原则，
  没有复制其代码。[Dice Request 源码](https://github.com/diceprotocol/dice-entropy/blob/main/contracts/src/sdk/DiceStructsV2.sol)
- Dice 还使用固定槽位加 overflow mapping，已完成槽位可复用；这能避免部分反复的零到非零写入。
  本轮不采用：我们需要保留随机结果供查询、失败重试以及延后清理，直接复用会改变现有语义。
  预填槽位也只是把部分成本移到部署，不是免费消除成本。
  [Dice 分配与清理实现](https://github.com/diceprotocol/dice-entropy/blob/main/contracts/src/DiceEntropy.sol)
- Dice/Quiver 的 hash-chain/commit–reveal 与我们的 ECVRF 不是同一种证明机制，不能靠删除
  ECVRF、L2 blockhash、确认数或 verifier code-hash 校验来追求相同价格。
  [Quiver 集成资料](https://github.com/camdengrieh/quiver-kit)
- 保留按计费执行量结算，不直接降低 gas limit 来制造“降本”。gas limit 主要是执行上限；
  过低会令回调或履约失败。[Chainlink VRF 计费说明](https://docs.chain.link/vrf/v2-5/billing)

## 实现与不变量

`VRFServiceCoordinatorV2` 的内部 Request 原先占 13 个 slots。新增 `StoredRequest` 占 7 个，
其中 6 个在正常新请求中非零；`randomness` 仍在通过证明后才写入非零输出。

`KeyVersion` 保存 keyHash、verifier、verifierCodeHash、fulfiller、payee、maxGasPriceWei、
verificationGasLimit 和 proofDataLength。注册 key 或 `setKeyService` 时创建新版本，
请求只记录 uint64 版本号。版本编号全局单调递增、Solidity checked arithmetic 防溢出；
旧版本没有修改或删除入口。`setKeyActive` 不改写历史快照。

每请求定价、额度、L2 区块、preSeed、预留金额和状态仍独立保存。没有缩窄 subscriptionId、
nonce、preSeed、reserve、randomness 的 uint256 范围，也没有改变请求 ID 或随机输出算法。

`getRequest` 从请求与其固定版本拼回原 `Request`。所有公开函数、返回 tuple、事件和错误
保持原 ABI；Operator、calibration 和 Consumer 的旧 ABI 不需要因这次优化重写。

安全边界保持：

- 服务轮换、定价更新、key 停用不改变旧请求的验证器、Fulfiller、payee、gas lane 和分账。
- proof 长度、外层 calldata 长度、verifier/L1 calculator code hash 仍在扣费之前校验。
- 订阅 reservation、最大付费限制、Consumer/Sponsor 配额、过期释放与防重入保持。
- 失败回调保留同一个随机输出；permissionless retry 不产生第二次服务扣费。
- 清理旧请求不能删除共享配置，不能影响后来使用同一版本的请求。
- Threshold adapter 与既有 BLS 互操作测试仍通过；这不代表 threshold 已获生产安全认证。

## 可重现 gas 对照

环境：Node 22.23.2、Hardhat 3.15.0、solc 0.8.24、viaIR、optimizer runs 500、Shanghai，
本地模拟链。交易 gas price 固定 1 gwei，L1 fee calculator 为零费 mock。

MockBlockContext 使用相同固定区块哈希，部署顺序、合约地址、请求 ID、证明 nonce 和
proof bytes 前后一致；gas 测试强制核对所有 requestId 和 proofHash，避免 hash-to-curve
循环次数不同造成虚假节省。mock 本身有执行成本，不能直接当作 Robinhood 交易 gas 校准。

单词场景 callback gas limit 100,000，32 词为 1,000,000，使用相同 Example Consumer。
`cold` 表示该 Consumer 首次写入随机数；`steady` 表示已有同长度结果。
3/32 词场景顺序从 1/3 词扩展，会包含新增结果存储。

| 场景 | 请求 gas：原 → 新 | 履约 gas：原 → 新 | 两笔合计：原 → 新 | 合计下降 |
| --- | ---: | ---: | ---: | ---: |
| 公共 1 词首次 | 415,954 → 279,562 | 252,913 → 247,984 | 668,867 → 527,546 | 21.1% |
| 公共 1 词常规 | 381,754 → 245,362 | 176,685 → 171,756 | 558,439 → 417,118 | 25.3% |
| 公共 3 词 | 381,754 → 245,362 | 240,875 → 235,940 | 622,629 → 481,302 | 22.7% |
| 公共 32 词 | 381,766 → 245,374 | 858,389 → 853,369 | 1,240,155 → 1,098,743 | 11.4% |
| Sponsor 1 词首次 | 424,238 → 287,813 | 238,433 → 233,504 | 662,671 → 521,317 | 21.3% |
| Sponsor 1 词常规 | 390,038 → 253,613 | 179,305 → 174,376 | 569,343 → 427,989 | 24.8% |
| 首次回调失败 | 415,954 → 279,562 | 208,396 → 203,475 | 624,350 → 483,037 | 22.6% |

失败后的额外 retry：92,444 → 87,521 gas；未计入上述“两笔合计”。
公共常规场景用户支出为 0.0007009924 → 0.0005588056 ETH（仅本地固定 1 gwei、零 L1 费）。
150,000 overhead 和费率均未降低；计费 gas 仍不等于 receipt gas，不能声称是网络实际成本加 20%。

代价：Coordinator 单体部署 4,557,886 → 4,761,279 gas，增加 203,393；注册与轮换配置也要
写入不可变快照。优化适合配置低频、请求高频的服务。新 runtime 为 19,593 bytes，低于
EIP-170 的 24,576-byte 限制；此上限已纳入回归测试。

### 费用量级，不是新的主网报价

沿用前一轮 2026-09-03 01:05–01:06（UTC+8）主网采样的 0.405268–0.419482 gwei，
假设此次本地差额可迁移且 L1 posting 费用保持此前量级：

- 整个服务正常自用网络成本约从 0.000227–0.000235 降到 **0.000170–0.000176 ETH**。
- 外部调用方总支出约从 0.000285–0.000295 降到 **0.000227–0.000235 ETH**。

方法是从上一轮 receipt-based 模型分别扣除 136,392 request gas、4,929 fulfillment gas，
以及计费公式中的 4,829 measured gas；没有把 Operator 网络费重复加到服务扣费上。
不含部署、配置、充值、提现、延迟归档、失败重试和服务器/RPC/审计成本。
这只是差额外推，仍需新地址的测试网与主网 fork/模拟校准；不是固定报价。
按此前同链报价量级，仍不能宣传比 Dice/Quiver 便宜。

## 证据与复现

- 优化前源码来自 Git `7ac35690ea36bdca82f765a74944ae8cd4807c66`，
  blob `11558d776d930c58f38c9b882a86f48e85f38474`。
- 原源码 SHA-256：`aec3741d299ed76f07b4872ad61b17489c18f4c86a8279b075916db04990c701`。
- 优化源码 SHA-256：`327c9e652f14d7673ae8123c817964bd05b3e9a68579620c567959c85b92e395`。
- 原始基线：[gas-baseline-v2.json](../test/fixtures/gas-baseline-v2.json)。
- 优化后证据：[gas-optimized-v2-2026-09-03.json](./evidence/gas-optimized-v2-2026-09-03.json)。
- 前后规范化 ABI SHA-256 均为
  `71c059af9ac0a4aed6517634e7618a830e82d69fe9268c0835df29dc21f3ae2e`。

使用兼容 Node 22，在 `vrf` 目录执行：

```bash
npx hardhat --config hardhat.config.js test test/GasBenchmark.test.cjs
npx hardhat --config hardhat.config.js test
```

专用 gas 测试使用独立本地模拟网络，不连接主网、不签真实交易。测试必须有完整基线，
并检查请求 gas 至少降低 25%、两笔合计至少降低 80,000 gas、用户支出下降、ABI 不变、
proof 输入相同和 runtime 大小。不要为绕过失败而直接更新基线。

新增安全回归覆盖：连续轮换及停用仍用旧费率/旧 lane/旧 payee；不同 key 与 verifier
配置隔离、拒绝跨 key proof；清理后共享版本仍可履约；打包字段上界、uint256 reserve
不截断、block 溢出回滚且 nonce/预留不变。原有收费/nonce/配额/回调/threshold 测试保留。

## 上线与下一阶段

这是不可升级 Coordinator 的新存储布局，只适用于**新部署**。不得把“ABI 兼容”解释成
可在已有状态上原位升级。线上采用前需另行授权：新地址部署、源码验证、manifest/codehash
更新、Consumer/订阅切换方案，以及旧 Coordinator 的 pending 清空和余额处理。

下一轮优先做同一业务 Consumer 的测试网回归与真实 overhead 校准。固定 overhead 同时影响
保留的回调后 gas 安全预算，不能仅按均值调低。更激进的 commitment-only Request、批量请求
或复用槽位会改变 Operator 输入/生命周期，需要单独设计与审计，不包含在本轮。
