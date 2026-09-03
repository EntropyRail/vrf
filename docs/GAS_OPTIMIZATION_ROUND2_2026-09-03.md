# V2 第二轮 gas 优化：固定费率版本与派生字段

> Historical technical document. Current release status and standalone integration instructions: [STATUS.md](STATUS.md) and [QUICKSTART.md](QUICKSTART.md). Example infrastructure settings are not live configuration.

状态：**仅本地实现和测试，未部署、未改线上费率或服务、未改密钥/CI/CD、未提交 Git**。
这是新部署候选代码，不可直接覆盖现有 Coordinator 的存储布局。

## 结果

在完全相同证明、请求 ID、调用顺序、Consumer 和 gas 参数下，普通单随机数常规请求：

| 指标 | 最初版本 | 第一轮 | 第二轮（当前） | 第二轮相对第一轮 |
| --- | ---: | ---: | ---: | ---: |
| 请求 gas | 381,754 | 245,362 | 202,424 | 降 17.5% |
| 履约 gas | 176,685 | 171,756 | 173,794 | 增 1.2% |
| 两笔总 gas | 558,439 | 417,118 | 376,218 | **降 9.8%** |
| 调用方支出，ETH（本地 1 gwei、零 L1 费） | 0.0007009924 | 0.0005588056 | 0.0005192804 | **降 7.1%** |

相对最初版本，累计请求 gas 降 **47.0%**、两笔总 gas 降 **32.6%**、调用方支出降 **25.9%**。
不是所有路径都变便宜：对固定历史配置重新计算会增加一些读取和计算，见后面的生命周期成本。
20% premium、150,000 overhead 以及执行上限在基准里都没有调低。

这些是本地对照，不是新部署后的 Robinhood 实测。不代表已通过主网准入或独立审计。

## 做了什么

每请求 `StoredRequest` 从第一轮 7 slots 减至 **5 slots**，正常 pending 请求有 4 个非零槽位。

1. 新增只追加的 `PricingConfig` 版本。构造或 `setPricing` 时生成新版本；请求保存当时的版本号。
2. 不再单独保存每请求的 `reservedPayment`：从固定的 key/费率版本、callbackGasLimit、numWords、
   premiumBps 和 waiveMinimumFee 精确复算。**Subscription 的实际 reservation 仍照常记账、锁定**，
   不是取消预留，也不是按新费率重算。
3. 不再单独保存 `expiresAtBlock`：使用原 requestBlock + 原费率版本中的 requestTimeoutBlocks。
   创建时的 uint64 上界检查、确认窗口、过期与 prune 边界不变。
4. 把状态、小字段和两个 uint64 放在紧凑布局中；随机词展开使用内存值和纯函数，避免重复验证状态。

紧凑存储仍需对照真实 gas 测试，而非仅数变量：打包字段会带来读改写成本。
[Solidity 存储布局说明](https://docs.soliditylang.org/en/v0.8.24/internals/layout_in_storage.html)

没有更改 proof scheme、随机输入/输出、确认数策略、blockhash/code-hash 校验、授权、白名单、
费用上限、防重入或失败回调重试。公开 ABI 与两份基线一致；没有改变请求/证明 calldata。

### 必须保留的不变量

- 历史 key 和 pricing 版本不得修改、删除或重用。版本 uint64 checked increment，溢出整笔回滚。
- `_quotePayment` 同时用于请求报价和固定请求的复算，使用完全相同的整数向下取整与最低费规则。
- 复算只能使用历史版本与不可变请求字段，不能读取当前 gas price、当前 Sponsor/override 或当前 pricing。
- quote 的 floor、premium、perWordGas、L1 reserve 和 key lane 在创建后都不受后续修改影响。
- `getRequest` 在 pending、fulfilled、expired 时都返回原 reserve；settle/expire 释放恰好同一金额。
- 余额只扣一次 charge；expire 不扣服务费；retry 不产生第二笔 charge。
- 清理单个 request 不删除 key/费率版本，以免影响其他请求。

## 生命周期代价与非典型场景

| 场景 | 第一轮 gas | 第二轮 gas |
| --- | ---: | ---: |
| 公共单词首次请求＋履约 | 527,546 | 486,646 |
| 公共 3 词请求＋履约 | 481,302 | 440,408 |
| 公共 32 词请求＋履约 | 1,098,743 | 1,057,937 |
| Sponsor 单词常规请求＋履约 | 427,989 | 387,194 |
| 首次回调失败，请求＋履约（不含重试） | 483,037 | 442,134 |
| 额外 retry | 87,521 | 89,481 |
| 过期释放 reservation | 54,562 | 60,905 |
| prune | 55,424 | 49,334 |
| getRequest（eth_call 执行 gas 估算，不是额外用户交易） | 50,737 | 52,786 |
| setPricing（相同参数测试） | 34,143 | 84,632 |
| setKeyService（相同参数测试） | 162,874 | 162,904 |
| Coordinator 单体部署 | 4,761,279 | 4,894,132 |

适合“请求高频、配置低频”的服务。频繁改价会抵消一部分收益；不能只展示请求减少的 gas
而忽略履约和配置成本。runtime 19,966 bytes，仍小于 EIP-170 的 24,576-byte 限制。
部署费用仅为单体比较，不包含其他合约、订阅切换、充值或服务器成本。

## 主网费用外推

仍沿用前一轮 2026-09-03 01:05–01:06（UTC+8）采样的 0.405268–0.419482 gwei，
未重新采样主网。假设本地执行差额可迁移且 L1 posting 费用保持原先量级：

- 自用真实网络总成本约 **0.000153–0.000159 ETH/次**。
- 外部调用方请求 gas + 服务扣费约 **0.000211–0.000219 ETH/次**。

相对最初 receipt-based 模型，分别扣除 179,330 request gas、2,891 fulfillment gas；
计费公式的 measured gas 只减少 1,985，不能误用 receipt gas 差额计算用户扣费。
此前第一轮外部估计约 0.000227–0.000235 ETH。本轮不是固定报价，也未验证比 Dice/Quiver 更便宜。
不含部署、配置、充值、提现、归档、失败重试、服务器/RPC/审计成本；仍需测试网与主网 fork 校准。

## 验证与证据

完整本地运行 **83 passing**（Hardhat 汇总），PostgreSQL 外部数据库和 Robinhood fork 本轮未启用。
原有 ECVRF、BLS、DKG/resharing、nonce、RPC、Sponsor 和会计不变量测试保留。

新加测试包括：

- 12 笔混合普通/Sponsor 请求，逐笔更改全部 fee 参数、premium override、Sponsor policy 和 key service。
- 独立 JS 整数公式核对每笔 quote、事件 reserve、getRequest reserve 和 expiry。
- 乱序履约一半请求、乱序过期另一半；每一步核对余额、预留、Operator/Treasury 负债与 pending 数。
- 修改当前 timeout 为更短或更长后，原请求精确边界（到期当块、下一块、prune 当块与下一块）不变。
- 保留 uint64/uint96 上界、超过 uint96 的 reserve、伪造 proof、跨 key、防重入和回调失败回归。

gas 测试同时保留最初与第一轮基线，不覆盖旧结果。第二轮每个基准场景要求请求与总 gas
至少比第一轮再低 30,000，并对履约、退款、重试、读取、配置与部署的额外开销设上限。
缺少任一基线会失败；禁止为隐藏回归直接重写基线。

- [第一轮扩展基线](../test/fixtures/gas-baseline-v2-round1.json)
- [第二轮原始结果](./evidence/gas-optimized-v2-round2-2026-09-03.json)
- [第一轮历史报告](./GAS_OPTIMIZATION_2026-09-03.md)
- 当前 Coordinator SHA-256：`73fad3a6e91983f46f7e317392a426a84474c1b980a9e5005f1fb85fb9dde3e9`。
- 规范化 ABI SHA-256：`71c059af9ac0a4aed6517634e7618a830e82d69fe9268c0835df29dc21f3ae2e`，三版一致。

Node 22.13+，在 `vrf` 目录：

```bash
npx hardhat --config hardhat.config.js test test/GasBenchmark.test.cjs
npx hardhat --config hardhat.config.js test
```

后续若要更大幅度降本，需要评估业务允许的批量随机数、commitment-only 请求或更精简的
Consumer/Operator 接口。这些会改变成本口径、接口或业务时序，需要单独设计，不能无条件套用。
不要把降低 overhead 的服务扣费变化宣传成底层网络 gas 节省。
