# Robinhood 随机数服务对照

> Historical technical document. Current release status and standalone integration instructions: [STATUS.md](STATUS.md) and [QUICKSTART.md](QUICKSTART.md). Example infrastructure settings are not live configuration.

更新：2026-09-02。以下是设计对照，不代表对其他项目的审计或背书。

| 维度 | 本项目 Proof VRF | Dice Entropy | Quiver | drand |
| --- | --- | --- | --- | --- |
| 完成结果的可验证性 | 链上 ECVRF 或 threshold-BLS proof | 链上 hash-chain reveal | 链上双边 commit/reveal | BLS threshold signature |
| 单方可用性风险 | 单 ECVRF 可 withholding；threshold 允许少数节点离线 | Provider 可 withholding，超时退款 | Provider/keeper 可 withholding，提供 retry/pull | 少于阈值在线则停止 |
| 请求输入 | Consumer、Subscription、nonce、L2 request block hash | 用户贡献 + provider hash-chain reveal | 用户贡献 + provider reveal，可纳入 blockhash | 固定轮次消息 |
| 收费 | Subscription 预付、实际 gas/L1 结算、Sponsor 白名单 | 当前公开说明为固定每请求费 | Provider fee，接入方应实时读取 | Beacon 本身不是本链按请求收费模型 |
| Callback | proof 先落盘，失败可 permissionless retry | reveal 交易中 callback | 状态先推进、失败缓冲并可 retry | 通常由应用拉取和验证 |
| 去中心化路径 | 3-of-5 DKG/resharing，当前实验性 | 当前公开说明为单 provider | 当前公开说明为 provider + keeper | 多组织 threshold network |

从 Dice/Quiver 采用的工程原则：不可因 callback 失败丢失随机结果、明确超时/退款、SDK/Consumer
边界、公开 provider/keeper 状态。没有照搬它们的 commit-reveal：本项目的主目标是 proof-based VRF，
最终输出必须由 verifier 验证，不能只依赖 Coordinator 地址认证。

从 Chainlink 采用的安全原则：requestId 必须绑定业务状态、确认数与价值风险相关、请求后不得取消或
重抽、应用在请求后不得继续接收影响结果的输入。本 Coordinator 因此固定 pending request 的 verifier、
key、Fulfiller、定价和 L2 request block，并禁止 redraw。

从 drand 采用的 threshold 原则：节点独立持有 share、达到阈值才可签名、最终 BLS 签名与所选合法
share 子集无关、委员会变更通过保持 group key 的 resharing 完成。仓库内实现不是 drand 代码，也没有
继承 drand 的审计结论；正式收费前仍需独立密码学审计和第二实现互操作。

来源：

- https://github.com/diceprotocol/dice-entropy
- https://quiver.foundation/
- https://github.com/camdengrieh/quiver-kit
- https://github.com/drand/drand
- https://docs.chain.link/vrf/v2-5/security
