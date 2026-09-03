# Robinhood Testnet 部署清单

> Historical technical document. Current release status and standalone integration instructions: [STATUS.md](STATUS.md) and [QUICKSTART.md](QUICKSTART.md). Example infrastructure settings are not live configuration.

这是一份可执行 gate，不是已部署声明。仓库不会生成 Safe、真实角色地址、RPC 订阅、服务器凭据或
测试资金，也不会把缺失的第三方审计标成通过。

## 1. 冻结构建

使用 `.nvmrc` 的 Node 22，要求 Git worktree clean；公共部署脚本会记录 `git rev-parse HEAD` 并在
dirty 状态下拒绝运行。

```bash
npm ci
npm test
npm run test:coverage
npm run test:robinhood-fork
npm audit --workspace vrf --audit-level=high
```

## 2. 角色

准备四个互不相同的权限域：

- Governance Safe：拥有 `VRFAdminTimelock`；
- Guardian：只能暂停新请求；
- Fulfiller：Operator gas relayer；
- Payee：Operator 收款账户。

先部署 Timelock，推荐 24 小时：

```bash
VRF_GOVERNANCE_MULTISIG=0x... \
VRF_TIMELOCK_DELAY_SECONDS=86400 \
VRF_TIMELOCK_MANIFEST=/secure/timelock.json \
npm run deploy:timelock:testnet
```

## 3. 单 Operator ECVRF 基线

离线创建 proof key；部署钱包、proof key、Fulfiller 和 Payee 不能共用。部署时明确设置真实 gas lane
和初始 reserve，不使用示例值：

```bash
VRF_OWNER=0x<TIMELOCK> \
VRF_TIMELOCK_MANIFEST=/secure/timelock.json \
VRF_GUARDIAN=0x... VRF_FULFILLER=0x... VRF_PAYEE=0x... \
VRF_PUBLIC_KEY_X=... VRF_PUBLIC_KEY_Y=... \
VRF_MAX_GAS_PRICE_WEI=... \
VRF_MINIMUM_REQUEST_FEE_WEI=... VRF_L1_FEE_RESERVE_WEI=... \
VRF_DEPLOYMENT_MANIFEST=/secure/deployment.json \
npm run deploy:service:testnet
```

每个合约部署后立即 checkpoint 地址、transaction、block 和 runtime codehash。Coordinator 构造函数
直接把已验证的 Timelock 设为 owner，并在同一笔部署交易中注册首个 proof key。部署清单状态必须为
`deployed`、`ownershipStatus == timelock-is-owner-at-deployment`、
`keyRegistrationMode == constructor-atomic`；同时确认链上 `owner == Timelock`、`pendingOwner == 0`
且首个 key active 后再继续。`prepare-accept-ownership.mjs` 只保留给旧部署或迁移场景使用。

## 4. 源码、字节码与角色验证

先在 Robinhood Blockscout 验证全部五个合约。创建不含密钥的 JSON；这里必须使用返回结构化 JSON 的
Blockscout API，普通 `#code` HTML 页面不会被当作验证证据：

```json
{
  "blockContext": "https://explorer.testnet.chain.robinhood.com/api?module=contract&action=getsourcecode&address=0x...",
  "blockhashStore": "https://explorer.testnet.chain.robinhood.com/api?module=contract&action=getsourcecode&address=0x...",
  "l1FeeCalculator": "https://explorer.testnet.chain.robinhood.com/api?module=contract&action=getsourcecode&address=0x...",
  "verifier": "https://explorer.testnet.chain.robinhood.com/api?module=contract&action=getsourcecode&address=0x...",
  "coordinator": "https://explorer.testnet.chain.robinhood.com/api?module=contract&action=getsourcecode&address=0x..."
}
```

运行：

```bash
npm run deployment:verify -- \
  --rpc-url https://rpc-a.example \
  --manifest /secure/deployment.json \
  --source-verification-file /secure/source-urls.json \
  --out /secure/deployment-verification.json
```

只有 runtime codehash、ArbSys L2 context、L1 calculator pin、Timelock/Safe、ownership、四角色、key
配置和所有 source URL 同时通过，报告才为 `pass`。

## 5. 单实例、双 RPC、PostgreSQL

把 `deploy/operator.conf.example` 的 placeholder 换成两个运营上独立的 RPC。Readiness 还要求
PostgreSQL 14+、TLS、key/Fulfiller、relayer 余额和依赖 codehash。先只启用一台
`proof-vrf-operator.service`；第二实例只能在共享 session-lock PostgreSQL 后启用。

CI 的 PostgreSQL 16 service 会执行 advisory-lock 排他、broadcast replacement journal 和子进程
`SIGKILL` 自动释放锁测试；目标数据库仍需单独做 failover 演练。

## 6. 内部无价值 canary 与 smoke

`canary:start:testnet` 硬限制 chain 46630，部署示例 Consumer、创建/充值 Subscription、授权并发起
一个 request；这里的“无价值”指没有生产用户、奖池或不可逆业务状态，不表示 gas 免费。

```bash
VRF_DEPLOYMENT_MANIFEST=/secure/deployment.json \
VRF_DEPLOYMENT_VERIFICATION_REPORT=/secure/deployment-verification.json \
VRF_CANARY_MANIFEST=/secure/canary.json \
npm run canary:start:testnet
```

Operator 履约后运行 `smoke:report`。报告必须证明双 RPC 一致、callback 成功且 proof/settlement 各一
次。未通过 smoke 不开始 soak 计时。

## 7. 校准、30 天 soak 与外部开放

至少 100 笔 settlement 后运行 `calibrate`，据 P99 gas/L1 数据提出新参数并经 Timelock 生效。随后从
最终参数生效且 smoke 通过的区块开始连续 30 天运行 `soak:report`；报告强制绑定部署验证、smoke 与
两个独立 HTTPS RPC，至少覆盖 RPC split、reorg、gas spike、callback
OOG、PostgreSQL failover、prover outage 与 relayer replacement。

30 天报告、故障演练、第三方 Solidity/Operator 审计及修复复审没有全部通过前：不公开收费、不接入
高价值业务。Threshold 使用独立的 [DKG_RUNBOOK.md](./DKG_RUNBOOK.md) 在 shadow 环境执行，并额外
要求密码学专项审计与第二实现互操作。
