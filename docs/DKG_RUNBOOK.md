# Threshold DKG 与 resharing 运行手册

> Historical technical document. Current release status and standalone integration instructions: [STATUS.md](STATUS.md) and [QUICKSTART.md](QUICKSTART.md). Example infrastructure settings are not live configuration.

## 使用边界

`operator/threshold-dkg.mjs` 是可执行的 Feldman-VSS DKG/resharing ceremony 工具：每个节点本地生成
Ed25519 identity key 与 X25519 transport key；每个 dealer 独立生成多项式，向每个 participant 发送
AES-256-GCM 加密 share；所有 deal、response、complaint resolution 和 finalization 都带身份签名并进入
统一 transcript。任何节点都不会构造完整 group secret。

这套实现目前只允许 testnet/shadow。它尚未经第三方密码学审计，也没有与第二套 DKG 实现完成
transcript 互操作，不能用于主网价值请求。

## Ceremony 前冻结

五家 Operator 通过带外签名文档冻结：`sessionId`、epoch、3-of-5 threshold、按 index 排序的 roster、
Robinhood chain ID、已部署的 `ThresholdBLSVerifierAdapter`、Git commit、容器 digest、时间窗口及
append-only bulletin board。所有参与方必须读取同一份完整 packet 集；私聊中出现但未进入 bulletin
board 的 packet 一律无效。

先部署并验证真实 backend/adapter：

```bash
VRF_THRESHOLD_VERIFIER_MANIFEST=/secure/threshold-verifier.json \
npm run deploy:threshold-verifier:testnet
```

脚本会用动态 RFC 9380 签名向量执行 EIP-2537 hash-to-curve、pairing 和 subgroup 互操作探测；失败则
终止部署流程。部署 manifest 的 adapter 地址必须进入 roster ceremony 参数。

部署后先为 `backend` 和 `adapter` 提交 Blockscout 源码验证，再生成独立验证报告。源码 URL 必须是
地址绑定的 Blockscout v1 `getsourcecode` 或 v2 `smart-contracts/{address}` JSON API：

```bash
npm run threshold:deployment:verify -- \
  --rpc-url https://rpc-a.example \
  --manifest /secure/threshold-verifier.json \
  --source-verification-file /secure/threshold-source-urls.json \
  --out /secure/threshold-verifier-verification.json
```

## 初始 3-of-5 DKG

每家 Operator 在自己的主机执行，密码只通过 `VRF_THRESHOLD_KEY_PASSWORD_FILE` 或交互式 secret
管理注入；以下以 Operator 1 为例：

```bash
npm run threshold:dkg -- identity \
  --id operator-1 \
  --endpoint https://operator-1.example \
  --out /secure/operator-1.threshold-keystore.json \
  --descriptor /board/operator-1.participant.json
```

协调方把五份公开 descriptor 合并成 `roster.json`，按 1..5 设置连续 index。每家分别生成 deal；
`dealer-state` 只留在 dealer 主机，不能上传 bulletin board：

```bash
npm run threshold:dkg -- deal \
  --ceremony dkg --session 0x<32-byte-session> --epoch 1 --threshold 3 \
  --roster /board/roster.json \
  --keystore /secure/operator-1.threshold-keystore.json \
  --out /board/deal-1.json \
  --state-out /secure/dealer-state-1.dkg-state.json
```

协调方把所有有效 deal 原样组成 `deals.json`。每家独立解密并验证自己的所有 share，输出一份签名
response：

```bash
npm run threshold:dkg -- respond \
  --ceremony dkg --session 0x<32-byte-session> --epoch 1 --threshold 3 \
  --roster /board/roster.json --deals /board/deals.json \
  --keystore /secure/operator-1.threshold-keystore.json \
  --out /board/response-1.json
```

如有 complaint，dealer 只能为经过身份签名的投诉公开对应 share；达到 threshold 数量的投诉时工具
拒绝继续公开，dealer 被淘汰并重启 ceremony，避免公开足够份额恢复 dealer 多项式：

```bash
npm run threshold:dkg -- resolve \
  --ceremony dkg --roster /board/roster.json \
  --keystore /secure/operator-1.threshold-keystore.json \
  --state /secure/dealer-state-1.dkg-state.json \
  --deal /board/deal-1.json --responses /board/responses.json \
  --out /board/resolution-1.json
```

所有节点在相同 deals/responses/resolutions 上 finalize；输出的新 keystore 仍为加密文件：

```bash
npm run threshold:dkg -- finalize \
  --ceremony dkg --session 0x<32-byte-session> --epoch 1 --threshold 3 \
  --roster /board/roster.json --deals /board/deals.json \
  --responses /board/responses.json --resolutions /board/resolutions.json \
  --keystore /secure/operator-1.threshold-keystore.json \
  --out /board/finalization-1.json \
  --keystore-out /secure/operator-1-final.threshold-keystore.json \
  --transcript-out /board/transcript-1.json
```

五份 finalization 必须逐字段一致并完整覆盖 roster。assemble 不读取密码：

```bash
npm run threshold:dkg -- assemble \
  --finalizations /board/finalizations.json --roster /board/roster.json \
  --network robinhood-testnet --chain-id 46630 \
  --verifier-adapter 0x... --software-commit <40-hex> \
  --container-digest sha256:<64-hex> --out /board/group.json
```

每家分别执行 `attest`，至少三份 attestation 加入 group manifest；然后用外部渠道确认
`manifestHash`，最后绑定自己的 share：

```bash
npm run threshold:dkg -- bind \
  --manifest /board/group.json --manifest-hash 0x... \
  --keystore /secure/operator-1-final.threshold-keystore.json \
  --out /secure/operator-1-bound.threshold-share.json
```

`bind` 会同时核对 identity key、transport key、secret share 对应的公开 share 和外部可信 manifest
hash，不能把错误 share 绑定到组。

## Resharing

新 roster 可改变成员与 index，但 group public key 和 `keyHash` 必须保持不变。先从旧 manifest 中按
原 roster 顺序冻结至少旧 threshold 数量的 selected dealers，例如：

```text
--ceremony reshare --epoch 2
--previous /board/group-epoch-1.json
--previous-manifest-hash 0x<trusted-hash>
--selected-dealers operator-1,operator-2,operator-3
```

上述参数附加到 `deal`、`respond` 和 `finalize`；dealer roster 来自旧 manifest，recipient roster 是新
roster。每个旧 dealer 的常数项乘零点 Lagrange 系数，所有预选 dealer 都必须 qualified，否则本次
resharing 整体中止。新 manifest 还必须包含：新委员会达到新 threshold 的 identity attestations，
以及旧委员会达到旧 threshold 的 handoff attestations。

## 在线节点

每个独立 Operator 启动一个 threshold node：

```bash
VRF_RPC_URLS='https://rpc-a.example,https://rpc-b.example' \
npm run threshold:node -- \
  --manifest /etc/proof-vrf/group.json \
  --keystore /secure/operator-1-bound.threshold-share.json \
  --coordinator 0x... \
  --state /var/lib/proof-vrf/signing-state.json \
  --audit-log /var/lib/proof-vrf/signing-audit.jsonl \
  --host 0.0.0.0 --port 9443 \
  --tls-key /secure/server.key --tls-cert /secure/server.crt --tls-ca /secure/client-ca.crt
```

节点只接受 `requestId`，从两个独立 RPC 自行读取 pending request、confirmation 后的 `requestSeed`
和 adapter message。它持久化 anti-equivocation state，拒绝同一 requestId 的不同 message，并写入
fsync 的 hash-chained JSONL audit log。Aggregator 用 mTLS 收集达到 threshold 的响应，验证 Ed25519
身份签名和 BLS share 后聚合；交易前的 gas estimate 会再次执行链上 adapter/backend 验证。

## 登记 gate

用 `threshold:prepare-register` 生成 Safe 调用数据。它只读链，不发送交易，并检查 verifier 部署
codehash、backend pin、动态 BLS probe、源码、group attestations、adapter/keyHash、Coordinator 部署
报告和 Timelock/Safe ownership：

```bash
npm run threshold:prepare-register -- \
  --rpc-url https://rpc-a.example --coordinator 0x... --timelock 0x... \
  --manifest /board/group.json --verifier-manifest /secure/threshold-verifier.json \
  --verifier-verification-report /secure/threshold-verifier-verification.json \
  --coordinator-verification-report /secure/deployment-verification.json \
  --fulfiller 0x... --payee 0x... --max-gas-price-wei 20000000000 \
  --verification-gas-limit 2900000
```

先在 shadow 环境完成固定消息互操作、恶意 dealer、节点离线、RPC split、进程 SIGKILL 和完整
resharing 演练。密码学审计与第二实现不通过时，不执行正式收费 key 登记。
