# Threshold group manifest 与聚合输入

> Historical technical document. Current release status and standalone integration instructions: [STATUS.md](STATUS.md) and [QUICKSTART.md](QUICKSTART.md). Example infrastructure settings are not live configuration.

## 安全边界

这些文件只包含公开信息和 partial signatures，绝不能包含 secret share、DKG transport 私钥或身份
私钥。validator 能证明公开 share key 与最终 polynomial commitments 一致、参与方对同一份 roster
达成阈值签名，以及聚合签名匹配 group public key；它不能代替 DKG complaint/resolution，也不能证明
某次 ceremony 没有在别处泄露 secret share。

## Group manifest v1

`format` 固定为 `robinhood-proof-vrf-threshold-group/v1`，`scheme` 固定为
`THRESHOLD_BLS_UNIQUE_SIGNATURE_V1`。所有字段都是必需字段：

| 字段 | 约束 |
| --- | --- |
| `network`, `chainId`, `verifierAdapter` | 绑定目标链和已部署 adapter |
| `ceremony` | 初始组为 `dkg`，成员变更为 `reshare` |
| `previousManifestHash` | 初始组为 `null`；reshare 为上一 epoch 的 canonical hash |
| `epoch` | 初始 DKG 必须是 1；reshare 必须严格加 1 |
| `threshold` | 至少 2、不得超过成员数、必须严格大于成员数一半 |
| `groupPublicKey` | 192-byte uncompressed BLS12-381 G2 point |
| `publicCoefficients` | 长度必须等于 threshold；第 0 项必须等于 group key，最高次项不得为零 |
| `keyHash` | 必须等于 adapter 的 scheme/group-key commitment |
| `dkgTranscriptHash` | 完整 ceremony transcript 的 32-byte hash |
| `softwareCommit`, `containerDigest` | 固定 40/64 hex commit 和 `sha256:` image digest |
| `participants` | 按 1 起连续 index 排序的 roster |
| `attestations` | 新 roster 至少 threshold 个 Ed25519 identity signatures |
| `handoffAttestations` | 初始 DKG 必须为空；reshare 为旧 roster 至少旧 threshold 个签名 |

每个 participant 固定包含：`id`、`index`、32-byte Ed25519 `identityPublicKey`、32-byte DKG
`transportPublicKey`、192-byte G2 `sharePublicKey` 和 HTTPS `endpoint`。ID、所有公钥和 endpoint 均须
唯一。validator 根据 `publicCoefficients` 重新计算每个 index 的 G2 share public key。

Canonical manifest hash 是对规范化、按 key 排序的 JSON body 做 `keccak256`；`attestations` 和
`handoffAttestations` 不进入 body。签名算法为 Ed25519，签名内容是原始 32-byte manifest hash。

```bash
npm run threshold:group -- \
  validate --file /secure/public/group-epoch-1.json
```

Resharing 不能只相信新文件自报的 `previousManifestHash`。调用者必须另外提供当前已可信的旧 hash：

```bash
npm run threshold:group -- \
  validate \
  --file /secure/public/group-epoch-2.json \
  --previous /secure/public/group-epoch-1.json \
  --trusted-previous-hash 0x...
```

validator 强制 scheme、network、chain、adapter、group public key 和 keyHash 不变。更换 group key 是
key rotation，必须登记新 keyHash，不能伪装成 resharing。

## Share set 与聚合输出

Aggregator 输入只允许三个顶层字段：

```json
{
  "manifestHash": "0x...32 bytes...",
  "message": "0x...32 bytes...",
  "shares": [
    {
      "participantId": "operator-1",
      "index": 1,
      "signature": "0x...96-byte uncompressed G1 point..."
    }
  ]
}
```

`participantId/index` 必须匹配 manifest；每个 partial 都先对该 participant 的 share public key 验证，
重复 index 会被拒绝。达到阈值后执行零点 Lagrange interpolation，再对 group public key 验证最终签名。

```bash
npm run threshold:group -- \
  aggregate \
  --manifest /secure/public/group-epoch-1.json \
  --shares /secure/public/request-shares.json
```

输出包含 `signature`、adapter 可直接解码的 ABI `proofData`、使用的 share indexes、manifest hash 和
keyHash。当前命令不会广播交易；生产 relayer 接入前还必须针对目标 request 执行 coordinator
`requestSeed` 重算、confirmation/blockhash 校验和链上 `eth_call`。
