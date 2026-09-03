const assert = require("node:assert/strict");
const { generateKeyPairSync, sign } = require("node:crypto");
const { mkdtempSync, readFileSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");
const { describe, it } = require("node:test");

function hex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

describe("threshold BLS share aggregation", function () {
  it("verifies shares and produces the same unique signature from different 3-of-5 subsets", async function () {
    const { bls12_381: bls } = await import("@noble/curves/bls12-381");
    const tools = await import("../operator/threshold-crypto.mjs");
    const message = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
    const coefficients = [123456789n, 99887766n, 44556677n];
    const scalarAt = (index) => coefficients.reduceRight(
      (value, coefficient) => (value * BigInt(index) + coefficient) % tools.BLS_SCALAR_ORDER,
      0n,
    );
    const messagePoint = bls.G1.hashToCurve(message, { DST: tools.BLS_DST });
    const groupPublicKey = hex(
      bls.G2.ProjectivePoint.BASE.multiply(coefficients[0]).toRawBytes(false),
    );
    const shares = [1, 2, 3, 4, 5].map((index) => {
      const scalar = scalarAt(index);
      return {
        index,
        publicKey: hex(bls.G2.ProjectivePoint.BASE.multiply(scalar).toRawBytes(false)),
        signature: hex(messagePoint.multiply(scalar).toRawBytes(false)),
      };
    });

    const first = tools.aggregateThresholdShares({
      message,
      groupPublicKey,
      threshold: 3,
      shares: [shares[0], shares[1], shares[2]],
    });
    const second = tools.aggregateThresholdShares({
      message,
      groupPublicKey,
      threshold: 3,
      shares: [shares[1], shares[3], shares[4]],
    });
    assert.equal(first.signature, second.signature);
    assert.equal(tools.verifyAggregateSignature({
      message,
      groupPublicKey,
      signature: first.signature,
    }), true);
  });

  it("rejects duplicate indexes and a forged partial signature", async function () {
    const { bls12_381: bls } = await import("@noble/curves/bls12-381");
    const tools = await import("../operator/threshold-crypto.mjs");
    const message = new Uint8Array(32).fill(7);
    const messagePoint = bls.G1.hashToCurve(message, { DST: tools.BLS_DST });
    const share = (index, scalar) => ({
      index,
      publicKey: hex(bls.G2.ProjectivePoint.BASE.multiply(scalar).toRawBytes(false)),
      signature: hex(messagePoint.multiply(scalar).toRawBytes(false)),
    });
    const shares = [share(1, 11n), share(2, 12n), share(3, 13n)];
    assert.throws(() => tools.aggregateThresholdShares({
      message,
      groupPublicKey: shares[0].publicKey,
      threshold: 3,
      shares: [shares[0], { ...shares[1], index: 1 }, shares[2]],
    }), /indexes must be unique/);
    assert.throws(() => tools.aggregateThresholdShares({
      message,
      groupPublicKey: shares[0].publicKey,
      threshold: 3,
      shares: [shares[0], { ...shares[1], signature: shares[0].signature }, shares[2]],
    }), /failed verification/);
  });
});

describe("threshold signer audit chain", function () {
  it("recovers its durable audit head and rejects a tampered record", async function () {
    const nodeTools = await import("../operator/threshold-node.mjs");
    const directory = mkdtempSync(join(tmpdir(), "proof-vrf-audit-"));
    const auditPath = join(directory, "audit.jsonl");
    const statePath = join(directory, "state.json");
    const message = `0x${"12".repeat(32)}`;
    const state = {
      format: "robinhood-proof-vrf-threshold-signing-state/v1",
      manifestHash: `0x${"34".repeat(32)}`,
      signedRequests: { "7": message },
      auditedRequests: {},
      auditHead: `0x${"00".repeat(32)}`,
    };
    nodeTools.internals.appendAuditRecord(auditPath, state, {
      format: "robinhood-proof-vrf-threshold-audit/v1",
      signedAt: "2026-09-02T00:00:00.000Z",
      participantId: "operator-1",
      manifestHash: state.manifestHash,
      keyHash: `0x${"56".repeat(32)}`,
      requestId: "7",
      message,
      signature: `0x${"78".repeat(96)}`,
      identitySignature: `0x${"9a".repeat(64)}`,
    });
    writeFileSync(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    const recovered = { ...state, auditedRequests: {}, auditHead: `0x${"00".repeat(32)}` };
    nodeTools.internals.loadAuditLog(auditPath, recovered, statePath);
    assert.equal(recovered.auditHead, state.auditHead);

    const record = JSON.parse(readFileSync(auditPath, "utf8"));
    record.message = `0x${"ff".repeat(32)}`;
    writeFileSync(auditPath, `${JSON.stringify(record)}\n`, { mode: 0o600 });
    assert.throws(() => nodeTools.internals.loadAuditLog(
      auditPath,
      recovered,
      statePath,
    ), /event hash is invalid/);
  });
});

describe("threshold group manifest", function () {
  it("binds the roster, DKG transcript, deployment and threshold identity attestations", async function () {
    const { bls12_381: bls } = await import("@noble/curves/bls12-381");
    const groupTools = await import("../operator/threshold-group.mjs");
    const keys = Array.from({ length: 5 }, () => generateKeyPairSync("ed25519"));
    const rawPublicKey = (key) => hex(
      key.export({ format: "der", type: "spki" }).subarray(-32),
    );
    const polynomial = [123n, 5n, 7n];
    const scalarAt = (index) => polynomial.reduceRight(
      (value, coefficient) => value * BigInt(index) + coefficient,
      0n,
    );
    const participants = keys.map(({ publicKey }, position) => ({
      id: `operator-${position + 1}`,
      index: position + 1,
      identityPublicKey: rawPublicKey(publicKey),
      transportPublicKey: hex(Buffer.alloc(32, position + 1)),
      sharePublicKey: hex(
        bls.G2.ProjectivePoint.BASE.multiply(scalarAt(position + 1)).toRawBytes(false),
      ),
      endpoint: `https://operator-${position + 1}.example`,
    }));
    const publicCoefficients = polynomial.map((coefficient) => hex(
      bls.G2.ProjectivePoint.BASE.multiply(coefficient).toRawBytes(false),
    ));
    const groupPublicKey = publicCoefficients[0];
    const manifest = {
      format: groupTools.GROUP_FORMAT,
      scheme: groupTools.BLS_SCHEME,
      network: "robinhood-testnet",
      chainId: 46630,
      verifierAdapter: "0x1111111111111111111111111111111111111111",
      ceremony: "dkg",
      previousManifestHash: null,
      epoch: 1,
      threshold: 3,
      groupPublicKey,
      publicCoefficients,
      keyHash: groupTools.adapterKeyHash(groupPublicKey),
      dkgTranscriptHash: hex(Buffer.alloc(32, 0xa1)),
      softwareCommit: "a".repeat(40),
      containerDigest: `sha256:${"b".repeat(64)}`,
      participants,
      attestations: [],
      handoffAttestations: [],
    };
    const prepared = groupTools.prepareGroupManifest(manifest);
    manifest.attestations = keys.slice(0, 3).map(({ privateKey }, position) => ({
      participantId: participants[position].id,
      signature: hex(sign(null, Buffer.from(prepared.manifestHash.slice(2), "hex"), privateKey)),
    }));
    const validated = groupTools.validateGroupManifest(manifest);
    assert.equal(validated.manifestHash, prepared.manifestHash);
    assert.deepEqual(validated.validAttesters, ["operator-1", "operator-2", "operator-3"]);

    const tampered = structuredClone(manifest);
    tampered.dkgTranscriptHash = hex(Buffer.alloc(32, 0xa2));
    assert.throws(() => groupTools.validateGroupManifest(tampered), /invalid identity attestation/);

    const nextKeys = Array.from({ length: 5 }, () => generateKeyPairSync("ed25519"));
    const nextPolynomial = [123n, 17n, 19n];
    const nextScalarAt = (index) => nextPolynomial.reduceRight(
      (value, coefficient) => value * BigInt(index) + coefficient,
      0n,
    );
    const nextParticipants = nextKeys.map(({ publicKey }, position) => ({
      id: `operator-next-${position + 1}`,
      index: position + 1,
      identityPublicKey: rawPublicKey(publicKey),
      transportPublicKey: hex(Buffer.alloc(32, position + 11)),
      sharePublicKey: hex(
        bls.G2.ProjectivePoint.BASE.multiply(nextScalarAt(position + 1)).toRawBytes(false),
      ),
      endpoint: `https://operator-next-${position + 1}.example`,
    }));
    const nextManifest = {
      ...manifest,
      ceremony: "reshare",
      previousManifestHash: prepared.manifestHash,
      epoch: 2,
      publicCoefficients: nextPolynomial.map((coefficient) => hex(
        bls.G2.ProjectivePoint.BASE.multiply(coefficient).toRawBytes(false),
      )),
      dkgTranscriptHash: hex(Buffer.alloc(32, 0xa3)),
      participants: nextParticipants,
      attestations: [],
      handoffAttestations: [],
    };
    const nextPrepared = groupTools.prepareGroupManifest(nextManifest);
    nextManifest.attestations = nextKeys.slice(0, 3).map(({ privateKey }, position) => ({
      participantId: nextParticipants[position].id,
      signature: hex(sign(
        null,
        Buffer.from(nextPrepared.manifestHash.slice(2), "hex"),
        privateKey,
      )),
    }));
    nextManifest.handoffAttestations = keys.slice(0, 3).map(({ privateKey }, position) => ({
      participantId: participants[position].id,
      signature: hex(sign(
        null,
        Buffer.from(nextPrepared.manifestHash.slice(2), "hex"),
        privateKey,
      )),
    }));
    const reshared = groupTools.validateGroupManifest(nextManifest, {
      previousManifest: manifest,
      trustedPreviousManifestHash: prepared.manifestHash,
    });
    assert.deepEqual(
      reshared.validHandoffAttesters,
      ["operator-1", "operator-2", "operator-3"],
    );
    assert.throws(() => groupTools.validateGroupManifest(nextManifest, {
      previousManifest: manifest,
      trustedPreviousManifestHash: hex(Buffer.alloc(32, 0xff)),
    }), /does not match the trusted hash/);
  });
});

describe("distributed DKG and resharing ceremony", function () {
  it("creates independent 3-of-5 shares and resharing preserves the group key", async function () {
    const dkg = await import("../operator/threshold-dkg.mjs");
    const groupTools = await import("../operator/threshold-group.mjs");
    const thresholdTools = await import("../operator/threshold-crypto.mjs");
    const nodeTools = await import("../operator/threshold-node.mjs");
    const password = "test-only-threshold-password";
    const generated = Array.from({ length: 5 }, (_, position) => dkg.generateParticipant({
      id: `dkg-operator-${position + 1}`,
      endpoint: `http://127.0.0.1:${9200 + position}`,
      password,
      workFactor: 1_024,
    }));
    const roster = generated.map(({ participant }, position) => ({
      ...participant,
      index: position + 1,
    }));
    const sessionId = `0x${"51".repeat(32)}`;
    const dealsAndStates = generated.map(({ keystore }) => dkg.createDealBundle({
      ceremony: "dkg",
      sessionId,
      epoch: 1,
      threshold: 3,
      roster,
      dealerKeystore: keystore,
      password,
      workFactor: 1_024,
    }));
    const deals = dealsAndStates.map((item) => item.packet);
    const responses = generated.map(({ keystore }) => dkg.createResponseBundle({
      ceremony: "dkg",
      sessionId,
      epoch: 1,
      threshold: 3,
      roster,
      recipientKeystore: keystore,
      password,
      deals,
    }));
    const finalized = generated.map(({ keystore }) => dkg.finalizeCeremony({
      ceremony: "dkg",
      sessionId,
      epoch: 1,
      threshold: 3,
      roster,
      participantKeystore: keystore,
      password,
      deals,
      responses,
      workFactor: 1_024,
    }));
    const manifest = dkg.assembleManifest({
      finalizations: finalized.map((item) => item.finalization),
      roster,
      network: "robinhood-testnet",
      chainId: 46630,
      verifierAdapter: "0x1111111111111111111111111111111111111111",
      softwareCommit: "a".repeat(40),
      containerDigest: `sha256:${"b".repeat(64)}`,
    });
    manifest.attestations = finalized.slice(0, 3).map((item) => dkg.attestManifest({
      manifest,
      participantKeystore: item.keystore,
      password,
    }));
    const firstGroup = groupTools.validateGroupManifest(manifest, { allowLoopback: true });
    const bound = finalized.map((item) => dkg.bindKeystoreToManifest({
      keystore: item.keystore,
      password,
      manifest,
      manifestHash: firstGroup.manifestHash,
      workFactor: 1_024,
    }));
    assert.throws(() => dkg.bindKeystoreToManifest({
      keystore: { ...finalized[0].keystore, participantId: roster[1].id },
      password,
      manifest,
      manifestHash: firstGroup.manifestHash,
      workFactor: 1_024,
    }), /does not match the manifest participant and share/);

    const message = `0x${"77".repeat(32)}`;
    const firstShares = bound.slice(0, 3).map((keystore, position) => {
      const secret = dkg.internals.loadKeystore(keystore, password).secret.thresholdShare;
      return {
        index: position + 1,
        publicKey: manifest.participants[position].sharePublicKey,
        signature: thresholdTools.signPartial({ message, secretShare: secret }),
      };
    });
    const aggregate = thresholdTools.aggregateThresholdShares({
      message,
      groupPublicKey: manifest.groupPublicKey,
      threshold: 3,
      shares: firstShares,
    });
    assert.equal(thresholdTools.verifyAggregateSignature({
      message,
      groupPublicKey: manifest.groupPublicKey,
      signature: aggregate.signature,
    }), true);
    const authenticatedPartial = nodeTools.buildPartialResponse({
      participant: manifest.participants[0],
      manifestHash: firstGroup.manifestHash,
      keyHash: firstGroup.keyHash,
      requestId: 123n,
      message,
      secretShare: dkg.internals.loadKeystore(bound[0], password).secret.thresholdShare,
      identityPrivateKey: dkg.internals.loadKeystore(bound[0], password).identityPrivateKey,
    });
    assert.equal(nodeTools.verifyPartialResponse(
      authenticatedPartial,
      manifest.participants[0],
      {
        manifestHash: firstGroup.manifestHash,
        keyHash: firstGroup.keyHash,
        requestId: 123n,
        message,
      },
    ).participantId, manifest.participants[0].id);
    const tamperedPartial = structuredClone(authenticatedPartial);
    tamperedPartial.body.requestId = "124";
    assert.throws(() => nodeTools.verifyPartialResponse(
      tamperedPartial,
      manifest.participants[0],
      {
        manifestHash: firstGroup.manifestHash,
        keyHash: firstGroup.keyHash,
        requestId: 124n,
        message,
      },
    ), /identity signature/);

    const reshareSessionId = `0x${"52".repeat(32)}`;
    const selectedDealerIds = roster.slice(0, 3).map((item) => item.id);
    const resharing = bound.slice(0, 3).map((keystore) => dkg.createDealBundle({
      ceremony: "reshare",
      sessionId: reshareSessionId,
      epoch: 2,
      threshold: 3,
      roster,
      dealerKeystore: keystore,
      password,
      previousManifest: manifest,
      previousManifestHash: firstGroup.manifestHash,
      selectedDealerIds,
      workFactor: 1_024,
    }));
    const reshareDeals = resharing.map((item) => item.packet);
    const reshareResponses = bound.map((keystore) => dkg.createResponseBundle({
      ceremony: "reshare",
      sessionId: reshareSessionId,
      epoch: 2,
      threshold: 3,
      roster,
      dealerRoster: manifest.participants,
      previousManifestHash: firstGroup.manifestHash,
      selectedDealerIds,
      recipientKeystore: keystore,
      password,
      deals: reshareDeals,
    }));
    const reshared = bound.map((keystore) => dkg.finalizeCeremony({
      ceremony: "reshare",
      sessionId: reshareSessionId,
      epoch: 2,
      threshold: 3,
      roster,
      dealerRoster: manifest.participants,
      participantKeystore: keystore,
      password,
      deals: reshareDeals,
      responses: reshareResponses,
      previousManifest: manifest,
      previousManifestHash: firstGroup.manifestHash,
      selectedDealerIds,
      workFactor: 1_024,
    }));
    assert.equal(reshared[0].finalization.groupPublicKey, manifest.groupPublicKey);
    assert.notEqual(reshared[0].finalization.sharePublicKey, manifest.participants[0].sharePublicKey);

    const nextManifest = dkg.assembleManifest({
      finalizations: reshared.map((item) => item.finalization),
      roster,
      network: "robinhood-testnet",
      chainId: 46630,
      verifierAdapter: manifest.verifierAdapter,
      softwareCommit: "c".repeat(40),
      containerDigest: `sha256:${"d".repeat(64)}`,
      previousManifestHash: firstGroup.manifestHash,
    });
    nextManifest.attestations = reshared.slice(0, 3).map((item) => dkg.attestManifest({
      manifest: nextManifest,
      participantKeystore: item.keystore,
      password,
    }));
    nextManifest.handoffAttestations = bound.slice(0, 3).map((keystore) => dkg.attestManifest({
      manifest: nextManifest,
      participantKeystore: keystore,
      password,
    }));
    const validatedReshare = groupTools.validateGroupManifest(nextManifest, {
      allowLoopback: true,
      previousManifest: manifest,
      trustedPreviousManifestHash: firstGroup.manifestHash,
    });
    assert.equal(validatedReshare.keyHash, firstGroup.keyHash);
  });

  it("publishes and verifies complaint resolutions without accepting a bad share", async function () {
    const dkg = await import("../operator/threshold-dkg.mjs");
    const password = "test-only-threshold-password";
    const generated = Array.from({ length: 3 }, (_, position) => dkg.generateParticipant({
      id: `complaint-operator-${position + 1}`,
      endpoint: `http://127.0.0.1:${9300 + position}`,
      password,
      workFactor: 1_024,
    }));
    const roster = generated.map(({ participant }, position) => ({
      ...participant,
      index: position + 1,
    }));
    const sessionId = `0x${"61".repeat(32)}`;
    const created = generated.map(({ keystore }) => dkg.createDealBundle({
      sessionId,
      epoch: 1,
      threshold: 2,
      roster,
      dealerKeystore: keystore,
      password,
      workFactor: 1_024,
    }));
    const corruptedDeals = created.map((item) => structuredClone(item.packet));
    corruptedDeals[0].body.encryptedShares[1].envelope.ciphertext = `0x${"ff".repeat(32)}`;
    const dealerSecrets = dkg.internals.decryptPayload(created[0].state.crypto, password);
    const dealer = dkg.internals.loadKeystore(generated[0].keystore, password);
    corruptedDeals[0].signature = dkg.internals.signPacket(
      corruptedDeals[0].body,
      dealer.identityPrivateKey,
    );
    const maliciousDealerState = {
      ...created[0].state,
      crypto: dkg.internals.encryptPayload({
        ...dealerSecrets,
        dealHash: dkg.internals.packetHash(corruptedDeals[0].body),
      }, password, 1_024),
    };
    const responses = generated.map(({ keystore }) => dkg.createResponseBundle({
      sessionId,
      epoch: 1,
      threshold: 2,
      roster,
      recipientKeystore: keystore,
      password,
      deals: corruptedDeals,
    }));
    assert.equal(responses[1].body.statuses.find(
      (item) => item.dealerId === roster[0].id,
    ).status, false);
    const forgedResponse = structuredClone(responses[2]);
    forgedResponse.body.statuses.find(
      (item) => item.dealerId === roster[0].id,
    ).status = false;
    assert.throws(() => dkg.createResolutionBundle({
      dealerKeystore: generated[0].keystore,
      dealerState: maliciousDealerState,
      password,
      deal: corruptedDeals[0],
      responses: [responses[0], responses[1], forgedResponse],
      roster,
    }), /invalid response packet/);

    const thresholdComplaints = structuredClone(responses);
    const thirdSigner = dkg.internals.loadKeystore(generated[2].keystore, password);
    thresholdComplaints[2].body.statuses.find(
      (item) => item.dealerId === roster[0].id,
    ).status = false;
    thresholdComplaints[2].body.statuses.find(
      (item) => item.dealerId === roster[0].id,
    ).reason = "dealer unavailable";
    thresholdComplaints[2].signature = dkg.internals.signPacket(
      thresholdComplaints[2].body,
      thirdSigner.identityPrivateKey,
    );
    assert.throws(() => dkg.createResolutionBundle({
      dealerKeystore: generated[0].keystore,
      dealerState: maliciousDealerState,
      password,
      deal: corruptedDeals[0],
      responses: thresholdComplaints,
      roster,
    }), /refusing to reveal threshold shares/);
    const resolution = dkg.createResolutionBundle({
      dealerKeystore: generated[0].keystore,
      dealerState: maliciousDealerState,
      password,
      deal: corruptedDeals[0],
      responses,
      roster,
    });
    const result = dkg.finalizeCeremony({
      sessionId,
      epoch: 1,
      threshold: 2,
      roster,
      participantKeystore: generated[1].keystore,
      password,
      deals: corruptedDeals,
      responses,
      resolutions: [resolution],
      workFactor: 1_024,
    });
    assert.equal(result.finalization.qualifiedDealerIds.includes(roster[0].id), true);
  });
});
