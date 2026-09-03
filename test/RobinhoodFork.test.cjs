const { before, describe, it } = require("node:test");
const { expect } = require("chai");

const runFork = process.env.VRF_RUN_ROBINHOOD_FORK === "true";
let network;

describe("Robinhood fork integration", { skip: !runFork }, function () {
  before(async function () {
    ({ network } = await import("hardhat"));
  });

  it("uses the live ArbSys L2 number and hash through the deployed context adapter", async function () {
    const { ethers } = await network.create();
    expect((await ethers.provider.getNetwork()).chainId).to.equal(46630n);
    // EDR forks Robinhood state but cannot emulate chain-specific precompiles. Install a
    // fork-only implementation whose NUMBER/BLOCKHASH now refer to the forked L2 chain.
    const arbSysMock = await ethers.deployContract("MockArbSysForFork");
    await arbSysMock.waitForDeployment();
    const mockCode = await ethers.provider.getCode(await arbSysMock.getAddress());
    await ethers.provider.send("hardhat_setCode", [
      "0x0000000000000000000000000000000000000064",
      mockCode,
    ]);
    const context = await ethers.deployContract("ArbitrumBlockContext");
    await context.waitForDeployment();
    const l2Block = await context.blockNumber();
    expect(l2Block).to.be.greaterThan(0n);
    const hash = await context.blockHash(l2Block - 1n);
    expect(hash).to.not.equal(ethers.ZeroHash);

    const store = await ethers.deployContract("BlockhashStore", [await context.getAddress()]);
    await store.waitForDeployment();
    await expect(store.store(l2Block - 1n)).to.emit(store, "BlockhashStored");
    expect(await store.blockhashes(l2Block - 1n)).to.equal(hash);
  });
});
