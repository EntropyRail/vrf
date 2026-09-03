const { before, describe, it } = require("node:test");

let expect;
let ethers;

before(async function () {
  ({ expect } = await import("chai"));
  const { network } = await import("hardhat");
  ({ ethers } = await network.create());
});

describe("VRFAdminTimelock", function () {
  it("delays owner calls and allows permissionless execution", async function () {
    const [owner, executor] = await ethers.getSigners();
    const delay = 12 * 60 * 60;
    const timelock = await ethers.deployContract("VRFAdminTimelock", [owner.address, delay]);
    const target = await ethers.deployContract("MockAdminTarget");
    await Promise.all([timelock.waitForDeployment(), target.waitForDeployment()]);

    const data = target.interface.encodeFunctionData("setValue", [7]);
    await timelock.connect(owner).schedule(await target.getAddress(), 0, data);
    await expect(timelock.connect(executor).execute(1, await target.getAddress(), 0, data))
      .to.be.revertedWithCustomError(timelock, "OperationNotReady");

    await ethers.provider.send("evm_increaseTime", [delay]);
    await ethers.provider.send("evm_mine", []);
    await expect(timelock.connect(executor).execute(1, await target.getAddress(), 0, data))
      .to.emit(timelock, "CallExecuted");
    expect(await target.value()).to.equal(7);
  });

  it("rechecks target code at execution time", async function () {
    const [owner, executor] = await ethers.getSigners();
    const delay = 12 * 60 * 60;
    const timelock = await ethers.deployContract("VRFAdminTimelock", [owner.address, delay]);
    const target = await ethers.deployContract("MockAdminTarget");
    await Promise.all([timelock.waitForDeployment(), target.waitForDeployment()]);
    const targetAddress = await target.getAddress();
    const data = target.interface.encodeFunctionData("setValue", [9]);
    await timelock.connect(owner).schedule(targetAddress, 0, data);
    await ethers.provider.send("hardhat_setCode", [targetAddress, "0x"]);
    await ethers.provider.send("evm_increaseTime", [delay]);
    await ethers.provider.send("evm_mine", []);
    await expect(timelock.connect(executor).execute(1, targetAddress, 0, data))
      .to.be.revertedWithCustomError(timelock, "InvalidTarget");
  });
});
