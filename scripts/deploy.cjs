function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main() {
  const { network } = await import("hardhat");
  const { ethers } = await network.create();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  if (chainId !== 31337 && chainId !== 46630 && chainId !== 4663) {
    throw new Error(`refusing unsupported chain ${chainId}`);
  }
  if (chainId === 4663 && process.env.VRF_ALLOW_MAINNET !== "I_UNDERSTAND_MAINNET_RISK") {
    throw new Error("mainnet deployment requires VRF_ALLOW_MAINNET=I_UNDERSTAND_MAINNET_RISK");
  }

  const [deployer] = await ethers.getSigners();
  if (!deployer) throw new Error("VRF_DEPLOYER_PRIVATE_KEY did not provide a signer");
  const owner = required("VRF_OWNER");
  const operator = required("VRF_OPERATOR");
  const publicKey = [BigInt(required("VRF_PUBLIC_KEY_X")), BigInt(required("VRF_PUBLIC_KEY_Y"))];
  const fee = BigInt(process.env.VRF_FEE_WEI || "25000000000000");

  const coordinatorFactory = await ethers.getContractFactory("ProofVRFCoordinator");
  const coordinator = await coordinatorFactory.deploy(deployer.address);
  await coordinator.waitForDeployment();
  const keyTransaction = await coordinator.registerKey(publicKey, operator, fee);
  await keyTransaction.wait();
  const keyHash = await coordinator.keyHash(publicKey);

  const routerFactory = await ethers.getContractFactory("ProofVRFRouter");
  const router = await routerFactory.deploy(deployer.address);
  await router.waitForDeployment();
  const providerTransaction = await router.registerProvider(keyHash, await coordinator.getAddress());
  await providerTransaction.wait();

  if (owner.toLowerCase() !== deployer.address.toLowerCase()) {
    await (await coordinator.transferOwnership(owner)).wait();
    await (await router.transferOwnership(owner)).wait();
  }

  process.stdout.write(`${JSON.stringify({
    chainId,
    deployer: deployer.address,
    owner,
    operator,
    keyHash,
    fee: fee.toString(),
    coordinator: await coordinator.getAddress(),
    router: await router.getAddress(),
  }, null, 2)}\n`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
