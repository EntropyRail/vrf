import hardhatEthersPlugin from "@nomicfoundation/hardhat-ethers";
import hardhatEthersChaiMatchersPlugin from "@nomicfoundation/hardhat-ethers-chai-matchers";
import hardhatNodeTestRunnerPlugin from "@nomicfoundation/hardhat-node-test-runner";
import { defineConfig } from "hardhat/config";

const externalAccounts = process.env.VRF_DEPLOYER_PRIVATE_KEY
  ? [process.env.VRF_DEPLOYER_PRIVATE_KEY]
  : [];

export default defineConfig({
  plugins: [
    hardhatEthersPlugin,
    hardhatEthersChaiMatchersPlugin,
    hardhatNodeTestRunnerPlugin,
  ],
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 500 },
      viaIR: true,
    },
  },
  networks: {
    hardhat: {
      type: "edr-simulated",
      chainType: "l1",
      chainId: 31337,
    },
    robinhoodFork: {
      type: "edr-simulated",
      chainType: "generic",
      chainId: 46630,
      forking: {
        url: process.env.ROBINHOOD_TESTNET_RPC_URL
          || "https://rpc.testnet.chain.robinhood.com",
      },
    },
    robinhoodTestnet: {
      type: "http",
      chainType: "generic",
      url: process.env.ROBINHOOD_TESTNET_RPC_URL || "https://rpc.testnet.chain.robinhood.com",
      chainId: 46630,
      accounts: externalAccounts,
    },
    robinhoodMainnet: {
      type: "http",
      chainType: "generic",
      url: process.env.ROBINHOOD_MAINNET_RPC_URL || "https://rpc.mainnet.chain.robinhood.com",
      chainId: 4663,
      accounts: externalAccounts,
    },
  },
});
