import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: "0.8.24",
  networks: {
    hardhat: {
      chainId: 1337,
      initialBaseFeePerGas: 0,
      gasPrice: 0,
      allowUnlimitedContractSize: true,
      blockGasLimit: 124500000,
    },
    besuWallet: {
      chainId: 1337,
      initialBaseFeePerGas: 0,
      gasPrice: 0,
      url: "http://localhost:8545/",
      accounts: [
        "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63"
      ],
      allowUnlimitedContractSize: true,
      blockGasLimit: 0x1fffffffffffff
    },
  },
  mocha: {
    timeout: 100000000,
  },
};

export default config;
