require('@nomicfoundation/hardhat-toolbox');
require('@nomicfoundation/hardhat-ethers');

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
	solidity: '0.8.24',
	networks: {
		hardhat: {
			chainId: 1337,
			initialBaseFeePerGas: 0,
			blockGasLimit: 124500000,
			allowUnlimitedContractSize: true,
		},
		besu: {
			initialBaseFeePerGas: 0,
			url: 'http://localhost:8545/',
			accounts: [
				'0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63',
			],
			allowUnlimitedContractSize: true,
		},
	},
	mocha: {
		timeout: 100000000,
	},
};
