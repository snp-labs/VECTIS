require('@nomicfoundation/hardhat-toolbox');
require('@nomicfoundation/hardhat-ethers');

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
	solidity: '0.8.24',
	networks: {
		hardhat: {
			chainId: 1337,
			initialBaseFeePerGas: 0,
			blockGasLimit: 1000000000,
		},
	},
};
