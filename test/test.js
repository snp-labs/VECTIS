const { parseRawFile } = require('./parse');
const { ethers } = require('hardhat');

describe('LegoGroth16', function () {
	const txCount = 100;

	for (let i = 1; i <= 10; i++) {
		const sz = 1 << i;
		const mockData = parseRawFile('./test/mock-' + sz + '.json');

		async function deploy(batchSize) {
			const legoGroth16 = await ethers.getContractFactory('LegoGroth16');
			const contract = await legoGroth16.deploy(
				mockData.vkGroth,
				mockData.vkLink,
				batchSize,
			);
			return contract;
		}

		it('Computing TPS by Tx Count', async function () {
			const contract = await deploy(sz);
			const provider = new ethers.JsonRpcProvider(
				'http://localhost:8545/',
			);

			await contract.init();

			const startTime = new Date();
			const data = (
				await contract.verify(mockData.proofGroth, mockData.proofLink)
			).data;

			let txs = [];
			for (let i = 0; i < txCount; i++) {
				const wallet = ethers.Wallet.createRandom();
				const signer = wallet.connect(provider);

				let signedTx = await signer.signTransaction({
					from: wallet.address,
					to: contract.target,
					nonce: 0,
					value: 0,
					maxFeePerGas: 0,
					data,
					gasLimit: 100000000,
					chainId: 1337,
				});

				txs.push(provider.broadcastTransaction(signedTx));
			}
			await Promise.all(txs);
			let deltaTime = (new Date().getTime() - startTime.getTime()) / 1000;

			console.log(
				'Gas:',
				await contract.verify.estimateGas(
					mockData.proofGroth,
					mockData.proofLink,
				),
			);
			console.log('TPS:', txCount / deltaTime);
		});
	}
});
