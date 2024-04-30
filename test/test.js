const { JsonRpcProvider } = require('ethers');
const { parseRawFile } = require('./parse');
const fs = require('fs');
const { ethers } = require('hardhat');

describe('LegoGroth16', function () {
	const txCount = 10;
	const BatchSize = 1 << 10; // NOTE: Set batch size (log)
	const mockData = parseRawFile('./test/mock-' + BatchSize + '.json');

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
		const contract = await deploy(BatchSize);

		await contract.init();

		const startTime = new Date();
		// let promise = [];
		// for (let i = 0; i < txCount; i++) {
		// 	promise.push(
		// 		await contract.verify(mockData.proofGroth, mockData.proofLink),
		// 	);
		// }

		const data = (
			await contract.verify(mockData.proofGroth, mockData.proofLink)
		).data;

		const provider = new ethers.JsonRpcProvider('http://localhost:8545/');

		let txs = [];
		for (let i = 0; i < txCount; i++) {
			const wallet = ethers.Wallet.createRandom();
			const signer = wallet.connect(provider);

			let signedTx = await signer.signTransaction({
				from: wallet.address,
				to: ethers.ZeroAddress,
				nonce: 0,
				value: 0,
				data,
				gasLimit: 100000000,
				chainId: 1337,
			});

			// txs.push(signedTx);
			txs.push(provider.broadcastTransaction(signedTx));
		}
		Promise.all(txs);
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

	/// NOTE: With random address
	// it('Computing TPS by Tx Count', async function () {
	// 	const provider = new ethers.JsonRpcProvider('http://localhost:8545/');
	// 	const contract = await deploy(BatchSize);

	// 	let txs = [];

	// 	const data = (
	// 		await contract.verify(
	// 			mockData.instance,
	// 			mockData.proofGroth,
	// 			mockData.proofLink,
	// 		)
	// 	).data;

	// 	for (let i = 0; i < txCount; i++) {
	// 		const wallet = ethers.Wallet.createRandom();
	// 		const signer = wallet.connect(provider);

	// 		let signedTx = await signer.signTransaction({
	// 			from: wallet.address,
	// 			to: ethers.ZeroAddress,
	// 			nonce: 0,
	// 			value: 0,
	// 			data,
	// 			gasLimit: 100000000,
	// 			chainId: 1337,
	// 		});

	// 		txs.push(signedTx);
	// 	}

	// 	txs = txs.join('\n');
	// 	fs.writeFileSync('txs.csv', txs, { encoding: 'utf-8' });

	// 	console.log(
	// 		'Gas:',
	// 		await contract.verify.estimateGas(
	// 			mockData.instance,
	// 			mockData.proofGroth,
	// 			mockData.proofLink,
	// 		),
	// 	);
	// });
});
