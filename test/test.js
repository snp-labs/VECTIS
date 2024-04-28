const { parseRawFile } = require('./parse');

describe('LegoGroth16', function () {
	const txCount = 100;
	const BatchSize = 1 << 5; // NOTE: Set batch size (log)
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
		const startTime = new Date();
		let promise = [];
		for (let i = 0; i < txCount; i++) {
			promise.push(
				await contract.verify(
					mockData.instance,
					mockData.proofGroth,
					mockData.proofLink,
				),
			);
		}
		let receipt = await Promise.all(promise);
		let deltaTime = (new Date().getTime() - startTime.getTime()) / 1000;

		// raw Transaction (optional)
		// for (let r of receipt) {
		// 	console.log(ethers.Transaction.from(r).serialized);
		// }

		console.log('TPS:', txCount / deltaTime);
	});
});
