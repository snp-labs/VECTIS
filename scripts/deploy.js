const { parseRawFile } = require('../test/parse');

async function main() {
	const BatchSize = 1 << 5; // NOTE: Set batch size (log)
	const mockData = parseRawFile('./test/mock-' + BatchSize + '.json');

	const legoGroth16 = await ethers.getContractFactory('LegoGroth16');
	await legoGroth16.deploy(mockData.vkGroth, mockData.vkLink, BatchSize);
}

main()
	.then(() => process.exit(0))
	.catch((error) => {
		console.error(error);
		process.exit(1);
	});
