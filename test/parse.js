const fs = require('fs');

function fileExist(filePath) {
	return fs.existsSync(filePath);
}

function rawG1(value) {
	const regex = /\(([^)]+)\)/g;
	const matches = Array.from(value.matchAll(regex));
	return matches.map((match) =>
		match[1].split(',').map((x) => BigInt(x.trim()).toString()),
	);
}

function rawG2(value) {
	const regex = /QuadExtField\((-?\d+) \+ (-?\d+) \* u\)/g;
	const matches = Array.from(value.matchAll(regex));
	return matches.map((match) => [
		BigInt(match[2]).toString(),
		BigInt(match[1]).toString(),
	]);
}

function rawLinkProof(value) {
	const data = JSON.parse(value);
	return rawG1(data.pi).flat();
}

function rawInstance(value) {
	const data = JSON.parse(value);
	return [...rawG1(data.link_com), ...rawG1(data.pd_cm)].flat();
}

function rawProof(value) {
	const data = JSON.parse(value);
	return [
		...rawG1(data.a),
		...rawG2(data.b),
		...rawG1(data.c),
		...rawG1(data.d),
	].flat();
}

function rawVk(value) {
	const data = JSON.parse(value);
	return [
		...rawG1(data.alpha),
		...rawG2(data.beta),
		...rawG2(data.delta),
		...rawG1(data.abc),
		...rawG2(data.gamma),
	].flat();
}

function rawVkLink(value) {
	const data = JSON.parse(value);
	return [...rawG2(data.C), ...rawG2(data.a)].flat();
}

function parseRawFile(inputFilePath) {
	if (!fileExist(inputFilePath)) {
		console.error('Input file does not exist.');
		return;
	}

	const rawData = fs.readFileSync(inputFilePath, 'utf8');
	const jsonData = JSON.parse(rawData);

	try {
		const instance = rawInstance(jsonData.instance);
		const proofGroth = rawProof(jsonData.proof_groth);
		const vkGroth = rawVk(jsonData.vk_groth);
		const proofLink = rawLinkProof(jsonData.proof_link);
		const vkLink = rawVkLink(jsonData.vk_link);

		const formattedData = {
			instance,
			proofGroth,
			vkGroth,
			proofLink,
			vkLink,
		};
		return formattedData;
	} catch (error) {
		console.error('Error during parsing or file writing:', error);
	}
}

module.exports = {
	parseRawFile,
};
