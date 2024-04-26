// verifier input file 읽고 옮겨쓰기
const { assert, Console } = require("console");
const fs = require("fs");
const _ = require("lodash");
const util = require("util");
const Web3Utils = require("web3-utils");
const ethers = require("ethers");

const readFileAsync = util.promisify(fs.readFile);

const MOCK_DATA_PATH = "./test/mockVerifierInput.json";

async function readVerifierInputJson() {
    try {
        const jsonStr = await readFileAsync(MOCK_DATA_PATH, "utf8");
        const data = JSON.parse(jsonStr);
        return data;
    } catch (err) {
        console.error("Error reading or parsing JSON:", err);
        // Handle the error accordingly, for example, you might want to throw it.
        throw err;
    }
}

async function parseVerifierInputJson() { 
    const verifierInputJson = await readVerifierInputJson();

    const verifierInputStrArr = [];

    verifierInputJson.vk_link.a.forEach((item) => {
        verifierInputStrArr.push(...item);
    });

    verifierInputJson.vk_link.c.forEach((item) => {
        verifierInputStrArr.push(...item);
    });

    verifierInputJson.instance.x.forEach((item) => {
        verifierInputStrArr.push(...item);
    });

    verifierInputJson.proof.pi.forEach((item) => {
        verifierInputStrArr.push(...item);
    });

    // assert(verifierInputStrArr.length === 12);

    return verifierInputStrArr;
}

async function verifierInputToBN(numOfInstance) {
    const verifierInputStrArr = await parseVerifierInputJson();

    let _vk_a = [];
    for (let i = 0; i < 4; i++) {
        _vk_a.push(Web3Utils.toBigInt(verifierInputStrArr[i]));
    }
    let _vk_c = [];
    for (let i = 4; i < 8; i++) {
        _vk_c.push(Web3Utils.toBigInt(verifierInputStrArr[i]));
    }
    
    let vk = [];
    vk.push(..._vk_a);
    for (let i = 0; i < numOfInstance; i++) {
        vk.push(..._vk_c);
    }

    let _instance = [];
    for (let i = 8; i < 10; i++) {
        _instance.push(Web3Utils.toBigInt(verifierInputStrArr[i]));
    }
    let instance = [];
    for (let i = 0; i < numOfInstance; i++) {
        instance.push(..._instance);
    }

    let proof = [];
    for (let i = 10; i < 12; i++) {
        proof.push(Web3Utils.toBigInt(verifierInputStrArr[i]));
    }
    //console.log(vk, instance, proof);
    return [vk, instance, proof];
}


module.exports = {
    verifierInputToBN,
    parseVerifierInputJson,
};