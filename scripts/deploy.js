const fs = require('fs');
const type = require("../test/type");
const { ethers } = require('hardhat');
require("@nomicfoundation/hardhat-ethers");

async function tps(signer, contractInstance, instance, proof) {
  const txCount = 10;

  let data = [];
  let receipt = [];
  let rawTx = [];

  for(let i = 0; i < txCount; i++) {
    // let d = await contractInstance.populateTransaction.verify(instance, proof);
    let d = await contractInstance.populate
    let r = await signer.sendTransaction(d);
    data.push(d);
    receipt.push(r);
    rawTx.push(r.raw);
  }
}

async function main() {
  const logSize = 2;
  const [vk, instance, proof]= await type.verifierInputToBN(1 << logSize);

  const [deployer] = await ethers.getSigners();
  const cpLinkVerifyBn128 = await ethers.getContractFactory("cpLinkVerifyBn128");
  const CpLinkVerifyBn128 = await cpLinkVerifyBn128.deploy(vk);

  
  const contractInstance = CpLinkVerifyBn128.connect(deployer);
  await tps(deployer, contractInstance, instance, proof);
  
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error);
    process.exit(1);
});