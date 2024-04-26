const fs = require('fs');
const type = require("../../test/type");
require("@nomicfoundation/hardhat-ethers/signers");

const calculateTPS = true;

async function tps(signer, contractInstance, instance, proof) {
  const txCount = 10;

  let data = [];
  let receipt = [];
  let rawTx = [];

  for(let i = 0; i < txCount; i++) {
    let d = await contractInstance.populateTransaction.verify(instance, proof);
    let r = await signer.sendTransaction(d);
    data.push(d);
    receipt.push(r);
    rawTx.push(r.raw);
  }

  
  console.log("TPS:", txCount / deltaTime);
}

async function main() {
  const logSize = 2;
  const [vk, instance, proof]= await type.verifierInputToBN(1 << logSize);

  const [deployer] = await ethers.getSigners();
  const cpLinkVerifyBn128 = await ethers.getContractFactory("cpLinkVerifyBn128");
  const CpLinkVerifyBn128 = await cpLinkVerifyBn128.deploy(vk);

  const tmp = await cpLinkVerifyBn128.deploy(vk);

  if (calculateTPS) {
    const contractInstance = CpLinkVerifyBn128.connect(deployer);
    await tps(deployer, contractInstance, instance, proof);
  }
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error);
    process.exit(1);
});