const fs = require('fs');
const type = require("./type");
const { expect } = require("chai");


describe("cpLinkVerify", function () {
  it("_verifyLS should return true", async function () {


    const logSize = 2;
    const logFilePath = './test/mockDataLog.txt'; 

    function writeToLog(message) {
      fs.appendFileSync(logFilePath, message + '\n');
    }

    if (fs.existsSync(logFilePath)) {
      fs.unlinkSync(logFilePath);
    }
    // writeToLog(`Log size: ${logSize}`);

    const [vk, instance, proof]= await type.verifierInputToBN(1 << logSize);
    const verify = await ethers.getContractFactory("cpLinkVerify");

    // for (let i = 1; i <= (1 << logSize); i <<= 1) {
    //   const verifierInputParam = await type.verifierInputToBN(i);
    //   //const logMessage = `verifierInputParam ${i}: ${verifierInputParam}`;
    //   //writeToLog(logMessage); 
    //   //console.log("verifierInputParam: ", verifierInputParam);
    //   const tmp = await verify.deploy(verifierInputParam[0]);
    //   const check = await tmp.verify(verifierInputParam[1], verifierInputParam[2]);
    //   assert(check === true);
    // }
    
    const logMessage = `vk:\n${vk}\ninstance:\n${instance}\nproof:\n${proof}\n\n`;
    writeToLog(logMessage);
    const tmp = await verify.deploy(vk);
    const check = await tmp.verify(instance, proof);
    // console.log("check: ", check);
  });
});

describe("cpLinkVerify", function () {
  it("_verifyLS should return true", async function () {

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

    const logSize = 2;
    const logFilePath = './test/mockDataLog.txt'; 



    const [vk, instance, proof]= await type.verifierInputToBN(1 << logSize);
    const verify = await ethers.getContractFactory("cpLinkVerify");
    
    const tmp = await verify.deploy(vk);
    const check = await tmp.verify(instance, proof);
    
    // console.log("check: ", check);
  });
});