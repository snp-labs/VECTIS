const hre = require("hardhat");
const type = require("../test/type");

async function main() {
  try {
    const logSize = 2;
    const cpLinkVerify = await hre.ethers.getContractFactory("cpLinkVerify");

    const contractAddress = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512"; // Replace with your deployed contract address
    const verifyContract = await cpLinkVerify.attach(contractAddress);

    const [_, instance, proof]= await type.verifierInputToBN(1 << logSize);
    await verifyContract.verify(instance, proof);

  } catch (error) {
    console.error(error);
    process.exit(1);
  }
}

main();