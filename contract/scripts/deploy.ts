import { ethers } from "hardhat"
import { mock } from "../test/mock"
import { BccSNARK } from "../typechain-types"
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers"

const calculateTPS = false

async function tps(signer: SignerWithAddress, contractInstance: BccSNARK) {
    const txCount = 300

    const startTime = new Date()
    let data = []
    let receipt = []
    let rawTx = []
    for (let i = 0; i < txCount; i++) {
        let d = await contractInstance.populateTransaction.verify(mock.proof)
        // let s = await signer.signTransaction(d)
        let r = await signer.sendTransaction(d)
        data.push(d)
        receipt.push(r)
        rawTx.push(r.raw)
    }

    let deltaTime = ((new Date()).getTime() - startTime.getTime()) / 1000

    // for (let d of data)
    //     console.log(d)

    // for (let r of receipt)
    //     console.log(r)
    
    for (let s of rawTx)
        console.log(s)
    console.log("TPS:", txCount / deltaTime)
}

async function main() {
    const [deployer] = await ethers.getSigners();
    const BccSNARK = await ethers.getContractFactory("BccSNARK")
    const bccSNARK = await BccSNARK.deploy(mock.vk, mock.list_cm)

    if (calculateTPS) {
        const contractInstance = bccSNARK.connect(deployer)
        await tps(deployer, contractInstance)
    }
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error)
        process.exit(1)
    })