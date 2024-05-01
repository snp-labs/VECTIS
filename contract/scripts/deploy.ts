import { ethers } from "hardhat"
import { mock } from "../test/mock"
import { BccSNARK } from "../typechain-types"
import { TransactionResponse, assert } from "ethers"

const calculateTPS = true
const logN = 5
const batchSize = 1 << logN
const txCount = 10

async function tps(contractInstance: BccSNARK) {
    const provider = new ethers.JsonRpcProvider("http://localhost:8545/");
    const contractAddress = await contractInstance.getAddress()
    console.log("Contract Address", contractAddress)

    let data = (await contractInstance.verify.populateTransaction(mock.batch[logN - 1].proof)).data
    let signedTx = []


    for (let i = 0; i < txCount; i++) {
        let wallet = ethers.Wallet.createRandom()
        let signer = wallet.connect(provider)

        signedTx.push(await signer.signTransaction({
            from: wallet.address,
            to: contractAddress,
            nonce: 0,
            value: 0,
            data,
            gasLimit: 0x1ffffffffffffe,
            chainId: 1337,
        }))
    }

    const startTime = new Date()
    let promise = []
    let response: TransactionResponse[] = []

    try {
        for (let i = 0; i < txCount; i++)
            promise.push(provider.broadcastTransaction(signedTx[i]))
        response = await Promise.all(promise)
    } catch (err) {
        console.error(err)
    }
    let deltaTime = ((new Date()).getTime() - startTime.getTime()) / 1000

    for (let r of response) {
        console.log(r.hash)
        console.log(await provider.getTransactionReceipt(r.hash))
    }

    console.log("Gas:", await contractInstance.verify.estimateGas(mock.batch[logN - 1].proof))
    console.log("TPS:", txCount / deltaTime)
}

async function main() {
    const [deployer] = await ethers.getSigners();
    const BccSNARK = await ethers.getContractFactory("BccSNARK")
    const bccSNARK = await BccSNARK.deploy(mock.batch[logN - 1].cm, mock.batch[logN - 1].vk, batchSize)

    if (calculateTPS) {
        const contractInstance = bccSNARK.connect(deployer)
        await tps(contractInstance)
    }
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error)
        process.exit(1)
    })