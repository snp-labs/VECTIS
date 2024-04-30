import { ethers } from "hardhat"
import { expect } from "chai"
import { mock } from "./mock"
import { result } from "./result"

describe('BccSNARK TPS', function () {
    const logN = 10
    const duration = 300 // 5 minutes
    const logGap = 5 // 5 seconds
    const txCount = 30

    async function deploy(batchSize: any) {
        const [deployer] = await ethers.getSigners();
        const BccSNARK = await ethers.getContractFactory('BccSNARK')
        const bccSNARK = await BccSNARK.deploy(mock.vk, batchSize)
        return bccSNARK
    }

    // it("TPS Summary", function () {
    //     for (let d of result.data) {
    //         let batchTPS = d.tx / d.time
    //         let TPS = d.batch * batchTPS
    //         let gasAvg = d.gas / d.tx
    //         console.log("batch size: ", d.batch)
    //         console.log("tps: ", batchTPS)
    //         console.log("tps (batch): ", TPS)
    //         console.log("gas (avg): ", gasAvg)
    //     }
    // })

    let batchSize = 1 << logN
    it("Calculating TPS by Tx Count", async function () {
        const bccSNARK = await deploy(batchSize)

        const startTime = new Date()
        let promise = []
        for (let i = 0; i < txCount; i++)
            promise.push(bccSNARK.verify(mock.proof))
        await Promise.all(promise)
        let deltaTime = ((new Date()).getTime() - startTime.getTime()) / 1000

        console.log("Batch Size:", batchSize)
        console.log("Gas:", await bccSNARK.estimateGas.verify(mock.proof))

        console.log("TPS:", txCount / deltaTime)
        expect(true)
    })

    // it("Calculating TPS by Duration", async function () {
    //     const bccSNARK = await deploy()
    //     let nextLog = logGap

    //     let transactionCount = 0
    //     const startTime = new Date()
    //     let deltaTime = 0
    //     while (deltaTime < duration) {
    //         let receipt = await bccSNARK.verify(mock.proof)
    //         let tx = ethers.Transaction.from(receipt).serialized
    //         console.log(receipt)
    //         console.log(tx)

    //         transactionCount++
    //         deltaTime = ((new Date()).getTime() - startTime.getTime()) / 1000

    //         if (deltaTime > nextLog) {
    //             nextLog += logGap
    //             console.log(deltaTime, transactionCount)
    //         }
    //     }

    //     console.log("TPS:", transactionCount / deltaTime)
    //     expect(true)
    // })

    // it("Change Test", async function () {
    //     const bccSNARK = await deploy()
    //     for (let i = 1; i <= 10; i++)
    //         await bccSNARK.chl(i - 1, i);
    //     expect(true)
    // })
})
