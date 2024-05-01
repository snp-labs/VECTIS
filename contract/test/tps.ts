import { ethers } from "hardhat"
import { expect } from "chai"
import { mock } from "./mock"

describe('BccSNARK TPS', function () {
    const logN = 10
    const duration = 300 // 5 minutes
    const logGap = 5 // 5 seconds
    const txCount = 100

    const provider = new ethers.JsonRpcProvider('http://localhost:8545/');

    async function deploy(logN: any, batchSize: any) {
        const BccSNARK = await ethers.getContractFactory('BccSNARK')
        const bccSNARK = await BccSNARK.deploy(mock.batch[logN - 1].cm, mock.batch[logN - 1].vk, batchSize)

        const data = (await bccSNARK.verify(mock.batch[logN - 1].proof)).data
        let user = []
        for (let i = 0; i < txCount; i++) {
            let wallet = ethers.Wallet.createRandom()
            let signer = wallet.connect(provider)

            user.push({
                wallet,
                signer
            })
        }

        return { bccSNARK, data, user }
    }

    for (let i = 1; i <= logN; i++) {

        let batchSize = 1 << i
        it("TPS", async function () {
            const { bccSNARK, data, user } = await deploy(i, batchSize)
            const bccSNARKAddress = await bccSNARK.getAddress()
            let signedTx = []
            for (let u of user) {
                signedTx.push(await u.signer.signTransaction({
                    from: u.wallet.address,
                    to: bccSNARKAddress,
                    nonce: 0,
                    value: 0,
                    data,
                    gasLimit: 100000000,
                    chainId: 1337,
                }))
            }

            const startTime = new Date()
            let promise = signedTx.map((tx) => {
                return provider.broadcastTransaction(tx)
            })

            let d = await Promise.all(promise)

            let deltaTime = ((new Date()).getTime() - startTime.getTime()) / 1000

            console.log("Batch Size:", batchSize)
            console.log("Gas:", await bccSNARK.verify.estimateGas(mock.batch[i - 1].proof))

            console.log("TPS:", txCount / deltaTime)
            expect(true)
        })
    }
})
