// SPDX-License-Identifier: LGPL-3.0+
pragma solidity >=0.8.0;

library cpLinkVerifyBn128 {
    function _verifyLS(
        // BN128에서 G1: uint256[2], G2: uint256[4]

        uint256[] storage vk,       // ([C]_2, [a]_2) ∈ G2^l & G2
        uint256[] memory instance,  // [x]_1 ∈ G1^l
        uint256[] memory proof      // [π]_1 ∈ G1
    ) internal returns (bool) {
        // // ct.length = 64 * 2 = 128 + cm in cc_groth.prove / proof.length = 2 / vk.length = 65 * 4 + 4(vk2)
        // require(proof.length == 4, "[Error] Invalid proof length"); 
        // require(
        //     vk.length == 2 * instance.length + 8, // vk는 G2라 vk 중 C의 길이는 instance의 2배 & [a]_2 ∈ G2 ...?
        //     "[Error] Invalid instance length"
        // );
        uint256[1] memory out;
        bool success;
        uint256 vk_slot_num;

        uint256 len = instance.length / 2;

        uint256[] memory inputs = new uint256[](6 * len + 6); // [x, vk1, pf, -vk2] (x ∈ G1^l, vk ∈ G2^l, pf ∈ G1)

        assembly {
            let proof_i := add(proof, 0x20)
            let instance_i := add(instance, 0x20)

            mstore(inputs, vk.slot)
            vk_slot_num := keccak256(inputs, 0x20)

            for {
                let i := 0
            } lt(i, sub(len, 1)) {
                i := add(i, 1)
            } {
                mstore(
                    add(mul(i, 0xc0), inputs),
                    mload(add(mul(i, 0x40), instance_i))
                ) // ct[i].X

                mstore(
                    add(add(mul(i, 0xc0), 0x20), inputs),
                    mload(add(add(mul(i, 0x40), 0x20), instance_i))
                ) // ct[i].Y

                mstore(
                    add(add(mul(i, 0xc0), 0x40), inputs),
                    sload(add(vk_slot_num, mul(i, 4)))
                ) // vk1[i].X1

                mstore(
                    add(add(mul(i, 0xc0), 0x60), inputs),
                    sload(add(vk_slot_num, add(mul(i, 4), 1)))
                ) // vk1[i].Y2

                mstore(
                    add(add(mul(i, 0xc0), 0x80), inputs),
                    sload(add(vk_slot_num, add(mul(i, 4), 2)))
                ) // vk1[i].Y3

                mstore(
                    add(add(mul(i, 0xc0), 0xa0), inputs),
                    sload(add(vk_slot_num, add(mul(i, 4), 3)))
                ) // vk1[i].Y4
            }

            mstore(sub(add(mul(len, 0xc0), inputs), 0xc0), mload(proof_i)) // cm.X

            mstore(
                sub(add(mul(len, 0xc0), inputs), 0xa0),
                mload(add(proof_i, 0x20))
            ) // cm.Y

            mstore(
                sub(add(mul(len, 0xc0), inputs), 0x80),
                sload(add(vk_slot_num, sub(mul(len, 4), 4)))
            ) // vk1[last].X1

            mstore(
                sub(add(mul(len, 0xc0), inputs), 0x60),
                sload(add(vk_slot_num, sub(mul(len, 4), 3)))
            ) // vk1[last].Y2

            mstore(
                sub(add(mul(len, 0xc0), inputs), 0x40),
                sload(add(vk_slot_num, sub(mul(len, 4), 2)))
            ) //vk1[last].Y3

            mstore(
                sub(add(mul(len, 0xc0), inputs), 0x20),
                sload(add(vk_slot_num, sub(mul(len, 4), 1)))
            ) //vk1[last].Y4

            mstore(add(mul(len, 0xc0), inputs), mload(add(proof_i, 0x40))) // pi.X

            mstore(
                add(add(mul(len, 0xc0), 0x20), inputs),
                mload(add(proof_i, 0x60))
            ) // pi.Y

            mstore(
                add(add(mul(len, 0xc0), 0x40), inputs),
                sload(add(vk_slot_num, mul(len, 4)))
            ) // -vk2.X1

            mstore(
                add(add(mul(len, 0xc0), 0x60), inputs),
                sload(add(vk_slot_num, add(mul(len, 4), 1)))
            ) // -vk2.Y2

            mstore(
                add(add(mul(len, 0xc0), 0x80), inputs),
                sload(add(vk_slot_num, add(mul(len, 4), 2)))
            ) // -vk2.Y3

            mstore(
                add(add(mul(len, 0xc0), 0xa0), inputs),
                sload(add(vk_slot_num, add(mul(len, 4), 3)))
            ) // -vk2.Y4

            success := call(
                sub(gas(), 2000),
                0x08, 
                0,
                inputs,
                mul(add(len, 1), 0xc0),
                out,
                0x20
            ) // Pairing check e(x^t, vk_1) == e(pi, vk_1) where vk_1 = a*k
        }
        require(!success, "Pairing Failed");

        return out[0] == 0;
    }
}