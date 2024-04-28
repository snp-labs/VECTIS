// SPDX-License-Identifier: LGPL-3.0+
pragma solidity >=0.8.0;
import "hardhat/console.sol";

library cpLinkVerifyBn128 {
    // Instance:
    //      uint256[(l+1)*2]   x    : G_1
    //      # of total (l+1) * 2

    // VerifyingKey :
    //      uint256[(l + 1)*4] C    : G_2
    //      uint256[4]         a    : G_2 (minus)
    //      # of total (l+1) * 4 + 4

    // Proof :
    //      uint256[2] pi    : G_1

    // Verification equation:
    //      x*C = pi*a
    //      x*c - pi*a = 0
    function _verifyLS(
        uint256[] storage vk, // ([C]_2, [a]_2) ∈ G2^{l+1} & G2
        uint256[] memory instance, // [x]_1 ∈ G1^{l+1} -> [cmList, cm']
        uint256[] memory proof // [π]_1 ∈ G1
    ) internal returns (bool) {
        uint256[1] memory out;
        bool success;

        uint256 vk_slot_num;
        uint256 vk_offset;
        uint256 a_offset;
        uint256 len = instance.length / 2; // l + 1
        uint256[] memory inputs = new uint256[](6 * (len + 1)); // [x, vk1, pf, -vk2] (x ∈ G1^l, vk ∈ G2^l, pf ∈ G1)

        assembly {
            let instance_i := add(instance, 0x20)
            mstore(inputs, vk.slot)
            vk_slot_num := keccak256(inputs, 0x20)

            for {
                let i := 0
            } lt(i, len) {
                i := add(i, 1)
            } {
                let offset := mul(i, 0xc0)
                vk_offset := add(vk_slot_num, mul(i, 4))

                mstore(
                    add(offset, inputs),
                    mload(add(mul(i, 0x40), instance_i))
                ) //cm[i].X
                mstore(
                    add(add(offset, 0x20), inputs),
                    mload(add(add(mul(i, 0x40), 0x20), instance_i))
                ) // cm[i].Y

                mstore(add(add(offset, 0x40), inputs), sload(vk_offset)) // C[i].X1
                mstore(add(add(offset, 0x60), inputs), sload(add(vk_offset, 1))) // C[i].Y1
                mstore(add(add(offset, 0x80), inputs), sload(add(vk_offset, 2))) // C[i].X2
                mstore(add(add(offset, 0xa0), inputs), sload(add(vk_offset, 3))) // C[i].Y2
            }

            let proof_i := add(proof, 0x20)
            let offset := mul(len, 0xc0)
            mstore(add(offset, inputs), mload(proof_i)) // π.X
            mstore(add(add(offset, 0x20), inputs), mload(add(proof_i, 0x20))) // π.Y

            a_offset := add(vk_slot_num, mul(len, 4))
            mstore(add(add(offset, 0x40), inputs), sload(a_offset)) // -a.X1
            mstore(add(add(offset, 0x60), inputs), sload(add(a_offset, 1))) // -a.Y1
            mstore(add(add(offset, 0x80), inputs), sload(add(a_offset, 2))) // -a.X2
            mstore(add(add(offset, 0xa0), inputs), sload(add(a_offset, 3))) // -a.Y2

            success := staticcall(
                sub(gas(), 2000),
                0x08, // Precompile address for Bn256 pairing
                inputs,
                mul(add(len, 1), 0xc0), // Input size
                out,
                0x20 // Output size
            )
        }
        // Pairing check e(x^t, vk_1) == e(pi, vk_1) where vk_1 = a*k
        require(success, "CPLink Pairing failed"); // Ensure pairing was successful

        return out[0] == 1; // Verification check
    }
}
