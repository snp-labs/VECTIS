// SPDX-License-Identifier: LGPL-3.0+
pragma solidity >=0.8.0;

import "./Bn128.sol";
import "hardhat/console.sol";

library CommitTree {
    function layerWiseMultiplication(
        uint256 r,
        Bn128.G1Point[] memory leafNodes
    ) internal view returns (Bn128.G1Point memory result) {
        uint256 coeff = r;
        uint256 order = Bn128.curveOrder;
        uint256 layerSize = leafNodes.length;
        uint256[4] memory io;
        delete r;

        result.X = leafNodes[0].X;
        result.Y = leafNodes[0].Y;

        assembly {
            let success := 0
            let ptr := 0 // pointer of leafNodes
            for {

            } gt(layerSize, 1) {
                coeff := mulmod(coeff, coeff, order)
            } {
                /* odd index sum */
                ptr := add(leafNodes, 0x40) // len, [p(x, y), ...]
                // initial G1 Point (0, 0)
                mstore(io, 0x00)
                mstore(add(io, 0x20), 0x00)
                for {
                    let end := add(ptr, shl(0x05, sub(layerSize, 0x01)))
                } lt(ptr, end) {
                    ptr := add(ptr, 0x40)
                } {
                    // Store p.x and p.y in memory
                    let p := mload(ptr)
                    mstore(add(io, 0x40), mload(p))
                    mstore(add(io, 0x60), mload(add(p, 0x20)))

                    success := staticcall(gas(), 0x06, io, 0x80, io, 0x40)
                }

                /* mul coeff */
                // Store scalar in memory
                mstore(add(io, 0x40), coeff)

                // Precompiled contract (0x07)
                // point.x, point.y, scalar
                success := staticcall(gas(), 0x07, io, 0x60, io, 0x40)

                /* sum depth result */
                mstore(add(io, 0x40), mload(result))
                mstore(add(io, 0x60), mload(add(result, 0x20)))

                success := staticcall(gas(), 0x06, io, 0x80, result, 0x40)

                /* make parent */
                layerSize := shr(0x01, layerSize)

                ptr := add(leafNodes, 0x20) // first 32 bytes is array length
                for {
                    let r_ptr := 0 // relative child pointer
                    let end := add(ptr, shl(0x05, layerSize))
                } lt(ptr, end) {
                    ptr := add(ptr, 0x20)
                    r_ptr := add(r_ptr, 0x20)
                } {
                    let parent := mload(ptr)
                    let left := mload(add(ptr, r_ptr))
                    let right := mload(add(ptr, add(r_ptr, 0x20)))
                    mstore(io, mload(left))
                    mstore(add(io, 0x20), mload(add(left, 0x20)))
                    mstore(add(io, 0x40), mload(right))
                    mstore(add(io, 0x60), mload(add(right, 0x20)))

                    success := staticcall(gas(), 0x06, io, 0x80, parent, 0x40)
                }
            }
        }
        delete io;
    }
}
