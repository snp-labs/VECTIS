// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity >=0.8.0;

/// Several pairing-related utility functions.
///
/// Precompiled contract details (bn256Add, bn256ScalarMul, bn256Pairing) can
/// be found at the following links:
/// implementations:
///   https://github.com/ethereum/go-ethereum/blob/master/core/vm/contracts.go
/// gas and costs:
// solhint-disable-next-line
///   https://github.com/ethereum/go-ethereum/blob/master/params/protocol_params.go
library Bn128 {
    uint256 internal constant curveOrder =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // The prime q in the base field F_q for G1
    uint256 internal constant q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256 X0;
        uint256 X1;
        uint256 Y0;
        uint256 Y1;
    }

    // Return the sum of two points of G1
    function add(
        G1Point memory p1,
        G1Point memory p2
    ) internal view returns (G1Point memory result) {
        assembly {
            // Free memory pointer
            let ptr := mload(0x40)

            // Store p1.x and p1.y in memory
            mstore(ptr, mload(p1))
            mstore(add(ptr, 0x20), mload(add(p1, 0x20)))

            // Store p2.x and p2.y in memory
            mstore(add(ptr, 0x40), mload(p2))
            mstore(add(ptr, 0x60), mload(add(p2, 0x20)))

            // Precompiled contract (0x06)
            // p1.x, p1.y, p2.x, p2.y
            let success := staticcall(gas(), 0x06, ptr, 0x80, ptr, 0x40)

            // Load the result
            mstore(result, mload(ptr))
            mstore(add(result, 0x20), mload(add(ptr, 0x20)))
        }
    }

    // Return the product of a point on G1 and a scalar, i.e.
    // p == p.mul(1) and p.add(p) == p.mul(2) for all points p.
    function mul(
        uint256 scalar,
        G1Point memory point
    ) internal view returns (G1Point memory result) {
        assembly {
            // Free memory pointer
            let ptr := mload(0x40)

            // Store point.x and point.y in memory
            mstore(ptr, mload(point))
            mstore(add(ptr, 0x20), mload(add(point, 0x20)))

            // Store scalar in memory
            mstore(add(ptr, 0x40), scalar)

            // Precompiled contract (0x07)
            // point.x, point.y, scalar
            let success := staticcall(gas(), 0x07, ptr, 0x60, ptr, 0x40)

            // Load the result
            mstore(result, mload(ptr))
            mstore(add(result, 0x20), mload(add(ptr, 0x20)))
        }
    }

    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        }
        return G1Point(p.X, q - (p.Y % q));
    }
}
