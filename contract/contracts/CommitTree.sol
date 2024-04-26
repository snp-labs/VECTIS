// SPDX-License-Identifier: LGPL-3.0+
pragma solidity >=0.8.0;

import "./Bn128.sol";

library CommitTree {
    function calculateEvenIndexedNodesSum(
        uint256 scalar,
        uint256 size,
        Bn128.G1Point[] memory nodes
    ) internal view returns (Bn128.G1Point memory sum) {
        unchecked {
            sum = Bn128.G1Point({X: 0, Y: 0});
            for (uint32 i = 1; i < size; ) {
                sum = Bn128.add(sum, nodes[i]);
                i += 2;
            }

            delete nodes;

            return Bn128.mul(scalar, sum);
        }
    }

    function layerWiseMultiplication(
        uint256 r,
        Bn128.G1Point[] memory leafNodes
    ) internal view returns (Bn128.G1Point memory result) {
        uint256 layerSize = leafNodes.length;
        result = calculateEvenIndexedNodesSum(r, layerSize, leafNodes);
        result = Bn128.add(result, leafNodes[0]);
        uint256 currentScalar = r;

        delete r; // unused memory free

        layerSize /= 2;

        for (; layerSize >= 1; ) {
            unchecked {
                for (uint32 i = 0; i < layerSize; ) {
                    leafNodes[i] = Bn128.add(
                        leafNodes[2 * i],
                        leafNodes[2 * i + 1]
                    );
                    delete leafNodes[2 * i]; // unused memory free
                    delete leafNodes[2 * i + 1]; // unused memory free
                    ++i;
                }
            }
            currentScalar = mulmod(
                currentScalar,
                currentScalar,
                Bn128.curveOrder
            );

            unchecked {
                result = Bn128.add(
                    result,
                    calculateEvenIndexedNodesSum(
                        currentScalar,
                        layerSize,
                        leafNodes
                    )
                );

                layerSize /= 2;
            }
        }
    }
}
