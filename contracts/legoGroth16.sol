// SPDX-License-Identifier: LGPL-3.0+
pragma solidity >=0.8.0;

import "./cpLinkVerifyBn128.sol";
import "./ccGroth16VerifyBn128.sol";
import "hardhat/console.sol";

contract LegoGroth16 {
    uint256[] vk_link;
    uint256[] vk_groth;
    uint256 private batch_size;

    constructor(
        uint256[] memory _vk_groth,
        uint256[] memory _vk_link,
        uint256 _batch_size
    ) {
        require(_vk_groth.length == 16, "Invalid ccGroth16 verification key");
        require(
            _vk_link.length == (4 * (_batch_size + 1) + 4), // C = l+1, a = 1
            "Invalid Link Key"
        );

        vk_groth = _vk_groth;
        vk_link = _vk_link;
        batch_size = _batch_size;
    }

    function verify(
        uint256[] memory instance,
        uint256[] memory proof_groth,
        uint256[] memory proof_link
    ) public returns (bool) {
        require(
            proof_groth.length == 10,
            "Error: Invalid ccGroth16 proof length"
        );
        require(proof_link.length == 2, "Error: Invalid link proof length");
        require(
            instance.length == (2 * batch_size) + 2,
            "Error: Invalid instance length"
        );

        require(
            ccGroth16VerifyBn128._verify(vk_groth, proof_groth),
            "ccGroth16 Failed"
        );

        require(
            cpLinkVerifyBn128._verifyLS(vk_link, instance, proof_link),
            "Link Failed"
        );

        return true;
    }
}
