// SPDX-License-Identifier: LGPL-3.0+
pragma solidity >=0.8.0;

import "./cpLinkVerifyBn128.sol";

contract cpLinkVerify {
    uint256[] vk_link;

    constructor(uint256[] memory _vk_link) {
        vk_link = _vk_link;
    }

    function verify(
        uint256[] memory instance,
        uint256[] memory proof
    ) public returns (bool) {
        return cpLinkVerifyBn128._verifyLS(vk_link, instance, proof);
    }
}
