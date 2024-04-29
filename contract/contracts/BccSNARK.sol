// SPDX-License-Identifier: LGPL-3.0+
pragma solidity ^0.8.0;

import "./Bn128.sol";
import "./CommitTree.sol";
import "./ccGroth16VerifyBn128.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "hardhat/console.sol";

// import "@openzeppelin/contracts/access/AccessControl.sol";

contract BccSNARK {
    uint256[] private vk;
    Bn128.G1Point[] public listCM;
    uint256 challenge;

    // mock data
    Bn128.G1Point public g =
        Bn128.G1Point(
            14503582948638727084502759502994279163222108009153332193323880774870858770036,
            14591073697149083878648039582988519715702082715595253321641344990827767900840
        );

    Bn128.G2Point public h =
        Bn128.G2Point(
            598134931736234900467939765247253867024649852659867435941841640401379183793,
            15738093922633515834030325254155237326871962654522925907436502223905379545674,
            14919326580790664754690105099088381271955422709270798132195168786371643203877,
            18145374548316659229864951505936810867524529744013061164160124189068667257707
        );

    constructor(uint256[] memory _vk, uint256 batch_size) {
        vk = _vk;

        for (uint256 i = 0; i < batch_size; i++)
            listCM.push(g);

        challenge = 0;
    }

    function verify(uint256[] memory proof) public returns (bool) {
        require(proof.length == 10, Strings.toString(proof.length));
        Bn128.G1Point memory D2 = Bn128.G1Point({X: proof[8], Y: proof[9]});

        // bytes memory transcript = abi.encodePacked(listCM[0].X, listCM[0].Y);
        // for (uint256 i = 1; i < listCM.length; i++)
        //     transcript = abi.encodePacked(transcript, listCM[i].X, listCM[i].Y);
        bytes memory transcript = abi.encodePacked(D2.X, D2.Y);
        uint256 tau = uint256(keccak256(transcript)) % Bn128.curveOrder;

        Bn128.G1Point memory D1 = CommitTree.layerWiseMultiplication(
            tau,
            listCM
        );

        Bn128.G1Point memory D3 = Bn128.mul(
            tau,
            Bn128.G1Point({X: vk[16], Y: vk[17]})
        ); // O

        delete tau;

        Bn128.G1Point memory D = Bn128.add(Bn128.add(D1, D2), D3);
        proof[8] = D.X;
        proof[9] = D.Y;

        delete D;
        delete D1;
        delete D2;
        delete D3;

        require(ccGroth16VerifyBn128._verify(vk, proof), "verify is failed");

        delete proof;
        return true;
    }

    function chl(uint256 prev, uint256 curr) public {
        require(prev == challenge, "prev challenge diff");
        challenge = curr;
    }
}
