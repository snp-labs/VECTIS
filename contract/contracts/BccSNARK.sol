// SPDX-License-Identifier: LGPL-3.0+
pragma solidity ^0.8.0;

import "./Bn128.sol";
import "./CommitTree.sol";
import "./ccGroth16VerifyBn128.sol";
import "hardhat/console.sol";

contract BccSNARK {
    uint256[] private vk;
    Bn128.G1Point[] public listCM;
    uint256 challenge;

    // mock data
    Bn128.G1Point public g =
        Bn128.G1Point(
            7519601383266717548710709804083595600366561084448799853543551610498604941811,
            15895479664152765121591734832175585709898926337923093690342838808429524790392
        );

    Bn128.G2Point public h =
        Bn128.G2Point(
            598134931736234900467939765247253867024649852659867435941841640401379183793,
            15738093922633515834030325254155237326871962654522925907436502223905379545674,
            14919326580790664754690105099088381271955422709270798132195168786371643203877,
            18145374548316659229864951505936810867524529744013061164160124189068667257707
        );

    constructor(
        uint256[] memory _cm,
        uint256[] memory _vk,
        uint256 batch_size
    ) {
        require(_vk.length == 18, "Invalid Verifying Key Size");
        vk = _vk;

        for (uint256 i = 0; i < batch_size; i++)
            listCM.push(Bn128.G1Point(_cm[0], _cm[1]));
    }

    function verify(uint256[] memory proof) public returns (bool) {
        require(proof.length == 10, "Invalid Proof Size");
        Bn128.G1Point memory D2 = Bn128.G1Point({X: proof[8], Y: proof[9]});

        // uint256 ord = Bn128.curveOrder;
        // uint256 tau;
        // assembly {
        //     let transcript := mload(0x40)
        //     mstore(transcript, mload(D2))
        //     mstore(add(transcript, 0x20), mload(add(D2, 0x20)))
        //     tau := mod(keccak256(transcript, 0x40), ord)
        // }

        uint _slot;
        assembly {
            _slot := listCM.slot
        }
        bytes32 lst = keccak256(abi.encode(_slot));
        uint256 len = listCM.length;
        uint256 ord = Bn128.curveOrder;
        uint256 tau;
        assembly {
            let transcript := mload(0x40)
            let trs := transcript
            for {
                let ptr := lst
                let end := add(lst, shl(0x01, len))
            } lt(ptr, end) {
                ptr := add(ptr, 0x02)
                trs := add(trs, 0x40)
            } {
                mstore(trs, sload(ptr))
                mstore(add(trs, 0x20), sload(add(ptr, 0x01)))
            }
            mstore(trs, mload(D2))
            mstore(add(trs, 0x20), mload(add(D2, 0x20)))
            trs := add(trs, 0x40)
            tau := mod(keccak256(transcript, sub(trs, transcript)), ord)
        }

        uint256[] memory tauList = new uint256[](listCM.length);
        tauList[0] = 1;
        assembly {
            for {
                let ptr := add(tauList, 0x40)
                let end := add(ptr, shl(0x05, sub(len, 1)))
            } lt(ptr, end) {
                ptr := add(ptr, 0x20)
            } {
                mstore(ptr, mulmod(mload(sub(ptr, 0x20)), tau, ord))
            }
        }

        // Bn128.G1Point memory D1 = Bn128.smsm(tauList, listCM);
        Bn128.G1Point memory D1 = Bn128.msm(tauList, listCM);

        delete tauList;

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
}
