// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// source: https://solidity-by-example.org/app/merkle-tree/

contract MerkleProof {
    //event hashfound(bytes32);

    function verify(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf,
        uint256 index
    ) public pure returns (bool) {
        bytes32 hash = leaf;


        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (index % 2 == 0) {
                hash = sha256(bytes.concat(hash, proofElement));
            } else {
                hash = sha256(bytes.concat(proofElement, hash));
            }
            //emit hashfound(hash);

            index = index / 2;
        }
        //emit hashfound(hash);

        return hash == root;
    }
}
