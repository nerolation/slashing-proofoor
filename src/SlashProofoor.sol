// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Merkleizer.sol";
import "./MerkleTree.sol";

contract SlashSplash is Merkleizer, MerkleProof {

    uint VALIDATOR_REGISTRY_LIMIT = 2**40;

    constructor(bytes32[] memory _zerohashes) Merkleizer(_zerohashes) {}

     function verifyProof(
        uint256 blocknumber,
        bytes32[] memory validators_proof,
        bytes32 validators_root,
        uint256 validators_index,
        bytes32[] memory validator_chunks,
        bytes32 stateRoot,
        bytes32[] memory proof_beaconstate,
        bytes32 root_beaconstate,
        bytes32[] memory proof_beaconblock
    ) public view returns (bool success) {
        // check that the user is proofing not being slashed
        assert(validator_chunks[3] == bytes32(0));

        // take validators inputs and compute hash_tree_root of validator
        bytes32 val_hash_tree_root = merkleizeChunks(validator_chunks, 8);

        // input the root of the validators element in the BeaconState (without mxing in the length yet) and 
        // verify that the validator, derived from the just computed val_hash_tree_root,
        // is in the specified position in the validators list
        require(verify(validators_proof, validators_root, val_hash_tree_root, validators_index));

        // mix in the length to beaconState.validators root to get the hash_tree_root
        bytes32 state_validators_hash_tree_root = mixInLength(validators_root, validators_proof.length);

        // verify that the derived validators are in the beaconstate
        require(verify(proof_beaconstate, root_beaconstate, state_validators_hash_tree_root, 11));

        // verify that the hash_tree_root of the beacon state is inside the specified beacon block

        //require(verify(proof_beaconblock, header.parent_beacon_block_root, root_beaconstate, 3));
        return success;
    }

}
