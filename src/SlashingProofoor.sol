// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Import Merkle tree related utilities for efficient data proofs
import "./Merkleizer.sol";
import "./MerkleTree.sol";

// Contract for managing slash proofs of validators
contract SlashingProofoor is Merkleizer, MerkleProof {
    uint public constant VALIDATOR_REGISTRY_LIMIT = 2**40;
    address beaconRootsContract = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
    uint256 private constant HISTORY_BUFFER_LENGTH = 8191;

    event Debug(bytes32 _hash);

    constructor(bytes32[] memory _zerohashes) Merkleizer(_zerohashes) {}

    function getRootFromTimestamp(uint256 timestamp) public returns (bytes32) {
        require(timestamp != 0, "Timestamp cannot be zero");
        require((block.timestamp % HISTORY_BUFFER_LENGTH) == (timestamp % HISTORY_BUFFER_LENGTH), "Timestamp is out of range");
        (bool ret, bytes memory data) = beaconRootsContract.call(bytes.concat(bytes32(timestamp)));
        return bytes32(data);
    }

    /**
     * @dev Verifies non-slashing proof of a validator using multiple Merkle proofs.
     * @param blockTimestamp The timestamp of the block related to the proof verification context.
     * @param validatorChunks Array of data chunks corresponding to the validator's attributes.
     * @param validatorsProof Merkle proofs for the beaconState.validators list.
     * @param validatorIndex Index of the validator in the beaconState.validators list.
     * @param validatorsRoot The root hash of the beaconState.validators tree.
     * @param beaconStateProof Merkle proof for the beacon state.
     * @param nr_validators Number of validators in beacon state.
     * @param beaconStateRoot The beacon state root used for verification.
     * @param beaconBlockProof Merkle proof for the beacon block.
     * @return success True if all validations pass, otherwise reverts.
     */
    function verifyProof(
        uint256 blockTimestamp,
        bytes32[] memory validatorChunks,
        bytes32[] memory validatorsProof,
        uint256 validatorIndex,
        bytes32 validatorsRoot,
        uint256 nr_validators,
        bytes32[] memory beaconStateProof,
        bytes32 beaconStateRoot,
        bytes32[] memory beaconBlockProof
    ) public returns (bool success) {
        // Ensure the validator has not been slashed (the slashing flag in the chunk must be zero)
        require(validatorChunks[3] != bytes32(0), "Provided validator chunks indicate non-slashed validator");

        // Compute the hash tree root of the validator's chunks
        bytes32 valHashTreeRoot = merkleizeChunks(validatorChunks, 8);
        emit Debug(valHashTreeRoot);

        // Verify the validator's position and inclusion in the state's validator list
        require(verify(validatorsProof, validatorsRoot, valHashTreeRoot, validatorIndex), "Validator proof failed");

        // Calculate the validators hash tree root by mixing in the number of validators
        bytes32 stateValidatorsHashTreeRoot = mixInLength(validatorsRoot, nr_validators);
        emit Debug(stateValidatorsHashTreeRoot);

        // Verify the hash tree root of validators against the beacon state root
        require(verify(beaconStateProof, beaconStateRoot, stateValidatorsHashTreeRoot, 11), "BeaconState validation failed");

        // Additional verification against the beacon block could be re-enabled if needed
        require(verify(beaconBlockProof, getRootFromTimestamp(blockTimestamp), beaconStateRoot, 3));
        return true;
    }
}
