// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Import Merkle tree related utilities for efficient data proofs
import "./Merkleizer.sol";
import "./MerkleTree.sol";

// Interface for interacting with the beacon roots storage contract (EIP-4788)
interface IBeaconRoots {
    // Retrieves the beacon root for a given timestamp
    function get(bytes32 timestamp) external view returns (bytes32);
}

// Contract for managing slash proofs of validators
contract FlashProofoor is Merkleizer, MerkleProof {
    uint public constant VALIDATOR_REGISTRY_LIMIT = 2**40;
    IBeaconRoots private beaconRootsContract = IBeaconRoots(0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02);
    uint256 private constant HISTORY_BUFFER_LENGTH = 8191;

    constructor(bytes32[] memory _zerohashes) Merkleizer(_zerohashes) {}

    function getRootFromTimestamp(uint256 timestamp) public view returns (bytes32) {
        require(timestamp != 0, "Timestamp cannot be zero");
        require((block.timestamp % HISTORY_BUFFER_LENGTH) == (timestamp % HISTORY_BUFFER_LENGTH), "Timestamp is out of range");
        return beaconRootsContract.get(bytes32(timestamp));
    }

    /**
     * @dev Verifies non-slashing proof of a validator using multiple Merkle proofs.
     * @param blockTimestamp The timestamp of the block related to the proof verification context.
     * @param validatorsProof Merkle proofs for the beaconState.validators list.
     * @param validatorsRoot The root hash of the beaconState.validators tree.
     * @param validatorIndex Index of the validator in the beaconState.validators list.
     * @param validatorChunks Array of data chunks corresponding to the validator's attributes.
     * @param proofBeaconState Merkle proof for the beacon state.
     * @param rootBeaconState The beacon state root used for verification.
     * @param proofBeaconBlock Merkle proof for the beacon block.
     * @return success True if all validations pass, otherwise reverts.
     */
    function verifyProof(
        uint256 blockTimestamp,
        bytes32[] memory validatorsProof,
        bytes32 validatorsRoot,
        uint256 validatorIndex,
        bytes32[] memory validatorChunks,
        bytes32[] memory proofBeaconState,
        bytes32 rootBeaconState,
        bytes32[] memory proofBeaconBlock
    ) public view returns (bool success) {
        // Ensure the validator has not been slashed (the slashing flag in the chunk must be zero)
        assert(validatorChunks[3] == bytes32(0));

        // Compute the hash tree root of the validator's chunks
        bytes32 valHashTreeRoot = merkleizeChunks(validatorChunks, 8);

        // Verify the validator's position and inclusion in the state's validator list
        require(verify(validatorsProof, validatorsRoot, valHashTreeRoot, validatorIndex), "Validator proof failed");

        // Calculate the validators hash tree root by mixing in the number of validators
        bytes32 stateValidatorsHashTreeRoot = mixInLength(validatorsRoot, validatorsProof.length);

        // Verify the hash tree root of validators against the beacon state root
        require(verify(proofBeaconState, rootBeaconState, stateValidatorsHashTreeRoot, 11), "BeaconState validation failed");

        // Additional verification against the beacon block could be re-enabled if needed
        require(verify(proofBeaconBlock, getRootFromTimestamp(blockTimestamp), rootBeaconState, 3));
        return true;
    }
}
