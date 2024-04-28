// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;


contract Merkleizer {
    // Assuming zerohashes are precomputed zero values hashed at each layer
    bytes32[] public zerohashes;

    constructor(bytes32[] memory _zerohashes) {
        zerohashes = _zerohashes;
    }

    function hash(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return sha256(abi.encodePacked(a, b));
    }

    function merkleizeChunks(bytes32[] memory chunks, uint256 limit) public view returns (bytes32) {
        if (limit == 0) {
            return zerohashes[0];
        }

        uint256 count = chunks.length;
        require(count <= limit, "Input size exceeds limit");

        uint256 depth = bitLength(count - 1);
        uint256 maxDepth = bitLength(limit - 1);

        bytes32[] memory tmp = new bytes32[](maxDepth + 1);
        for (uint256 i = 0; i < count; ++i) {
            merge(chunks[i], i, tmp, count, depth);
        }

        // Complement with zero hash if count is not a power of two
        if (count & (count - 1) != 0) {
            merge(zerohashes[0], count, tmp, count, depth);
        }

        // Fill up remaining depths with zero-hashes
        for (uint256 j = depth; j < maxDepth; ++j) {
            tmp[j + 1] = hash(tmp[j], zerohashes[j]);
        }

        return tmp[maxDepth];
    }

    function merge(bytes32 h, uint256 i, bytes32[] memory tmp, uint256 count, uint256 depth) private view {
        uint256 j = 0;
        while (true) {
            if ((i & (1 << j)) == 0) {
                if (i == count && j < depth) {
                    h = hash(h, zerohashes[j]);
                } else {
                    break;
                }
            } else {
                h = hash(tmp[j], h);
            }
            j++;
        }
        tmp[j] = h;
    }

    function bitLength(uint256 x) private pure returns (uint256) {
        uint256 len = 0;
        while (x > 0) {
            len++;
            x >>= 1;
        }
        return len;
    }

    function toLittleEndian(uint256 v) public pure returns (bytes32) {
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8)
            | ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16)
            | ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32)
            | ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64)
            | ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
        v = (v >> 128) | (v << 128);
        return bytes32(v);
    }

    // Function to mix in the length of the list into the Merkle root using little-endian encoding
    function mixInLength(bytes32 root, uint256 length) public pure returns (bytes32) {
        bytes32 littleEndianLength = toLittleEndian(length);
        return sha256(abi.encodePacked(root, littleEndianLength));
    }   
}
