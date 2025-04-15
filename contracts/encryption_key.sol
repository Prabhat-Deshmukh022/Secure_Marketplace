// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract KeyManagement {
    struct EncryptionKey {
        bytes publicKey;      // Buyer's public key
        bytes encryptedKey;   // Encrypted secret key for the buyer
    }

    mapping(address => bytes) public userPublicKeys;
    mapping(uint256 => mapping(address => EncryptionKey)) private imageKeys;

    event PublicKeyRegistered(address indexed user, bytes publicKey);
    event EncryptedKeyStored(uint256 indexed imageId, address indexed buyer);

    function registerPublicKey(bytes calldata _publicKey) external {
        userPublicKeys[msg.sender] = _publicKey;
        emit PublicKeyRegistered(msg.sender, _publicKey);
    }

    function storeEncryptedKey(uint256 _imageId, address _buyer, bytes calldata _encryptedKey) external {
        require(userPublicKeys[_buyer].length > 0, "Buyer public key not registered");
        imageKeys[_imageId][_buyer] = EncryptionKey({
            publicKey: userPublicKeys[_buyer],
            encryptedKey: _encryptedKey
        });
        emit EncryptedKeyStored(_imageId, _buyer);
    }

    function getEncryptedKey(uint256 _imageId) external view returns (bytes memory) {
        return imageKeys[_imageId][msg.sender].encryptedKey;
    }
}