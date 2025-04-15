// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SecureImageSharing.sol";
import "./KeyManagement.sol";

contract ImageSharingRegistry {
    SecureImageSharing public imageSharing;
    KeyManagement public keyManagement;
    address public admin;

    constructor() {
        admin = msg.sender;
        imageSharing = new SecureImageSharing();
        keyManagement = new KeyManagement();
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    function upgradeImageSharing(address _newContract) external onlyAdmin {
        imageSharing = SecureImageSharing(_newContract);
    }

    function upgradeKeyManagement(address _newContract) external onlyAdmin {
        keyManagement = KeyManagement(_newContract);
    }
}