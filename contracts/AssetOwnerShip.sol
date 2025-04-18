// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AssetOwnership {

    struct Asset {
        address owner;
        string ipfsCID;
    }

    mapping(uint256 => Asset) public assets;

    event AssetRegistered(uint256 indexed assetId, address indexed owner, string ipfsCID);
    event OwnershipTransferred(uint256 indexed assetId, address indexed from, address indexed to);

    function registerAsset(string calldata ipfsCID) external returns (uint256) {
        uint256 assetId = uint256(keccak256(abi.encodePacked(ipfsCID)));
        require(assets[assetId].owner == address(0), "Asset already registered.");

        assets[assetId] = Asset(msg.sender, ipfsCID);
        emit AssetRegistered(assetId, msg.sender, ipfsCID);

        return assetId;
    }

    function transferOwnership(uint256 assetId, address newOwner) external {
        require(assets[assetId].owner != address(0), "Asset does not exist.");
        // require(msg.sender == assets[assetId].owner, "You are not authorized to transfer this asset.");

        address previousOwner = assets[assetId].owner;
        assets[assetId].owner = newOwner;

        emit OwnershipTransferred(assetId, previousOwner, newOwner);
    }

    function getOwner(uint256 assetId) external view returns (address) {
        return assets[assetId].owner;
    }
}
