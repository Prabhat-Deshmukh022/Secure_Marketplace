// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IAssetOwnership {
    function getOwner(uint256 assetId) external view returns (address);
}

contract Marketplace {

    IAssetOwnership public assetOwnership;

    struct Listing {
        uint256 assetId;
        uint256 price;
        bool isListed;
    }

    mapping(uint256 => Listing) public listings;

    event AssetListed(uint256 assetId, address indexed seller, uint256 price);
    event AssetPurchased(uint256 assetId, address indexed buyer, address indexed seller, uint256 price);

    constructor(address _assetOwnershipAddress) {
        assetOwnership = IAssetOwnership(_assetOwnershipAddress);
    }

    function listAssetForSale(uint256 assetId, uint256 price) external {
        address currentOwner = assetOwnership.getOwner(assetId);
        require(msg.sender == currentOwner, "You are not the owner of this asset.");
        require(price > 0, "Price must be greater than zero.");

        listings[assetId] = Listing(assetId, price, true);
        emit AssetListed(assetId, msg.sender, price);
    }

    function buyAsset(uint256 assetId) external payable {
        Listing memory listing = listings[assetId];
        require(listing.isListed, "Asset is not for sale.");
        require(msg.value == listing.price, "Incorrect payment amount.");

        address seller = assetOwnership.getOwner(assetId);
        require(seller != address(0), "Asset has invalid owner.");
        require(seller != msg.sender, "You cannot buy your own asset.");

        listings[assetId].isListed = false;

        // Transfer payment
        payable(seller).transfer(msg.value);

        emit AssetPurchased(assetId, msg.sender, seller, listing.price);

        // Ownership transfer must happen as a separate transaction after payment.
    }
}
