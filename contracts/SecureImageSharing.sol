// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureImageSharing {
    struct Image {
        address owner;
        string encryptedImageCID;     // IPFS CID of encrypted image
        string encryptedKeysCID;      // IPFS CID containing encrypted keys for buyers
        uint256 price;
        bool isActive;
        mapping(address => bool) authorizedBuyers;
    }

    // Image ID => Image details
    mapping(uint256 => Image) public images;
    uint256 private imageCounter;

    // Events
    event ImageListed(uint256 indexed imageId, address owner, uint256 price);
    event ImagePurchased(uint256 indexed imageId, address buyer);
    event ImageAccessRevoked(uint256 indexed imageId, address buyer);
    event PriceUpdated(uint256 indexed imageId, uint256 newPrice);

    modifier onlyImageOwner(uint256 _imageId) {
        require(images[_imageId].owner == msg.sender, "Not the image owner");
        _;
    }

    modifier imageExists(uint256 _imageId) {
        require(_imageId <= imageCounter && _imageId > 0, "Image does not exist");
        _;
    }

    function listImage(string memory _encryptedImageCID, string memory _encryptedKeysCID, uint256 _price) 
        external 
        returns (uint256) 
    {
        imageCounter++;
        Image storage newImage = images[imageCounter];
        newImage.owner = msg.sender;
        newImage.encryptedImageCID = _encryptedImageCID;
        newImage.encryptedKeysCID = _encryptedKeysCID;
        newImage.price = _price;
        newImage.isActive = true;

        emit ImageListed(imageCounter, msg.sender, _price);
        return imageCounter;
    }

    function purchaseImage(uint256 _imageId) external payable imageExists(_imageId) {
        Image storage image = images[_imageId];
        require(image.isActive, "Image not available");
        require(msg.value >= image.price, "Insufficient payment");
        require(!image.authorizedBuyers[msg.sender], "Already purchased");

        image.authorizedBuyers[msg.sender] = true;
        payable(image.owner).transfer(msg.value);

        emit ImagePurchased(_imageId, msg.sender);
    }

    function getImageDetails(uint256 _imageId) external view imageExists(_imageId) 
        returns (
            address owner,
            string memory encryptedImageCID,
            string memory encryptedKeysCID,
            uint256 price,
            bool isActive,
            bool hasPurchased
        ) 
    {
        Image storage image = images[_imageId];
        return (
            image.owner,
            image.encryptedImageCID,
            image.encryptedKeysCID,
            image.price,
            image.isActive,
            image.authorizedBuyers[msg.sender]
        );
    }

    function updatePrice(uint256 _imageId, uint256 _newPrice) 
        external 
        onlyImageOwner(_imageId) 
    {
        images[_imageId].price = _newPrice;
        emit PriceUpdated(_imageId, _newPrice);
    }

    function deactivateImage(uint256 _imageId) 
        external 
        onlyImageOwner(_imageId) 
    {
        images[_imageId].isActive = false;
    }

    function reactivateImage(uint256 _imageId) 
        external 
        onlyImageOwner(_imageId) 
    {
        images[_imageId].isActive = true;
    }
}