// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./encryption_key.sol";

contract SecureImageSharing {
    KeyManagement public keyManagementContract;
    uint256 public imageCounter;  // Made public for easier tracking
    
    struct Image {
        address owner;
        string encryptedImageCID;     // IPFS CID of encrypted image
        string encryptedKeysCID;      // IPFS CID containing encrypted keys for buyers
        uint256 price;
        bool isActive;
        mapping(address => bool) authorizedBuyers;
        mapping(address => string) buyerEncryptedKeys; // Store encrypted keys for each buyer
    }

    // Image ID => Image details
    mapping(uint256 => Image) public images;

    // Events
    event ImageListed(uint256 indexed imageId, address owner, uint256 price);
    event ImagePurchased(uint256 indexed imageId, address buyer);
    event ImageAccessRevoked(uint256 indexed imageId, address buyer);
    event PriceUpdated(uint256 indexed imageId, uint256 newPrice);
    event EncryptedKeyStored(uint256 indexed imageId, address indexed buyer);

    // Constructor to set KeyManagement contract
    constructor(address _keyManagementAddress) {
        keyManagementContract = KeyManagement(_keyManagementAddress);
        imageCounter = 0;  // Explicitly initialize counter
    }

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
        require(_price > 0, "Price must be greater than 0");
        require(bytes(_encryptedImageCID).length > 0, "Image CID required");
        
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
        
        // Verify buyer has registered their public key
        require(keyManagementContract.userPublicKeys(msg.sender).length > 0, "Register public key first");

        image.authorizedBuyers[msg.sender] = true;
        payable(image.owner).transfer(msg.value);

        emit ImagePurchased(_imageId, msg.sender);
    }

    function storeEncryptedKeyForBuyer(
        uint256 _imageId, 
        address _buyer, 
        string memory _encryptedKey
    ) external onlyImageOwner(_imageId) {
        require(images[_imageId].authorizedBuyers[_buyer], "Buyer not authorized");
        images[_imageId].buyerEncryptedKeys[_buyer] = _encryptedKey;
        emit EncryptedKeyStored(_imageId, _buyer);
    }

    function getBuyerEncryptedKey(uint256 _imageId) 
        external 
        view 
        returns (string memory) 
    {
        require(images[_imageId].authorizedBuyers[msg.sender], "Not authorized");
        return images[_imageId].buyerEncryptedKeys[msg.sender];
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