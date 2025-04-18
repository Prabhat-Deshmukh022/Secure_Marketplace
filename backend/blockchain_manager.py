from web3 import Web3
import json
import os
from dotenv import load_dotenv

load_dotenv()

class BlockchainManager:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(os.getenv('WEB3_PROVIDER_URL')))
        
        # Load contract ABIs
        with open(r'contracts\SecureImageSharing.json') as f:
            self.image_sharing_abi = json.load(f)['abi']
        with open(r'contracts\KeyManagement.json') as f:
            self.key_management_abi = json.load(f)['abi']
            
        # Contract addresses with checksum
        self.image_sharing_address = Web3.to_checksum_address(os.getenv('IMAGE_SHARING_CONTRACT'))
        self.key_management_address = Web3.to_checksum_address(os.getenv('KEY_MANAGEMENT_CONTRACT'))
        
        # Initialize contracts
        self.image_sharing = self.w3.eth.contract(
            address=self.image_sharing_address,
            abi=self.image_sharing_abi
        )
        self.key_management = self.w3.eth.contract(
            address=self.key_management_address,
            abi=self.key_management_abi
        )

    def get_transaction_params(self, from_address, value=0):
        """Get standard transaction parameters"""
        return {
            'from': from_address,
            'nonce': self.w3.eth.get_transaction_count(from_address),
            'gas': 2000000,
            'gasPrice': self.w3.eth.gas_price,
            'value': value
        }

    def list_image(self, encrypted_image_cid, encrypted_keys_cid, price, from_address):
        """List an image for sale"""
        tx_params = self.get_transaction_params(from_address)
        
        return self.image_sharing.functions.listImage(
            encrypted_image_cid,
            encrypted_keys_cid,
            price
        ).build_transaction(tx_params)

    def purchase_image(self, image_id, price, from_address):
        """Purchase an image"""
        tx_params = self.get_transaction_params(from_address, value=price)
        
        return self.image_sharing.functions.purchaseImage(
            image_id
        ).build_transaction(tx_params)

    def register_public_key(self, public_key, from_address):
        """Register a user's public key"""
        tx_params = self.get_transaction_params(from_address)
        
        return self.key_management.functions.registerPublicKey(
            public_key
        ).build_transaction(tx_params)

    def store_encrypted_key(self, image_id, buyer_address, encrypted_key, from_address):
        """Store encrypted key for a buyer"""
        tx_params = self.get_transaction_params(from_address)
        
        return self.key_management.functions.storeEncryptedKey(
            image_id,
            buyer_address,
            encrypted_key
        ).build_transaction(tx_params)

    def get_public_key(self, address):
        """Get a user's registered public key"""
        return self.key_management.functions.userPublicKeys(address).call()

    def get_encrypted_key(self, image_id, buyer_address):
        """Get encrypted key for a specific buyer"""
        return self.image_sharing.functions.getBuyerEncryptedKey(image_id).call({
            'from': buyer_address
        })

    async def wait_for_transaction(self, tx_hash):
        """Wait for a transaction to be mined and return the receipt"""
        try:
            return await self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        except Exception as e:
            print(f"Transaction failed: {str(e)}")
            return None