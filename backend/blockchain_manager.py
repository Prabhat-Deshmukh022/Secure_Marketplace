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
            
        # Contract addresses (after deployment)
        self.image_sharing_address = os.getenv('IMAGE_SHARING_CONTRACT')
        self.key_management_address = os.getenv('KEY_MANAGEMENT_CONTRACT')
        
        # Initialize contracts
        self.image_sharing = self.w3.eth.contract(
            address=self.image_sharing_address,
            abi=self.image_sharing_abi
        )
        self.key_management = self.w3.eth.contract(
            address=self.key_management_address,
            abi=self.key_management_abi
        )

    def list_image(self, encrypted_image_cid, encrypted_keys_cid, price, from_address):
        nonce = self.w3.eth.get_transaction_count(from_address)
        txn = self.image_sharing.functions.listImage(
            encrypted_image_cid,
            encrypted_keys_cid,
            price
        ).build_transaction({
            'from': from_address,
            'nonce': nonce,
            'gas': 2000000
        })
        return txn

    def purchase_image(self, image_id, price, from_address):
        nonce = self.w3.eth.get_transaction_count(from_address)
        txn = self.image_sharing.functions.purchaseImage(image_id).build_transaction({
            'from': from_address,
            'value': price,
            'nonce': nonce,
            'gas': 2000000
        })
        return txn

    def store_encrypted_key(self, image_id, buyer_address, encrypted_key, from_address):
        nonce = self.w3.eth.get_transaction_count(from_address)
        txn = self.key_management.functions.storeEncryptedKey(
            image_id,
            buyer_address,
            encrypted_key
        ).build_transaction({
            'from': from_address,
            'nonce': nonce,
            'gas': 2000000
        })
        return txn