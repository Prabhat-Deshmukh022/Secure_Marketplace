from web3 import Web3
import json
import os
from dotenv import load_dotenv
import time

load_dotenv(override=True)

private_key = os.getenv("METAMASK_PRIVATE_KEY")
WEB3_PROVIDER_URL = os.getenv("WEB3_PROVIDER_URL")
asset_ownership_contract_address = os.getenv("ASSET_OWNERSHIP_ADDRESS")
list_market_place_contract_address = os.getenv('MARKET_PLACE_ADDRESS')

w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER_URL))

with open(r'D:\6th_Semester\BC_PES1UG22CS419\Project\decentralized_storage_project\contracts\AssetOwnerShip.json') as f:
    asset_ownership_abi = json.load(f)

with open(r'D:\6th_Semester\BC_PES1UG22CS419\Project\decentralized_storage_project\contracts\ListMarketPlace.json') as f:
    list_market_place_abi = json.load(f)

class BlockchainManager:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(os.getenv('WEB3_PROVIDER_URL')))
        
        # Load contract ABIs
        with open(r'D:\6th_Semester\BC_PES1UG22CS419\Project\decentralized_storage_project\contracts\SecureImageSharing.json') as f:
            self.image_sharing_abi = json.load(f)['abi']
        with open(r'D:\6th_Semester\BC_PES1UG22CS419\Project\decentralized_storage_project\contracts\KeyManagement.json') as f:
            self.key_management_abi = json.load(f)['abi']
            
        # Contract addresses with checksum
        self.image_sharing_address = Web3.to_checksum_address(os.getenv('IMAGE_SHARING_CONTRACT'))
        self.key_management_address = Web3.to_checksum_address(os.getenv('KEY_MANAGEMENT_CONTRACT'))
        # Contract addresses (after deployment)
        self.image_sharing_address = os.getenv('IMAGE_SHARING_CONTRACT')
        self.key_management_address = os.getenv('KEY_MANAGEMENT_CONTRACT')

        self.account = w3.eth.account.from_key(private_key)

        self.list_market_place_contract = w3.eth.contract(
            address=Web3.to_checksum_address(list_market_place_contract_address),
            abi=list_market_place_abi
        )

        self.asset_ownership_contract = w3.eth.contract(
            address=Web3.to_checksum_address(asset_ownership_contract_address),
            abi=asset_ownership_abi
        )
        
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
        return txn
    
    def register_asset(self, ipfs_cid):
        nonce = w3.eth.get_transaction_count(self.account.address)
        
        # Build the transaction
        txn = self.asset_ownership_contract.functions.registerAsset(ipfs_cid).build_transaction({
            'from': self.account.address,
            'nonce': nonce,
            'gas': 300000,
            'gasPrice': w3.to_wei('20', 'gwei')
        })
        
        # Sign the transaction
        signed_txn = w3.eth.account.sign_transaction(txn, private_key=private_key)

        print(signed_txn)
        
        # Send the transaction and get the tx hash
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        
        # Return the transaction hash as a hexadecimal string
        return w3.to_hex(tx_hash)

    def transfer_ownership(self, asset_id, new_owner_address):
        nonce = w3.eth.get_transaction_count(self.account.address)
        txn = self.asset_ownership_contract.functions.transferOwnership(asset_id, new_owner_address).build_transaction({
            'from': self.account.address,
            'nonce': nonce,
            'gas': 300000,
            'gasPrice': w3.to_wei('20', 'gwei')
        })
        signed_txn = w3.eth.account.sign_transaction(txn, private_key=private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        return w3.to_hex(tx_hash)

    def get_owner(self, asset_id):
        return self.asset_ownership_contract.functions.getOwner(asset_id).call()

    def list_asset_for_sale(self,asset_id, price_wei):
        nonce = w3.eth.get_transaction_count(self.account.address)

        tx = self.list_market_place_contract.functions.listAssetForSale(asset_id, price_wei).build_transaction({
            'chainId': 11155111,  # Sepolia
            'gas': 200000,
            'gasPrice': w3.to_wei('20', 'gwei'),
            'nonce': nonce,
            # 'maxPriorityFeePerGas': w3.to_wei('2', 'gwei'),
            # 'maxFeePerGas': w3.to_wei('50', 'gwei'),
        })

        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        print(f"Listed asset {asset_id} for sale. TX: {tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt
    
    def buy_asset(self, asset_id,value):
        nonce = w3.eth.get_transaction_count(self.account.address)

        tx = self.list_market_place_contract.functions.buyAsset(asset_id).build_transaction({
            'chainId':11155111,
            'gas': 200000,
            'gasPrice': w3.to_wei('20', 'gwei'),
            'value':value,
            'nonce': nonce
        })

        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        print(f"Buy Asset {asset_id} bough. TX: {tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt
