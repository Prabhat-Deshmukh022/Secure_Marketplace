from web3 import Web3
import json
import os
from dotenv import load_dotenv

# Load both .env and .env.test files
load_dotenv()
load_dotenv('.env.test')

def test_contracts():
    # Connect to the network
    w3 = Web3(Web3.HTTPProvider(os.getenv('WEB3_PROVIDER_URL')))
    
    # Get test wallet credentials from environment
    wallet_address = os.getenv('WALLET_ADDRESS')
    private_key = os.getenv('PRIVATE_KEY')
    
    print(f"Using wallet address: {wallet_address}")
    print(f"Connected to network: {w3.is_connected()}")
    
    if not wallet_address or not private_key:
        print("Error: Wallet credentials not found in environment variables")
        return
        
    # Load contract addresses
    image_sharing_address = os.getenv('IMAGE_SHARING_CONTRACT')
    key_management_address = os.getenv('KEY_MANAGEMENT_CONTRACT')
    
    print(f"Image Sharing Contract: {image_sharing_address}")
    print(f"Key Management Contract: {key_management_address}")
    
    # Load contract ABIs
    with open(r'contracts\SecureImageSharing.json') as f:
        image_sharing_abi = json.load(f)['abi']
    with open(r'contracts\KeyManagement.json') as f:
        key_management_abi = json.load(f)['abi']
    
    # Initialize contracts
    image_sharing = w3.eth.contract(address=image_sharing_address, abi=image_sharing_abi)
    key_management = w3.eth.contract(address=key_management_address, abi=key_management_abi)
    
    try:
        print("Testing SecureImageSharing Contract...")
        
        # Test listing an image
        nonce = w3.eth.get_transaction_count(wallet_address)
        tx = image_sharing.functions.listImage(
            "test_encrypted_image_cid",
            "test_encrypted_keys_cid",
            w3.to_wei(0.1, 'ether')
        ).build_transaction({
            'from': wallet_address,
            'nonce': nonce,
            'gas': 2000000,
            'gasPrice': w3.eth.gas_price
        })
        
        # Sign and send transaction
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)  # Changed from rawTransaction to raw_transaction
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        print(f"Image listed successfully! Transaction hash: {tx_hash.hex()}")
        
        print("\nTesting KeyManagement Contract...")
        
        # Test registering a public key
        nonce = w3.eth.get_transaction_count(wallet_address)
        tx = key_management.functions.registerPublicKey(
            b"test_public_key"
        ).build_transaction({
            'from': wallet_address,
            'nonce': nonce,
            'gas': 2000000,
            'gasPrice': w3.eth.gas_price
        })
        
        # Sign and send transaction
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)  # Changed here as well
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        print(f"Public key registered successfully! Transaction hash: {tx_hash.hex()}")
        
        print("\nAll tests passed! ✅")
        
    except Exception as e:
        print(f"Error during testing: {str(e)}")

if __name__ == "__main__":
    test_contracts()