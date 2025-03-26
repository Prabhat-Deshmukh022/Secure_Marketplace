from web3 import Web3 # type: ignore
import os

# Connect to Ethereum node (Infura/Alchemy)
w3 = Web3(Web3.HTTPProvider(os.getenv('WEB3_PROVIDER_URL')))

def verify_signature(wallet_address, signature):

    original_message = f"Auth for {wallet_address} (Testnet)"

    try:
        signer = w3.eth.account.recover_message(
            text=original_message, 
            signature=signature
        )
        return signer.lower() == wallet_address.lower()
    except:
        return False