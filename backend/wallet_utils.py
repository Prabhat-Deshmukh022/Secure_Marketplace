from web3 import Web3
from eth_account.messages import encode_defunct  # Import message encoder
import os

# Connect to Ethereum node (Infura/Alchemy)
w3 = Web3(Web3.HTTPProvider(os.getenv('WEB3_PROVIDER_URL')))

def verify_signature(wallet_address, signature):
    original_message = f"Auth for {wallet_address} (Testnet)"

    # ✅ Encode the message properly (MetaMask signs with `personal_sign`)
    message = encode_defunct(text=original_message)

    try:
        # ✅ Recover the signer from the signature
        signer = w3.eth.account.recover_message(message, signature=signature)

        print("Expected Wallet Address:", wallet_address.lower())
        print("Recovered Signer:", signer.lower())

        return signer.lower() == wallet_address.lower()
    except Exception as e:
        print("Signature verification error:", e)
        return False
