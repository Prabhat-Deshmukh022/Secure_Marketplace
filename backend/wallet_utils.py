from web3 import Web3
from eth_account.messages import encode_defunct  # Import message encoder
from eth_keys.datatypes import Signature
from eth_utils import keccak
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

def get_public_key_from_signature(wallet_address, signature):
    original_message = f"Auth for {wallet_address} (Testnet)"
    message = encode_defunct(text=original_message)

    try:
        msg_hash = keccak(message.body)
        recovered_address = w3.eth.account.recover_message(message, signature=signature)
        if recovered_address.lower() != wallet_address.lower():
            print("Signature does not match address")
            return None

        # Break signature down
        sig_bytes = bytes.fromhex(signature[2:])
        r = sig_bytes[:32]
        s = sig_bytes[32:64]
        v = sig_bytes[64]
        if v >= 27:
            v -= 27

        signature_obj = Signature(vrs=(v, int.from_bytes(r, 'big'), int.from_bytes(s, 'big')))
        public_key = signature_obj.recover_public_key_from_msg_hash(msg_hash)

        # Get the raw uncompressed key bytes (starts with 0x04 + 64 bytes)
        uncompressed_bytes = public_key.to_bytes()
        if uncompressed_bytes[0] == 0x04:
            uncompressed_bytes = uncompressed_bytes[1:]

        # ✅ Pad to ensure it's exactly 64 bytes
        if len(uncompressed_bytes) != 64:
            uncompressed_bytes = uncompressed_bytes.rjust(64, b'\x00')

        # Convert to hex for storage/transmission
        public_key_hex = uncompressed_bytes.hex()

        print("✅ Clean Public Key:", public_key_hex)
        return public_key_hex

    except Exception as e:
        print("Error extracting public key:", e)
        return None
