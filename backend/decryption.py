import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import ecies
from eth_keys import keys
from io import BytesIO
from ipfs_service import IPFSService
import requests

load_dotenv(override=True)

class DecryptImageAndKey:
    def __init__(self):
        self.ipfs_instance = IPFSService()
        self.private_key = os.getenv("METAMASK_PRIVATE_KEY")  # User's private key (MetaMask)

    def decrypt_and_download(self, encrypted_image_cid, encrypted_key_cid):
        """
        Decrypts the encrypted image and the secret key after downloading them from IPFS.

        Parameters:
        - encrypted_image_cid: The IPFS CID for the encrypted image.
        - encrypted_key_cid: The IPFS CID for the encrypted secret key.

        Returns:
        - The decrypted image bytes.
        """
        # Step 1: Download the encrypted image and secret key from IPFS
        encrypted_image = self.ipfs_instance.download_from_ipfs(encrypted_image_cid)
        encrypted_key = self.ipfs_instance.download_from_ipfs(encrypted_key_cid)

        print(f"The encrypted key is {encrypted_key}")

        # Step 2: Decrypt the secret key using MetaMask private key
        decrypted_key = self.decrypt_secret_key(encrypted_key)

        print(F"This is the decrypted key {decrypted_key}")

        # Step 3: Decrypt the image using the decrypted secret key (Fernet)
        fernet = Fernet(decrypted_key)
        decrypted_image_bytes = fernet.decrypt(encrypted_image)

        return decrypted_image_bytes, decrypted_key

    def decrypt_secret_key(self, encrypted_key_bytes):
        """
        Decrypts the secret key using the user's private key (MetaMask).
        
        Returns the decrypted Fernet key as bytes.
        """
        # Step 1: Get the private key from the environment variable
        private_key = self.private_key
        
        if not private_key:
            raise ValueError("Private key is missing from environment variables")

        # Step 2: Remove the '0x' prefix from the private key if it exists
        private_key = private_key.lstrip('0x')  # Strip '0x' prefix if it exists

        # Step 3: Ensure the private key is 64 hexadecimal characters (32 bytes)
        if len(private_key) != 64:
            raise ValueError("Private key is not the correct length. Expected 64 hexadecimal characters.")
        
        # Step 4: Convert the private key to a PrivateKey object
        try:
            private_key_bytes = bytes.fromhex(private_key)  # Convert hex string to bytes
            private_key_obj = keys.PrivateKey(private_key_bytes)  # Create PrivateKey object
        except ValueError as e:
            raise ValueError(f"Invalid private key format: {e}")
        
        # Step 5: Decrypt the secret key using the MetaMask private key
        try:
            decrypted_key = ecies.decrypt(private_key_bytes, encrypted_key_bytes)
        except Exception as e:
            raise ValueError(f"Failed to decrypt the secret key: {e}")
        
        # Step 6: Return the decrypted secret key as a string (Fernet key)
        return decrypted_key.decode()  # Decode bytes to string
