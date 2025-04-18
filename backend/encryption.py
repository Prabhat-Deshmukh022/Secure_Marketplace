# import os
# from dotenv import load_dotenv
# from cryptography.fernet import Fernet
# from eth_keys import keys
# from io import BytesIO
# from ipfs_service import IPFSService
# from ecies import encrypt
# import re

# load_dotenv(override=True)

# class EncryptImageAndKey:
#     def __init__(self):
#         self.ipfs_instance = IPFSService()
#         self.secret_key = os.getenv("SECRET_KEY")

#     def encrypt_and_upload(self, file_bytes, public_key_hex):
#         """
#         Encrypts the file and the secret key, and uploads both to IPFS.
        
#         Parameters:
#         - file_bytes: The raw file data to be encrypted and uploaded.
#         - public_key_hex: The public key (Ethereum address) to encrypt the secret Fernet key.
        
#         Returns:
#         - A tuple of the CIDs for the encrypted image and the encrypted secret key.
#         """
#         # Encrypt the file
#         encrypted_image_cid = self.encrypt_file_and_upload_to_ipfs(file_bytes)

#         # Encrypt the secret key and upload it to IPFS
#         encrypted_key_cid = self.encrypt_key_and_upload_to_ipfs(public_key_hex)

#         return encrypted_image_cid, encrypted_key_cid

#     def encrypt_file_and_upload_to_ipfs(self, file_bytes):

#         print("SECRET KEY",self.secret_key)

#         """
#         Encrypt the file using the secret Fernet key and upload it to IPFS.
        
#         Returns the IPFS CID of the encrypted file.
#         """
#         if not self.secret_key:
#             raise ValueError("SECRET_KEY not found in environment variables")

#         fernet = Fernet(self.secret_key)

#         # If file_bytes is already bytes (e.g. from an API), skip .read()
#         if hasattr(file_bytes, 'read'):
#             original_file_bytes = file_bytes.read()
#         else:
#             original_file_bytes = file_bytes

#         # Encrypt the file
#         encrypted_bytes = fernet.encrypt(original_file_bytes)

#         # Wrap the encrypted bytes into a file-like object
#         encrypted_file_stream = BytesIO(encrypted_bytes)

#         # Upload the encrypted file to IPFS
#         cid = self.ipfs_instance.upload_to_ipfs(
#             encrypted_file_stream,
#             file_name="encrypted_asset.bin"
#         )

#         return cid
    
#     def encrypt_key_and_upload_to_ipfs(self, public_key_hex):
#         if not self.secret_key:
#             raise ValueError("SECRET_KEY not found in environment variables")

#         # Step 1: Clean the hex (strip '0x' if present)
#         clean_pubkey = public_key_hex.lower().replace("0x", "")

#         # Step 2: Validate hex format
#         if not re.fullmatch(r"[0-9a-f]{128}", clean_pubkey):
#             raise ValueError("Public key must be 128 valid hex characters (64 bytes)")

#         # Step 3: Add uncompressed EC point prefix '04'
#         full_public_key = "04" + clean_pubkey  # now 130 characters

#         # Step 4: Encrypt using ECIES
#         encrypted_key = encrypt(full_public_key, self.secret_key.encode())

#         # Step 5: Upload to IPFS
#         encrypted_key_stream = BytesIO(encrypted_key)
#         cid = self.ipfs_instance.upload_to_ipfs(
#             encrypted_key_stream,
#             file_name="encrypted_fernet_key.bin"
#         )

#         return cid

import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from eth_keys import keys
from io import BytesIO
from ipfs_service import IPFSService
import ecies
import re

load_dotenv(override=True)

class EncryptImageAndKey:
    def __init__(self):
        self.ipfs_instance = IPFSService()
        self.secret_key = os.getenv("SECRET_KEY")

    def encrypt_and_upload(self, file_bytes, public_key_hex):
        """
        Encrypts the file and the secret key, and uploads both to IPFS.
        
        Parameters:
        - file_bytes: The raw file data to be encrypted and uploaded.
        - public_key_hex: The public key (Ethereum address) to encrypt the secret Fernet key.
        
        Returns:
        - A tuple of the CIDs for the encrypted image and the encrypted secret key.
        """
        # Encrypt the file
        encrypted_image_cid = self.encrypt_file_and_upload_to_ipfs(file_bytes)

        # Encrypt the secret key and upload it to IPFS
        encrypted_key_cid = self.encrypt_key_and_upload_to_ipfs(public_key_hex)

        return encrypted_image_cid, encrypted_key_cid

    def encrypt_file_and_upload_to_ipfs(self, file_bytes):

        print("SECRET KEY",self.secret_key)

        """
        Encrypt the file using the secret Fernet key and upload it to IPFS.
        
        Returns the IPFS CID of the encrypted file.
        """
        if not self.secret_key:
            raise ValueError("SECRET_KEY not found in environment variables")

        fernet = Fernet(self.secret_key)

        # If file_bytes is already bytes (e.g. from an API), skip .read()
        if hasattr(file_bytes, 'read'):
            original_file_bytes = file_bytes.read()
        else:
            original_file_bytes = file_bytes

        # Encrypt the file
        encrypted_bytes = fernet.encrypt(original_file_bytes)

        # Wrap the encrypted bytes into a file-like object
        encrypted_file_stream = BytesIO(encrypted_bytes)

        # Upload the encrypted file to IPFS
        cid = self.ipfs_instance.upload_to_ipfs(
            encrypted_file_stream,
            file_name="encrypted_asset.bin"
        )

        return cid
    
    def encrypt_key_and_upload_to_ipfs(self, public_key_hex):
        if not self.secret_key:
            raise ValueError("SECRET_KEY not found in environment variables")

        # Step 1: Clean the hex (strip '0x' if present)
        clean_pubkey = public_key_hex.lower().replace("0x", "")

        # Step 2: Validate hex format
        if not re.fullmatch(r"[0-9a-f]{128}", clean_pubkey):
            raise ValueError("Public key must be 128 valid hex characters (64 bytes)")

        # Step 3: Add uncompressed EC point prefix '04'
        full_public_key = "04" + clean_pubkey  # now 130 characters

        # Step 4: Encrypt using ECIES
        encrypted_key = ecies.encrypt(bytes.fromhex(full_public_key), self.secret_key.encode())

        print(F"This is ALSO encrypted key {encrypted_key}")

        # Step 5: Upload to IPFS
        encrypted_key_stream = BytesIO(encrypted_key)
        cid = self.ipfs_instance.upload_to_ipfs(
            encrypted_key_stream,
            file_name="encrypted_fernet_key.bin"
        )

        return cid
