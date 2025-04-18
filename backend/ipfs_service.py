import io
import requests
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

class IPFSService:
    def __init__(self):
        self.pinata_api_key = os.getenv("PINATA_API_KEY")
        self.pinata_secret = os.getenv("PINATA_API_SECRET")
        self.pinata_jwt = os.getenv("PINATA_JWT")
        self.ipfs_gateway = "https://gateway.pinata.cloud/ipfs/"
        
    def upload_to_ipfs(self, file_stream, file_name, metadata=None):
        """
        Uploads a file to IPFS using Pinata
        Returns: IPFS hash (CID) if successful, None otherwise
        """
        try:
            # Prepare the file for upload
            files = {
                'file': (file_name, file_stream)
            }
            
            headers = {
                'Authorization': f'Bearer {self.pinata_jwt}'
            }
            
            # Upload to Pinata
            response = requests.post(
                'https://api.pinata.cloud/pinning/pinFileToIPFS',
                files=files,
                headers=headers
            )
            
            if response.status_code == 200:
                ipfs_hash = response.json()['IpfsHash']
                return ipfs_hash
            else:
                print(f"IPFS Upload Error: {response.text}")
                return None
                
        except Exception as e:
            print(f"IPFS Upload Exception: {str(e)}")
            return None
            
    def pin_json(self, json_data, name="metadata.json"):
        """
        Pins JSON data to IPFS
        """
        try:
            headers = {
                'Authorization': f'Bearer {self.pinata_jwt}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                'https://api.pinata.cloud/pinning/pinJSONToIPFS',
                json=json_data,
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json()['IpfsHash']
            return None
        except Exception as e:
            print(f"JSON Pin Error: {str(e)}")
            return None

    def download_from_ipfs(self, cid):
        """
        Downloads a file from IPFS given the CID.
        
        Returns the file content in bytes.
        """
        try:
            url = f'https://gateway.pinata.cloud/ipfs/{cid}'
            response = requests.get(url)

            if response.status_code == 200:
                return response.content
            else:
                print(f"Error downloading from IPFS: {response.text}")
                return None
        except Exception as e:
            print(f"IPFS download exception: {str(e)}")
            return None

    def get_ipfs_url(self, cid):
        """Returns full IPFS gateway URL for a CID"""
        return f"{self.ipfs_gateway}{cid}"