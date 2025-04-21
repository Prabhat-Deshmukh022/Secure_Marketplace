import warnings

warnings.filterwarnings("ignore",category=ImportWarning)

from jwt_generate import generate_token
from db_connect import connect
from wallet_utils import verify_signature, get_public_key_from_signature
from ipfs_service import IPFSService
import requests
from flask_bcrypt import Bcrypt # type: ignore
import jwt
from dotenv import load_dotenv
from dateutil.relativedelta import relativedelta
import os
from functools import wraps
import datetime
from bson import ObjectId # type: ignore
from blockchain_manager import BlockchainManager
from encryption import EncryptImageAndKey
from decryption import DecryptImageAndKey
from io import BytesIO
from flask import send_file
from eth_utils import keccak
from web3 import Web3

 # type: ignore


load_dotenv(override=True)

blockchain_manager = BlockchainManager()

SECRET=os.getenv("SECRET_KEY")
WEB3_PROVIDER_URL = os.getenv("WEB3_PROVIDER_URL")

w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER_URL))

MARKETPLACE_CONTRACT_ADDRESS = os.getenv("MARKET_PLACE_ADDRESS")

from flask import Flask,request,jsonify,make_response # type: ignore
from flask_cors import CORS # type: ignore

db=connect()
user_collection=db["users"]
asset_collection=db["assets"]  # Fixed typo from "assests" to "assets"
marketplace_collection=db["marketplace"]
purchase_collection=db["purchases"]

app = Flask(__name__)
bcrypt = Bcrypt(app)
CORS(app,supports_credentials=True)

def check_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check cookies first
        if 'token' in request.cookies:
            token = request.cookies.get('token')
        
        # Then check Authorization header
        elif 'Authorization' in request.headers:
            auth_header = request.headers.get('Authorization')
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        
        try:
            data = jwt.decode(token, SECRET, algorithms=["HS256"])
            # print(f"Decoded token data: {data}")  # Debug log
            
            # Convert string ID to ObjectId if needed
            from bson import ObjectId # type: ignore
            user_id = ObjectId(data["id"]) if isinstance(data["id"], str) else data["id"]
            
            user = user_collection.find_one({"_id": user_id})
            # print(f"Found user: {user}")  # Debug log
            
            if not user:
                return jsonify({"message": "User not found!"}), 401
                
            # Add user to kwargs for route access
            kwargs['user'] = user
            return f(*args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token!"}), 401
        except Exception as e:
            print(f"Token verification error: {str(e)}")
            return jsonify({"message": "Token verification failed"}), 401
            
    return decorated

@app.route("/signup",methods=["POST"])
def signup():
    data = request.json 
    username = data["username"]
    password = data["password"]

    if not username or not password:
        return jsonify({
            "message":"Username or password not provided!"
        },401)
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        user_collection.insert_one({
            "username":username,
            "password":hashed_password
        })
    except Exception as e:
        return jsonify({"message": f"An error occurred: {e}"}), 500

    return jsonify({
        "message":"user successfully registered"
    },200)

@app.route("/login",methods=["POST"])
def login():

    print("In login")

    data=request.json
    username=data["username"]
    password=data["password"]

    if not username or not password:
        return jsonify({
            "message":"Username or password not provided!"
        },401)
    
    user = user_collection.find_one({
        "username":username
    })

    if not user or not bcrypt.check_password_hash(user["password"],password):
        return jsonify({"message": "Invalid username or password!"},401)
    
    token=generate_token(user["_id"])

    print(token)

    response = make_response(
        jsonify({
            "message": "User logged in!",
            "username": user["username"]
        }), 
        200
    )
    response.set_cookie("token", token, httponly=True, secure=False, samesite='Lax')

    return response

@app.route("/logout", methods=["POST"])
@check_token
def logout(user):

    try:
        response = make_response(jsonify({
            "message": "Successfully logged out",
            "user": str(user["_id"])
        }), 200)
        
        # Clear the cookie
        response.set_cookie(
            'token',
            '',
            expires=0,
            httponly=True,
            samesite='Lax',
            secure=False  # Set to True in production with HTTPS
        )
        
        return response
        
    except Exception as e:
        print(f"Logout error: {str(e)}")
        return jsonify({"message": "Logout failed"}), 500

@app.route("/verify", methods=["GET"])
@check_token
def verify_token(user):
    """Endpoint to verify if token is still valid"""
    return jsonify({
        "valid": True,
        "user": user["username"]
    }), 200

@app.route('/verify_wallet', methods=['POST'])
@check_token
def verify_wallet(user):

    # print("IN VERIFY WALLET")

    data = request.json
    wallet_address = data['wallet_address']
    signature = data['signature']

    # print( "THE WALLET INFO IS", wallet_address,signature )

    # print(f"In /verifyWallet, walletaddress is {wallet_address} and signature is {signature}")

    if not verify_signature(wallet_address, signature):
        print("Invalid signature")
        return jsonify({"error": "Invalid signature"}), 400

    wallet_value = get_public_key_from_signature(wallet_address,signature)
    
    # Update user in database
    user_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "wallet": wallet_address,
            "wallet_value":wallet_value
        }}
    )
    
    return jsonify({"message": "Wallet verified"}), 200

ipfs_service = IPFSService()

def validate_content(metadata):
    # Check for inappropriate content
    inappropriate_words = ['nigger', 'slur', 'hate', 'racist']
    text_to_check = (str(metadata.get('name', '')).lower() + ' ' + 
                     str(metadata.get('description', '')).lower())
    
    for word in inappropriate_words:
        if word in text_to_check:
            return False, "Content contains inappropriate language"
    
    # Validate other required fields
    required_fields = ['name', 'description', 'price']
    for field in required_fields:
        if not metadata.get(field):
            return False, f"Missing required field: {field}"
            
    return True, "Content is valid"

@app.route('/upload_asset_ipfs', methods=['POST'])
@check_token
def upload_asset_ipfs(user):
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files['file']
        asset_data = request.form.to_dict()

        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
        is_valid, message = validate_content(asset_data)
        if not is_valid:
            return jsonify({"error": message}), 400

        ipfs_hash = ipfs_service.upload_to_ipfs(file.stream, file.filename)
        if not ipfs_hash:
            return jsonify({"error": "Failed to upload to IPFS"}), 500

        created_at = datetime.datetime.utcnow()
        expiry = created_at + relativedelta(months=2)

        metadata = {
            "name": asset_data.get("name", file.filename),
            "description": asset_data.get("description", ""),
            "author": user["username"],
            "wallet_address": user.get("wallet", ""),
            "created_at": created_at.isoformat(),
            "expiry": expiry.isoformat(),
            "file_name": file.filename,
            "content_type": file.content_type,
            "ipfs_hash": ipfs_hash,
            "price": asset_data.get("price"),
            "available": asset_data.get("list_to_marketplace", "False").lower() == "true",
            "blockchain_tx": None,
            "asset_id": None
        }

        asset_collection.insert_one(metadata)
        user_collection.update_one({"_id": user["_id"]}, {"$push": {"assets": ipfs_hash}})

        return jsonify({
            "success": True,
            "file_cid": ipfs_hash,
            "file_url": ipfs_service.get_ipfs_url(ipfs_hash)
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/confirm_asset_registration', methods=['POST'])
@check_token
def confirm_asset_registration(user):
    try:
        data = request.get_json()
        tx_hash = data.get('tx_hash')
        ipfs_cid = data.get('ipfs_cid')
        wallet_address = data.get('wallet_address')

        if not tx_hash or not ipfs_cid or not wallet_address:
            return jsonify({"error": "Missing transaction hash, CID, or wallet address."}), 400

        receipt = w3.eth.get_transaction_receipt(tx_hash)
        if not receipt or receipt.status != 1:
            return jsonify({"error": f"Transaction {tx_hash} is not confirmed or failed."}), 400

        tx = w3.eth.get_transaction(tx_hash)
        if tx['from'].lower() != wallet_address.lower():
            return jsonify({"error": "Transaction sender does not match."}), 400

        # Match the asset_id like in your contract logic
        asset_id = int.from_bytes(keccak(text=ipfs_cid), byteorder='big')
        # print("BACKEND, checking asset id ",asset_id)

        asset_collection.update_one(
            {"ipfs_hash": ipfs_cid},
            {"$set": {
                "blockchain_tx": tx_hash,
                "asset_id": str(asset_id)
            }}
        )

        return jsonify({"success": True, "asset_id": str(asset_id)}), 200

    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route('/user_assets', methods=['GET'])
@check_token
def get_user_assets(user):
    try:
        user_assets = list(asset_collection.find(
            {"author":user["username"]},
            {"_id":0}
        ))

        # print(user_assets)
        
        return jsonify({
            "success": True,
            "assets": user_assets
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/sale', methods=['POST'])
@check_token
def put_for_sale(user):

    print("IN /SALE")

    try:
        # Get the request payload
        data = request.json
        ipfs_hash = data.get('ipfs_hash')

        if not ipfs_hash:
            return jsonify({"message": "CID not sent!"}), 400

        # Find the asset by ipfs_hash
        asset=None
        try:
            asset = asset_collection.find_one({"ipfs_hash": ipfs_hash})
            if not asset:
                return jsonify({"message": "Asset not found"}), 404
        except Exception as db_error:
            # print(f"Error finding asset: {str(db_error)}")
            return jsonify({"error": "Database error while finding asset"}), 500

        current_time = datetime.datetime.utcnow()

        try:

            asset_id = int(asset.get('asset_id'))
            price = asset.get('price')

            # owner_on_chain = blockchain_manager.get_owner(asset_id)
            # print(f"On-chain owner: {owner_on_chain}")
            # print(f"Transaction sender: {blockchain_manager.account.address}")

            # price_wei = w3.to_wei(price, 'ether')

            # print(f"PRICE WEI {price_wei}")

            # tx_hash = blockchain_manager.list_asset_for_sale(asset_id, price_wei)

            # Update asset collection first
            asset_update = asset_collection.update_one(
                {"ipfs_hash": ipfs_hash},
                {"$set": {"available": True}}
            )
            
            if asset_update.matched_count == 0:
                return jsonify({"error": "Asset not found in collection"}), 404

            marketplace_data = {
                "ipfs_hash": ipfs_hash,
                "name": asset.get("name"),
                "description": asset.get("description"),
                "author": asset.get("author"),
                "wallet_address": asset.get("wallet_address"),
                "price": asset.get("price"),
                "file_name": asset.get("file_name"),
                "content_type": asset.get("content_type"),
                "created_at": asset.get("created_at"),
                "available": True,
                "listed_at": current_time.isoformat(),
                "owner_id": user["_id"],
                "asset_id":str(asset_id),
            }
            # Then handle marketplace collection
            existing_listing = marketplace_collection.find_one({"ipfs_hash": ipfs_hash})
            
            if existing_listing:
                marketplace_collection.update_one(
                    {"ipfs_hash": ipfs_hash},
                    {
                        "$set": {
                            "available": True,
                            "listed_at": current_time.isoformat(),
                            "asset_id":str(asset_id)
                        }
                    }
                )
            else:
                marketplace_collection.insert_one(marketplace_data)

            return jsonify({
                "status": "success",
                "message": "Asset successfully listed to marketplace!"
            }), 200

        except Exception as db_error:
            print(f"Database operation error: {str(db_error)}")
            # Try to revert the asset collection update if marketplace update failed
            try:
                asset_collection.update_one(
                    {"ipfs_hash": ipfs_hash},
                    {"$set": {"available": False}}
                )
            except:
                pass  # If revert fails, we can't do much about it
            return jsonify({
                "error": "Failed to update marketplace listing",
                "details": str(db_error)
            }), 500

    except Exception as e:
        # print(f"Error in /sale route: {str(e)}")
        return jsonify({
            "error": "An unexpected error occurred",
            "details": str(e)
        }), 500

@app.route('/display-all-assets',methods=['GET'])
@check_token
def display_assets(user):
    try:
        # Get all available assets from asset collection EXCEPT current user's assets
        assets = list(
            marketplace_collection.find(
                {
                    "available": True,
                    "author": {"$ne": user["username"]},  # Exclude current user's assets
                    "listed_at": {"$ne": None}  # Only show items that have been listed
                },
                {
                    "_id": 0,
                    "author": 1,
                    "description": 1,
                    "ipfs_hash": 1,
                    "name": 1,
                    "price": 1,
                    "file_name": 1,
                    "listed_at": 1,
                    "asset_id":1
                }
            )
        )

        if not assets:
            return jsonify({"message": "No assets for sale from other users"}), 404

        return jsonify({
            "assets": assets
        }), 200
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route('/buy', methods=['POST'])
def buy_asset():
    try:
        data = request.json
        asset_id = data.get('asset_id')
        tx_hash = data.get('tx_hash')
        buyer_address = data.get('sender')

        # Assuming you have a function to save the purchase record
        save_purchase_record(asset_id, tx_hash,buyer_address)

        return jsonify({"status": "success", "message": "Purchase recorded successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

# Function to save purchase record in MongoDB
def save_purchase_record(asset_id, tx_hash, buyer_address):
    # Create a purchase record dictionary
    purchase_record = {
        "asset_id": asset_id,
        "tx_hash": tx_hash,
        "buyer_address": buyer_address,
        "purchase_date": datetime.datetime.now()
    }

    # Insert the record into the purchases collection
    purchase_collection.insert_one(purchase_record)

@app.route('/confirm_sale', methods=['POST'])
@check_token
def confirm_sale(user):
    try:
        # Get the request payload
        data = request.json
        tx_hash = data.get('tx_hash')
        ipfs_hash = data.get('ipfs_hash')
        wallet_address = data.get('wallet_address')

        if not tx_hash or not ipfs_hash or not wallet_address:
            return jsonify({"error": "Missing required fields"}), 400

        # Find the asset by IPFS hash
        asset = asset_collection.find_one({"ipfs_hash": ipfs_hash})
        if not asset:
            return jsonify({"error": "Asset not found"}), 404

        # Validate the transaction by checking if the sender matches the wallet address
        blockchain_owner = blockchain_manager.get_owner(int(asset['asset_id']))
        # print(f" BLOCKCHAIN OWNER {blockchain_owner}")
        # print(f"WALLET ID SEND {wallet_address}")
        if blockchain_owner.lower() != wallet_address.lower():
            return jsonify({"error": "Transaction sender does not match the asset owner"}), 400

        # Confirm the sale in the database and marketplace
        current_time = datetime.datetime.utcnow()

        # Update asset collection to mark it as sold
        asset_update = asset_collection.update_one(
            {"ipfs_hash": ipfs_hash},
            {"$set": {"available": True, "blockchain_tx": tx_hash, "listed_at": current_time.isoformat()}}
        )

        if asset_update.matched_count == 0:
            return jsonify({"error": "Failed to update asset status"}), 500

        # Insert into marketplace collection
        marketplace_data = {
            "ipfs_hash": ipfs_hash,
            "name": asset.get("name"),
            "description": asset.get("description"),
            "author": asset.get("author"),
            "wallet_address": wallet_address,
            "price": asset.get("price"),
            "file_name": asset.get("file_name"),
            "content_type": asset.get("content_type"),
            "created_at": asset.get("created_at"),
            "available": True,
            "listed_at": current_time.isoformat(),
            "owner_id": user["_id"],
            "asset_id": str(asset['asset_id']),
            "blockchain_receipt": tx_hash
        }
        marketplace_collection.insert_one(marketplace_data)

        return jsonify({
            "success": True,
            "message": "Sale confirmed and asset listed!"
        }), 200

    except Exception as e:
        # print(f"Error in /confirm_sale route: {str(e)}")
        return jsonify({
            "error": "An unexpected error occurred",
            "details": str(e)
        }), 500


if __name__=="__main__":
    app.run(debug=True)