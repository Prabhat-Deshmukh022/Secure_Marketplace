import warnings

warnings.filterwarnings("ignore",category=ImportWarning)

from jwt_generate import generate_token
from db_connect import connect
from wallet_utils import verify_signature
from ipfs_service import IPFSService
import requests
from flask_bcrypt import Bcrypt # type: ignore
import jwt
from dotenv import load_dotenv
from dateutil.relativedelta import relativedelta
import os
from functools import wraps
import datetime
from blockchain_manager import BlockchainManager

 # type: ignore


load_dotenv()

blockchain_manager = BlockchainManager()

SECRET=os.getenv("SECRET_KEY")

from flask import Flask,request,jsonify,make_response # type: ignore
from flask_cors import CORS # type: ignore

db=connect()
user_collection=db["users"]
asset_collection=db["assets"]  # Fixed typo from "assests" to "assets"
marketplace_collection=db["marketplace"]

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
    data = request.json
    wallet_address = data['wallet_address']
    signature = data['signature']

    # print(f"In /verifyWallet, walletaddress is {wallet_address} and signature is {signature}")

    if not verify_signature(wallet_address, signature):
        print("Invalid signature")
        return jsonify({"error": "Invalid signature"}), 400
    
    # Update user in database
    user_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"wallet": wallet_address}}
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

@app.route('/upload_asset', methods=['POST'])
@check_token
def upload_asset(user):
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
            
        file = request.files['file']
        asset_data = request.form.to_dict()
        
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
        
        # Validate content before processing
        is_valid, message = validate_content(asset_data)
        if not is_valid:
            return jsonify({"error": message}), 400

        # Upload file to IPFS
        ipfs_hash = ipfs_service.upload_to_ipfs(
            file.stream,
            file.filename
        )
        
        if not ipfs_hash:
            return jsonify({"error": "Failed to upload to IPFS"}), 500

        created_at = datetime.datetime.utcnow()
        expiry = created_at + relativedelta(months=2)
        price = asset_data.get("price")
        list_to_marketplace = asset_data.get("list_to_marketplace", "False").lower() == "true"

        # Create metadata with sanitized content
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
            "price": price,
            "available": list_to_marketplace  # Set based on checkbox
        }
        
        # Pin metadata to IPFS
        metadata_hash = ipfs_service.pin_json(metadata)

        # Add to asset collection
        asset_collection.insert_one(metadata)

        # Update user's assets
        user_collection.update_one(
            {"_id": user["_id"]},
            {"$push": {"assets": ipfs_hash}}
        )

        # Initialize in marketplace collection only if list_to_marketplace is True
        if list_to_marketplace:
            marketplace_collection.insert_one({
                **metadata,
                "listed_at": datetime.datetime.utcnow().isoformat(),
                "owner_id": user["_id"]
            })
        
        return jsonify({
            "success": True,
            "file_cid": ipfs_hash,
            "metadata_cid": metadata_hash,
            "file_url": ipfs_service.get_ipfs_url(ipfs_hash),
            "metadata_url": ipfs_service.get_ipfs_url(metadata_hash)
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
    try:
        # Get the request payload
        data = request.json
        ipfs_hash = data.get('ipfs_hash')

        if not ipfs_hash:
            return jsonify({"message": "CID not sent!"}), 400

        # Find the asset by ipfs_hash
        try:
            asset = asset_collection.find_one({"ipfs_hash": ipfs_hash})
            if not asset:
                return jsonify({"message": "Asset not found"}), 404
        except Exception as db_error:
            print(f"Error finding asset: {str(db_error)}")
            return jsonify({"error": "Database error while finding asset"}), 500

        current_time = datetime.datetime.utcnow()

        # Create marketplace data
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
            "owner_id": user["_id"]
        }

        try:
            # Update asset collection first
            asset_update = asset_collection.update_one(
                {"ipfs_hash": ipfs_hash},
                {"$set": {"available": True}}
            )
            
            if asset_update.matched_count == 0:
                return jsonify({"error": "Asset not found in collection"}), 404

            # Then handle marketplace collection
            existing_listing = marketplace_collection.find_one({"ipfs_hash": ipfs_hash})
            
            if existing_listing:
                marketplace_collection.update_one(
                    {"ipfs_hash": ipfs_hash},
                    {
                        "$set": {
                            "available": True,
                            "listed_at": current_time.isoformat()
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
        print(f"Error in /sale route: {str(e)}")
        return jsonify({
            "error": "An unexpected error occurred",
            "details": str(e)
        }), 500

@app.route('/display-all-assets',methods=['GET'])
@check_token
def display_assets(user):
    try:
        # Get all available assets from marketplace collection
        assets = list(
            asset_collection.find(
                {"available":True},
                {"_id":0,"author":1,"description":1,"ipfs_hash":1}
            )
        )

        if not assets:
            return jsonify({"message": "No assets for sale from other users"}), 404

        return jsonify({
            "assets": assets
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/update-availability/<ipfs_hash>', methods=['PUT'])
@check_token
def update_availability(user, ipfs_hash):
    try:
        # Update in marketplace collection
        result = marketplace_collection.update_one(
            {"ipfs_hash": ipfs_hash},
            {
                "$set": {
                    "available": True,
                    "listed_at": datetime.datetime.utcnow().isoformat()
                }
            }
        )

        # Update in asset collection
        asset_collection.update_one(
            {"ipfs_hash": ipfs_hash},
            {"$set": {"available": True}}
        )

        if result.modified_count > 0:
            return jsonify({"message": "Asset availability updated successfully"}), 200
        else:
            return jsonify({"message": "Asset not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/update-asset/<asset_id>', methods=['PUT'])
@check_token
def update_assets(user, asset_id):

    print("IN UPDATE_ASSETS")

    try:
        # Convert asset_id to ObjectId
        try:
            asset_id = ObjectId(asset_id)
        except Exception:
            return jsonify({"message": "Invalid asset ID format"}), 400

        # Find the asset by _id
        asset = asset_collection.find_one({"_id": asset_id})

        if not asset:
            return jsonify({"message": "Asset not found"}), 404

        # Get the request payload
        data = request.json
        price = data.get("price")
        name = data.get("name")
        description = data.get("description")

        # Prepare the update fields
        update_fields = {}
        if price is not None:
            update_fields["price"] = price
        if name is not None:
            update_fields["name"] = name
        if description is not None:
            update_fields["description"] = description

        if not update_fields:
            return jsonify({"message": "No fields to update"}), 400

        # Update the asset
        result = asset_collection.update_one(
            {"_id": asset_id},
            {"$set": update_fields}
        )

        if result.modified_count == 0:
            return jsonify({"message": "No changes made to the asset"}), 200

        return jsonify({"message": "Asset updated successfully"}), 200

    except Exception as e:
        print(f"Error in /update-asset route: {str(e)}")  # Debug log
        return jsonify({"error": "An unexpected error occurred"}), 500
    
if __name__=="__main__":
    app.run(debug=True)