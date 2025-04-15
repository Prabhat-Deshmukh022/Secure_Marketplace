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


load_dotenv()

SECRET=os.getenv("SECRET_KEY")

from flask import Flask,request,jsonify,make_response # type: ignore
from flask_cors import CORS # type: ignore

db=connect()
user_collection=db["users"]
asset_collection=db["assests"]

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

@app.route('/upload_asset', methods=['POST'])
@check_token
def upload_asset(user):

    # print( f" File: {request.files['file']}, form_data: {request.form.to_dict()}" )

    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
            
        file = request.files['file']
        asset_data = request.form.to_dict()
        
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
            
        # Upload file to IPFS
        ipfs_hash = ipfs_service.upload_to_ipfs(
            file.stream,
            file.filename
        )
        
        if not ipfs_hash:
            return jsonify({"error": "Failed to upload to IPFS"}), 500

        created_at=datetime.datetime.utcnow()
        expiry=created_at+relativedelta(months=2)

        price=asset_data.get("price")

        # Create metadata
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
            "price":price,
            "available":False        
        }
        
        # Pin metadata to IPFS
        metadata_hash = ipfs_service.pin_json(metadata)

        asset_collection.insert_one(metadata)

        user_collection.update_one(
            {
                "_id":user["_id"]
            },
            {
                "$push":{
                    "assets":ipfs_hash
                }
            }
        )
        
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
        if not user:
            return jsonify({"message": "User not logged in"}), 400
        
        # Get the request payload
        data = request.json
        ipfs_hash = data.get('ipfs_hash')

        if not ipfs_hash:
            return jsonify({"message": "CID not sent!"}), 400

        # Find the asset by ipfs_hash
        asset = asset_collection.find_one({"ipfs_hash": ipfs_hash})

        if not asset:
            return jsonify({"message": "Asset not found"}), 404

        # Validate the `expiry` field
        expiry = asset.get('expiry')
        if not expiry:
            return jsonify({"message": "Asset expiry date is missing"}), 400

        try:
            expiry_date = datetime.datetime.fromisoformat(expiry)
        except ValueError:
            return jsonify({"message": "Invalid expiry date format"}), 400

        # Check if the asset has expired
        if expiry_date <= datetime.datetime.utcnow():
            return jsonify({"message": "Asset has expired"}), 400

        # Update the `available` field to True
        asset_collection.update_one(
            {"ipfs_hash": ipfs_hash},  # Filter to find the asset
            {"$set": {"available": True}}  # Update the `available` field to True
        )

        return jsonify({
            "message": "Asset is up for sale!",
            "asset_id": ipfs_hash,
            "description": asset.get("description", "No description available"),
            "author": asset.get("author", "Unknown author"),
            # "wallet_id": asset.get("wallet_address", "N/A")  # Uncomment if wallet_address is used
        }), 200

    except Exception as e:
        print(f"Error in /sale route: {str(e)}")  # Debug log
        return jsonify({"error": "An unexpected error occurred"}), 500
    
@app.route('/display-all-assets',methods=['GET'])
def display_assets():
    try:
        assets = list(
            asset_collection.find(
                {"available":True},
                {"_id":0,"author":1,"description":1,"ipfs_hash":1}
            )
        )

        if not assets:
            return jsonify({"message":"No assets for sale"}), 404

        return jsonify({
            "assets":assets
        }), 200
    except Exception as e:
        return jsonify({"error":str(e)}), 500


if __name__=="__main__":
    app.run(debug=True)