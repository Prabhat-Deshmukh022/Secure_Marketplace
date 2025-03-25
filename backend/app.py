import warnings

warnings.filterwarnings("ignore",category=ImportWarning)

from jwt_generate import generate_token
from db_connect import connect
import requests
from flask_bcrypt import Bcrypt # type: ignore
import jwt
from dotenv import load_dotenv
import os
from functools import wraps


load_dotenv()

SECRET=os.getenv("SECRET_KEY")

from flask import Flask,request,jsonify,make_response # type: ignore
from flask_cors import CORS # type: ignore

db=connect()
user_collection=db["users"]

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
            print(f"Decoded token data: {data}")  # Debug log
            
            # Convert string ID to ObjectId if needed
            from bson import ObjectId # type: ignore
            user_id = ObjectId(data["id"]) if isinstance(data["id"], str) else data["id"]
            
            user = user_collection.find_one({"_id": user_id})
            print(f"Found user: {user}")  # Debug log
            
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

    response = make_response(jsonify({"message": "User logged in!"}), 200)
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

if __name__=="__main__":
    app.run(debug=True)