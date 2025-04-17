from pymongo import MongoClient  # type: ignore
import os
from dotenv import load_dotenv  # type: ignore

# Load environment variables from .env file
load_dotenv()

# Get the connection string from environment variables
CONNECTION_STRING = os.getenv("CONNECTION_STRING")

def connect():
    # Initialize the MongoDB client
    try:
        if not CONNECTION_STRING:
            raise ValueError("MongoDB connection string not found in environment variables")
            
        client = MongoClient(CONNECTION_STRING)
        db = client["secure_marketplace"]
        
        # Initialize collections if they don't exist
        if "assets" not in db.list_collection_names():
            db.create_collection("assets")
        if "marketplace" not in db.list_collection_names():
            db.create_collection("marketplace")
        if "users" not in db.list_collection_names():
            db.create_collection("users")
            
        # Test the connection
        db.command("ping")
        print("MongoDB connection successful")
        return db
        
    except Exception as e:
        print(f"MongoDB connection error: {str(e)}")
        raise e  # Re-raise the exception to handle it in the main application