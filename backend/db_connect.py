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
        client = MongoClient(CONNECTION_STRING)
        db = client["secure_marketplace"]
        print("MongoDB connection successful")
    except Exception as e:
        print(f"MongoDB connection error: {e}")

    return db