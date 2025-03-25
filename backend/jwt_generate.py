import jwt #type: ignore
from dotenv import load_dotenv # type: ignore
import os
import datetime

load_dotenv()

SECRET_KEY=os.getenv("SECRET_KEY")

def generate_token(id):

    payload={"id":str(id), "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}


    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm="HS256"
    )

    return token

# print(generate_token("my_id"))