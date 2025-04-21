from eth_account import Account
from eth_account.messages import encode_defunct
from dotenv import load_dotenv
import os

load_dotenv()

# Simulate signature and message
message = "This is a test message"
private_key = os.getenv("METAMASK_PRIVATE_KEY")

# Create an account object from the private key
acct = Account.from_key(private_key)

# Sign the message
message_hash = encode_defunct(text=message)
signed_message = acct.sign_message(message_hash)

# Recover the address from the signed message
recovered_address = Account.recover_message(message_hash, signature=signed_message.signature)

# Print the recovered public address (Ethereum address)
print("Recovered Address:", recovered_address)



b'\x044\x01\x18\xef+\xb5\xb0*\x01\xfd\x13\\\xe0d\xa8J\xf3\x1c\xfc\xad.G\xf9\xb9L\xaf\xfc\xec\xd8\xdfruNk\xa8\xa2\xa2\xdb\x99s\ro\xe0LU@\xc7\xfbYT#\x9b\x89\x8f+\xc5\x03\xfeU\x99-mO-\x18%\x1f?\xa0\xb0\xe9i\x19\xc1\x95!\xe6c\xea\x83\xcb\x05\xd627\x99\xd2w\xdb8\xbd\xbe\xea\x18d\xe4\xec\x8cN\x04{+\xbb\xe1#\xdfYn\xd3l\xef\xb0\xa4\x10"\xa8:\x95\x1fy@K\xb8\xcajj\xfd\xf2\x00\xda\xe5\x94\xcd/\xd6m^j\x1db'