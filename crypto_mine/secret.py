# import base64
# import os

# # Generate a random 32-byte secret key (e.g., using os.urandom)
# secret_key = os.urandom(32)

# # URL-safe base64 encode the key
# url_safe_key = base64.urlsafe_b64encode(secret_key).rstrip(b'=')

# # Ensure the key is in the correct format (string)
# url_safe_key_str = url_safe_key.decode('utf-8')

# print(f"URL-safe base64 encoded key: {url_safe_key_str}")


from cryptography.fernet import Fernet

# Generate a new key
new_key = Fernet.generate_key()

# Print the new key or save it to your .env file
print(new_key.decode())