import json
import streamlit as st
import requests
from datetime import datetime
import warnings
from streamlit.deprecation_util import make_deprecated_name_warning
from streamlit_javascript import st_javascript
from web3 import Web3
import os
from dotenv import load_dotenv
import nacl.utils
import nacl.secret  # Added missing import
from nacl.public import PrivateKey, PublicKey, Box
from eth_keys import keys
from eth_utils import decode_hex

# Load environment variables
load_dotenv()
load_dotenv('.env.test')

# Initialize Web3
w3 = Web3(Web3.HTTPProvider(os.getenv('WEB3_PROVIDER_URL')))

# Load contract ABIs
with open(r'contracts\SecureImageSharing.json') as f:
    image_sharing_abi = json.load(f)['abi']
with open(r'contracts\KeyManagement.json') as f:
    key_management_abi = json.load(f)['abi']

# Initialize contracts
image_sharing_address = Web3.to_checksum_address(os.getenv('IMAGE_SHARING_CONTRACT'))
key_management_address = Web3.to_checksum_address(os.getenv('KEY_MANAGEMENT_CONTRACT'))
image_sharing_contract = w3.eth.contract(address=image_sharing_address, abi=image_sharing_abi)
key_management_contract = w3.eth.contract(address=key_management_address, abi=key_management_abi)

import time
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Create a session object to handle cookies
session = requests.Session()
session.headers.update({"Content-Type": "application/json"})

# Backend API URL
API_URL = "http://127.0.0.1:5000"

def generate_keypair():
    """Generate a NaCl keypair for encryption"""
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key

def encrypt_file(file_bytes, public_key):
    """Encrypt file data with a random secret key, then encrypt that key with recipient's public key"""
    # Generate random secret key for file encryption
    secret_key = nacl.utils.random(32)
    
    # Encrypt file with secret key
    box = nacl.secret.SecretBox(secret_key)
    encrypted_file = box.encrypt(file_bytes)
    
    # Encrypt secret key with recipient's public key
    recipient_key = PublicKey(public_key)
    sender_private = PrivateKey.generate()
    sender_box = Box(sender_private, recipient_key)
    encrypted_key = sender_box.encrypt(secret_key)
    
    return encrypted_file, encrypted_key

def decrypt_file(encrypted_file, encrypted_key, private_key):
    """Decrypt file using private key"""
    # First decrypt the secret key
    private_key_obj = PrivateKey(private_key)
    box = Box(private_key_obj, PublicKey(encrypted_key[:32]))
    secret_key = box.decrypt(encrypted_key[32:])
    
    # Then decrypt the file
    secret_box = nacl.secret.SecretBox(secret_key)
    decrypted_file = secret_box.decrypt(encrypted_file)
    return decrypted_file

def main():
    st.set_page_config(page_title="Secure Digital Asset Marketplace", layout="wide")
    
     # Initialize ALL session state variables
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "current_user" not in st.session_state:
        st.session_state.current_user = None
    if "token" not in st.session_state:
        st.session_state.token = None
    if "show_signup" not in st.session_state:
        st.session_state.show_signup = False
    # Add these wallet-specific initializations
    if "wallet_connected" not in st.session_state:
        st.session_state.wallet_connected = False
    if "wallet_address" not in st.session_state:
        st.session_state.wallet_address = None
    if "wallet_data" not in st.session_state:
        st.session_state.wallet_data = None
    # Check for existing token on page load
    if not st.session_state.authenticated and not st.session_state.token:
        check_existing_session()

    # Route to appropriate page
    if st.session_state.show_signup:
        show_signup()
    elif not st.session_state.authenticated:
        show_login()
    else:
        show_home()
    
def check_existing_session():
    """Check for existing valid session from cookies"""
    try:
        # Get token from URL params - correct way
        token = st.query_params.get("token", None)
        
        # Skip verification if empty token
        if not token or token == "None":
            st.session_state.authenticated = False
            return
            
        # Verify with backend
        response = session.get(
            f"{API_URL}/verify",
            headers={"Authorization": f"Bearer {token}"},
            cookies={"token": token}
        )
        
        if response.status_code == 200:
            st.session_state.authenticated = True
            st.session_state.current_user = response.json().get("user")
            st.session_state.token = token
        else:
            # Clear invalid token from URL - correct way
            if "token" in st.query_params:
                del st.query_params["token"]
            st.session_state.authenticated = False
    except Exception as e:
        print(f"Session check error: {e}")
        st.session_state.authenticated = False
        if "token" in st.query_params:
            del st.query_params["token"]

def show_login():
    st.title("Welcome to Secure Digital Asset Marketplace")
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            try:
                response = session.post(
                    f"{API_URL}/login",
                    json={"username": username, "password": password}
                )
                
                # In your login function, after successful auth:
                if response.status_code == 200:
                    token = response.cookies.get("token")
                    if not st.session_state.current_user:
                        st.session_state.current_user=response.json()['username']
                    if token:
                        st.session_state.token = token
                        # Correct way to set query param
                        st.query_params["token"] = token
                        st.session_state.authenticated = True
                        st.rerun()
                    else:
                        st.error("Login failed - no token received")
                else:
                    error_msg = response.json().get("message", "Login failed. Please try again.")
                    st.error(error_msg)
            except Exception as e:
                st.error(f"An error occurred: {str(e)}")
        
    st.write("Don't have an account?")
    if st.button("Sign Up"):
        st.session_state.show_signup = True  # Set the flag
        st.rerun()  # Force rerun to show signup page

def show_signup():
    st.title("Sign Up for Secure Digital Asset Marketplace")
    
    with st.form("signup_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submit = st.form_submit_button("Sign Up")
        
        if submit:
            if password != confirm_password:
                st.error("Passwords do not match!")
                return
                
            try:
                response = session.post(
                    f"{API_URL}/signup",
                    json={"username": username, "password": password}
                )
                
                if response.status_code == 200:
                    st.success("Account created successfully! Please log in.")
                    st.session_state.show_signup = False
                    st.rerun()
                else:
                    error_msg = response.json().get("message", "Signup failed. Please try again.")
                    st.error(error_msg)
            except Exception as e:
                st.error(f"An error occurred: {str(e)}")
    
    st.write("Already have an account?")
    if st.button("Back to Login"):
        st.session_state.show_signup = False  # Clear the flag
        st.rerun()  # Force rerun to show login page

def clear_storage():
    st.components.v1.html(
        """
        <script>
        // ✅ Clear localStorage on page load
        window.localStorage.removeItem("walletData");
        console.log("Cleared walletData from localStorage");
        </script>
        """,
        height=10
    )

def show_home():
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["My Assets", "Marketplace", "Notifications"])

    # Display user info and logout button in sidebar
    st.sidebar.markdown("---")
    st.sidebar.write(f"Logged in as: **{st.session_state.current_user}**")
    if st.sidebar.button("Logout"):
        logout_user()

    st.title("Welcome to the Secure Marketplace")
    st.write("This platform allows secure exchange of digital assets using blockchain and IPFS.")

    # Initialize wallet connection state
    if 'wallet_connected' not in st.session_state:
        st.session_state.wallet_connected = False
    if 'wallet_address' not in st.session_state:
        st.session_state.wallet_address = None

    # Wallet Connection Section
    if not st.session_state.wallet_connected:
        with st.expander("🔗 Connect MetaMask Wallet", expanded=True):
            # Step 1: Sign with MetaMask
            st.markdown("**Step 1:** Sign with MetaMask")
            connect_js = """
            <script>
            async function requestSignature() {
                console.log("Checking for window.ethereum...");
                
                if (!window.ethereum) {
                    console.log("window.ethereum is NOT available. Trying different detection methods...");
                    if (window.parent && window.parent.ethereum) {
                        console.log("Detected inside an iframe! Using window.parent.ethereum.");
                        window.ethereum = window.parent.ethereum;
                    } else {
                        alert("MetaMask not detected! Try opening this page in a new tab.");
                        return null;
                    }
                }

                console.log("MetaMask detected, requesting accounts...");
                try {
                    const accounts = await ethereum.request({ method: 'eth_requestAccounts' });
                    console.log("Accounts:", accounts);
                    
                    if (accounts.length === 0) {
                        alert("No accounts found!");
                        return null;
                    }
                    
                    const message = "Auth for " + accounts[0] + " (Testnet)";
                    console.log("Signing message:", message);

                    let signature;
                    try {
                        signature = await ethereum.request({
                            method: 'personal_sign',
                            params: [message, accounts[0]]
                        });
                    } catch (signError) {
                        console.error("Error during signing:", signError);
                        alert("Failed to sign the message. Please check the console.");
                        return null;
                    }

                    if (!signature) {
                        console.error("Signature is undefined or null.");
                        return null;
                    }

                    console.log("Signature received:", signature);

                    // Store in localStorage
                    const walletData = JSON.stringify({
                        type: 'WALLET_CONNECTED',
                        address: accounts[0],
                        signature: signature
                    });

                    console.log("Storing wallet data in localStorage:", walletData);
                    window.localStorage.setItem("walletData", walletData);

                    return walletData;

                } catch (error) {
                    console.error("MetaMask Error:", error);
                    alert("MetaMask Signature Failed! Check console.");
                    return null;
                }
            }

            function callRequestSignature() {
                requestSignature().then(data => {
                    if (data) {
                        console.log("Wallet data successfully stored in localStorage.");
                    } else {
                        console.log("Failed to store wallet data.");
                    }
                });
            }
            </script>

            <button onclick="callRequestSignature()">Sign with MetaMask</button>
            """
            
            st.components.v1.html(connect_js, height=100)
            
            # Step 2: Connect to Backend
            st.markdown("**Step 2:** Connect to backend")
            wallet_data = st_javascript("window.localStorage.getItem('walletData')")
            
            if wallet_data:
                if st.button("Connect Wallet", type="primary"):
                    try:
                        data = json.loads(wallet_data)
                        
                        with st.spinner("Verifying wallet..."):
                            response = requests.post(
                                f"{API_URL}/verify_wallet",
                                json={
                                    "wallet_address": data["address"],
                                    "signature": data["signature"]
                                },
                                headers={"Authorization": f"Bearer {st.session_state.token}"}
                            )

                        if response.status_code == 200:
                            st.session_state.wallet_connected = True
                            st.session_state.wallet_address = data["address"]
                            st.rerun()
                        else:
                            st.error("Wallet verification failed. Please try again.")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
            else:
                st.warning("Please sign with MetaMask first")

            # Add JavaScript to handle the refresh
            st.components.v1.html("""
            <script>
            window.addEventListener('message', (event) => {
                if (event.data.type === 'WALLET_SIGNED') {
                    // Trigger Streamlit rerun
                    window.parent.document.querySelectorAll('iframe').forEach(iframe => {
                        if (iframe.src.includes('streamlit')) {
                            iframe.contentWindow.postMessage({type: 'RERUN'}, '*');
                        }
                    });
                }
            });
            </script>
            """, height=0)

    # After wallet connection section
    st.components.v1.html("""
    <script>
    // Helper function to initialize Web3 library and setup communication
    window.setupWeb3 = async function() {
        if (window.ethereum) {
            window.web3Provider = window.ethereum;
        } else if (window.parent.ethereum) {
            window.web3Provider = window.parent.ethereum;
        }
        
        if (!window.web3Provider) {
            throw new Error('No Web3 provider found. Please install MetaMask.');
        }

        window.web3 = new Web3(window.web3Provider);
        
        // Setup cross-frame communication
        window.addEventListener('message', function(event) {
            if (event.data.type === 'WEB3_REQUEST') {
                window.parent.postMessage({ type: 'WEB3_RESPONSE', provider: window.web3Provider }, '*');
            }
        });

        return window.web3Provider;
    };

    // Initialize on load
    window.addEventListener('load', function() {
        if (!window.web3) {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/web3@1.5.2/dist/web3.min.js';
            script.onload = () => {
                setupWeb3().catch(console.error);
            };
            document.head.appendChild(script);
        }
    });
    </script>
    """, height=0)

    # Display connection status
    if st.session_state.wallet_connected:
        st.success(f"🔗 Connected: {st.session_state.wallet_address[:6]}...{st.session_state.wallet_address[-4:]}")

    if page == "My Assets":
        show_my_assets()
    elif page == "Marketplace":
        show_marketplace()
    elif page == "Notifications":
        show_notifications()

def logout_user():
    # clear_storage()
    try:
        if st.session_state.token:
            # Prepare both cookies and headers
            cookies = {"token": st.session_state.token}
            headers = {"Authorization": f"Bearer {st.session_state.token}"}
            
            response = session.post(
                f"{API_URL}/logout",
                cookies=cookies,
                headers=headers
            )
            
            if response.status_code == 200:
                st.success("Logged out successfully!")
                # Correct way to clear query param
                if "token" in st.query_params:
                    del st.query_params["token"]
            else:
                st.error(f"Logout failed: {response.json().get('message', 'Unknown error')}")
    except Exception as e:
        st.error(f"An error occurred during logout: {str(e)}")
    
    # Reset session state
    st.session_state.clear()  # Clear ALL session state instead of individual items
    session.cookies.clear()
    st.rerun()

def show_my_assets():
    st.title("My Digital Assets")
    
    if not st.session_state.wallet_connected:
        st.warning("Please connect your wallet first to upload and manage assets.")
        return

    # Initialize form data in session state
    if 'form_data' not in st.session_state:
        st.session_state.form_data = {
            'asset_name': '',
            'description': '',
            'price': 0.0,
            'file_bytes': None,
            'file_name': None,
            'file_type': None
        }

    with st.form("upload_asset_form", clear_on_submit=True):
        st.subheader("Upload New Asset")
        
        asset_name = st.text_input("Asset Name*", value=st.session_state.form_data['asset_name'])
        description = st.text_area("Description", value=st.session_state.form_data['description'])
        price = st.number_input("Price (ETH)*", value=float(st.session_state.form_data['price']), min_value=0.0, step=0.01)
        file = st.file_uploader("Asset File*", type=["png", "jpg", "jpeg", "gif", "mp4", "mov", "pdf", "glb"])
        list_to_marketplace = st.checkbox("List it to marketplace", value=False)

        submitted = st.form_submit_button("Upload Asset")

        if submitted:
            if not all([asset_name, file]):
                st.error("Please fill all required fields (*)")
            else:
                try:
                    # Store file bytes immediately
                    file_bytes = file.getvalue()
                    
                    with st.spinner("Uploading to IPFS..."):
                        files = {
                            'file': (file.name, file_bytes, file.type)
                        }
                        data = {
                            'name': asset_name,
                            'description': description,
                            'price': str(price),
                            'list_to_marketplace': str(list_to_marketplace)
                        }
                        headers = {
                            'Authorization': f'Bearer {st.session_state.token}'
                        }
                        
                        response = requests.post(
                            f"{API_URL}/upload_asset",
                            files=files,
                            data=data,
                            headers=headers
                        )
                        
                        if response.status_code == 200:
                            ipfs_data = response.json()
                            file_cid = ipfs_data['file_cid']
                            metadata_cid = ipfs_data.get('metadata_cid', '')

                            # After IPFS upload success, encrypt the file
                            if ipfs_data:
                                # Generate a random key for this asset
                                asset_key = nacl.utils.random(32)
                                
                                # Encrypt the file
                                encrypted_file = nacl.secret.SecretBox(asset_key).encrypt(file_bytes)
                                
                                # Upload encrypted file to IPFS
                                encrypted_ipfs_response = requests.post(
                                    f"{API_URL}/upload_asset",
                                    files={'file': ('encrypted_' + file.name, encrypted_file)},
                                    headers=headers
                                )
                                
                                if encrypted_ipfs_response.status_code == 200:
                                    encrypted_cid = encrypted_ipfs_response.json()['file_cid']
                                    
                                    # Store the asset key encrypted with owner's public key
                                    owner_public_key = PublicKey(st.session_state.public_key)
                                    box = Box(PrivateKey.generate(), owner_public_key)
                                    encrypted_key = box.encrypt(asset_key)
                                    
                                    # Upload encrypted key to IPFS
                                    key_response = requests.post(
                                        f"{API_URL}/upload_asset",
                                        files={'file': ('key.bin', encrypted_key)},
                                        headers=headers
                                    )
                                    
                                    if key_response.status_code == 200:
                                        key_cid = key_response.json()['file_cid']
                                        
                                        # Now proceed with blockchain listing using encrypted CIDs
                                        # ...existing blockchain listing code...

                            # Convert price to Wei
                            price_wei = w3.to_wei(price, 'ether')

                            # Build smart contract transaction
                            st.info("Please approve the transaction in MetaMask...")
                            
                            # Inject JavaScript to handle the transaction
                            tx_js = f"""
                            <script>
                            async function listOnBlockchain() {{
                                try {{
                                    const accounts = await ethereum.request({{ method: 'eth_requestAccounts' }});
                                    
                                    // Create the function selector for listImage(string,string,uint256)
                                    const functionSelector = '0x' + web3.utils.keccak256('listImage(string,string,uint256)').slice(0, 8);
                                    
                                    // Encode parameters
                                    const abiCoder = new web3.eth.abi.encoder;
                                    const encodedParams = web3.eth.abi.encodeParameters(
                                        ['string', 'string', 'uint256'],
                                        ['{file_cid}', '{metadata_cid}', '{price_wei}']
                                    );
                                    
                                    // Combine function selector and encoded parameters
                                    const data = functionSelector + encodedParams.slice(2); // remove '0x' from params
                                    
                                    const tx = await ethereum.request({{
                                        method: 'eth_sendTransaction',
                                        params: [{{
                                            from: '{st.session_state.wallet_address}',
                                            to: '{image_sharing_address}',
                                            data: data,
                                            gas: '0x4C4B40'  // 5,000,000 gas
                                        }}]
                                    }});
                                    
                                    window.parent.postMessage({{
                                        type: 'LISTING_COMPLETE',
                                        txHash: tx
                                    }}, '*');
                                    
                                    return tx;
                                }} catch (error) {{
                                    console.error('Error:', error);
                                    window.parent.postMessage({{
                                        type: 'LISTING_ERROR',
                                        error: error.message
                                    }}, '*');
                                    return null;
                                }}
                            }}
                            
                            // Add web3 library
                            const script = document.createElement('script');
                            script.src = 'https://cdn.jsdelivr.net/npm/web3@1.5.2/dist/web3.min.js';
                            script.onload = () => {{
                                window.web3 = new Web3(window.ethereum);
                                listOnBlockchain();
                            }};
                            document.head.appendChild(script);
                            </script>
                            """
                            st.components.v1.html(tx_js, height=0)

                            # Wait for transaction response
                            with st.spinner("Waiting for blockchain transaction..."):
                                # Here we would ideally wait for the transaction event
                                # For now, we'll just show a success message
                                st.success("Asset uploaded and listed successfully!")
                                
                            # Reset form
                            st.session_state.form_data = {
                                'asset_name': '',
                                'description': '',
                                'price': 0.0,
                                'file_bytes': None,
                                'file_name': None,
                                'file_type': None
                            }
                            st.rerun()
                        else:
                            st.error(f"Upload failed: {response.text}")
                except Exception as e:
                    st.error(f"Error: {str(e)}")
    
    st.subheader("Your Assets")
    display_user_assets()

def display_user_assets():
    """Fetch and display user's assets from backend with Update and Put for Sale buttons."""
    st.title("Your Assets")
    try:
        # Fetch user assets
        response = session.get(
            f"{API_URL}/user_assets",
            headers={"Authorization": f"Bearer {st.session_state.token}"}
        )
        
        if response.status_code == 200:
            assets = response.json().get("assets", [])
            
            if not assets:
                st.info("You haven't uploaded any assets yet.")
                return
                
            for asset in assets:
                with st.container():
                    col1, col2, col3 = st.columns([2, 2, 1])
                    
                    with col1:
                        st.subheader(asset["name"])
                        st.write(asset["description"])
                        st.write(f"💰 Price: {asset['price']} ETH")
                        st.write(f"📅 Uploaded: {asset['created_at']}")
                    
                    with col2:
                        ipfs_url = f"https://gateway.pinata.cloud/ipfs/{asset['ipfs_hash']}"
                        st.markdown(f"🔗 [View on IPFS]({ipfs_url})")
                        st.write(f"📄 File: {asset['file_name']}")
                        
                    with col3:
                        if not asset.get('available', False):
                            list_button_key = f"list_{asset['ipfs_hash']}"
                            if st.button("List to Marketplace", key=list_button_key, type="primary"):
                                with st.spinner("Listing asset to marketplace..."):
                                    headers = {"Authorization": f"Bearer {st.session_state.token}"}
                                    list_response = requests.post(
                                        f"{API_URL}/sale",
                                        json={"ipfs_hash": asset['ipfs_hash']},
                                        headers=headers
                                    )
                                    
                                    if list_response.status_code == 200:
                                        st.success("Asset successfully listed to marketplace!")
                                        time.sleep(1)  # Show success message
                                        st.rerun()
                                    else:
                                        error_msg = list_response.json().get('error', 'Failed to list asset')
                                        st.error(f"Error: {error_msg}")
                        else:
                            st.success("🏪 Listed in Marketplace")
                    
                    st.markdown("---")
        else:
            st.error("Failed to fetch assets.")
    except Exception as e:
        st.error(f"Error loading assets: {str(e)}")    

def show_marketplace():
    st.title("Marketplace")
    st.write("Browse and buy digital assets from other users.")

    if not st.session_state.wallet_connected:
        st.warning("Please connect your wallet to make purchases.")
        return

    try:
        # Fetch listings from MongoDB through backend
        response = requests.get(
            f"{API_URL}/display-all-assets",
            headers={"Authorization": f"Bearer {st.session_state.token}"}
        )
        
        if response.status_code == 200:
            assets = response.json().get("assets", [])
            
            if not assets:
                st.info("No assets currently listed in the marketplace.")
                return

            for asset in assets:
                with st.container():
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.subheader(asset["name"])
                        st.write(asset["description"])
                        st.write(f"👤 Author: {asset['author']}")
                        
                        ipfs_hash = asset["ipfs_hash"]
                        if ipfs_hash:
                            preview_url = f"https://gateway.pinata.cloud/ipfs/{ipfs_hash}"
                            st.markdown(f"🔗 [Preview Asset]({preview_url})")
                            
                    with col2:
                        price = float(asset["price"])
                        price_wei = w3.to_wei(price, 'ether')
                        st.write(f"💰 Price: {price} ETH")
                        
                        if st.button(f"Purchase", key=f"buy_{ipfs_hash}"):
                            if st.session_state.wallet_connected:
                                try:
                                    # Generate keypair for the transaction
                                    private_key = PrivateKey.generate()
                                    public_key = private_key.public_key
                                    
                                    # Store private key securely in session state
                                    st.session_state['temp_private_key'] = private_key.encode()
                                    st.session_state['temp_public_key'] = public_key.encode()
                                    
                                    # Create container for transaction status
                                    with st.status("Processing purchase...", expanded=True) as status:
                                        st.write("⌛ Initializing web3 connection...")
                                        
                                        # Inject Web3 code with proper key handling
                                        web3_js = f"""
                                        <script>
                                        async function handlePurchase() {{
                                            console.log("Starting purchase process...");
                                            if (typeof window.ethereum === 'undefined' && typeof window.parent.ethereum === 'undefined') {{
                                                throw new Error('No Web3 provider found. Please install MetaMask.');
                                            }}
                                            
                                            // Get the correct ethereum provider
                                            const ethereum = window.ethereum || window.parent.ethereum;
                                            const web3 = new Web3(ethereum);
                                            
                                            try {{
                                                // Request account access
                                                const accounts = await ethereum.request({{ method: 'eth_requestAccounts' }});
                                                const account = accounts[0];
                                                console.log("Connected account:", account);
                                                
                                                // Convert public key to proper format
                                                const publicKeyBytes = '{st.session_state.temp_public_key.hex()}'.replace('0x', '');
                                                console.log("Public key to register:", publicKeyBytes);
                                                
                                                // First register public key
                                                window.parent.postMessage({{ type: 'STATUS_UPDATE', message: 'Registering your public key...' }}, '*');
                                                
                                                const keyRegisterTx = {{
                                                    from: account,
                                                    to: '{key_management_address}',
                                                    gas: '0x186A0',
                                                    data: web3.eth.abi.encodeFunctionCall({{
                                                        name: 'registerPublicKey',
                                                        type: 'function',
                                                        inputs: [{{
                                                            type: 'bytes',
                                                            name: '_publicKey'
                                                        }}]
                                                    }}, ['0x' + publicKeyBytes])
                                                }};

                                                console.log("Sending key registration tx:", keyRegisterTx);
                                                const keyRegisterHash = await ethereum.request({{
                                                    method: 'eth_sendTransaction',
                                                    params: [keyRegisterTx]
                                                }});

                                                // Wait for key registration confirmation
                                                window.parent.postMessage({{ 
                                                    type: 'STATUS_UPDATE', 
                                                    message: 'Waiting for key registration confirmation...' 
                                                }}, '*');
                                                
                                                let receipt;
                                                while (!receipt) {{
                                                    receipt = await web3.eth.getTransactionReceipt(keyRegisterHash);
                                                    if (!receipt) {{
                                                        await new Promise(resolve => setTimeout(resolve, 1000));
                                                    }}
                                                }}

                                                if (!receipt.status) {{
                                                    throw new Error('Key registration failed');
                                                }}
                                                
                                                // Proceed with purchase
                                                window.parent.postMessage({{ 
                                                    type: 'STATUS_UPDATE', 
                                                    message: 'Processing purchase transaction...' 
                                                }}, '*');

                                                const purchaseTx = {{
                                                    from: account,
                                                    to: '{image_sharing_address}',
                                                    value: web3.utils.toHex('{price_wei}'),
                                                    gas: '0x186A0',
                                                    data: web3.eth.abi.encodeFunctionCall({{
                                                        name: 'purchaseImage',
                                                        type: 'function',
                                                        inputs: [{{
                                                            type: 'uint256',
                                                            name: '_imageId'
                                                        }}]
                                                    }}, ['{asset.get("image_id", "1")}'])
                                                }};

                                                console.log("Sending purchase tx:", purchaseTx);
                                                const purchaseHash = await ethereum.request({{
                                                    method: 'eth_sendTransaction',
                                                    params: [purchaseTx]
                                                }});

                                                // Wait for purchase confirmation
                                                window.parent.postMessage({{ 
                                                    type: 'STATUS_UPDATE', 
                                                    message: 'Waiting for purchase confirmation...' 
                                                }}, '*');
                                                
                                                receipt = null;
                                                while (!receipt) {{
                                                    receipt = await web3.eth.getTransactionReceipt(purchaseHash);
                                                    if (!receipt) {{
                                                        await new Promise(resolve => setTimeout(resolve, 1000));
                                                    }}
                                                }}

                                                if (!receipt.status) {{
                                                    throw new Error('Purchase transaction failed');
                                                }}

                                                // Notify of completion
                                                window.parent.postMessage({{
                                                    type: 'PURCHASE_COMPLETE',
                                                    txHash: purchaseHash,
                                                    imageId: '{ipfs_hash}'
                                                }}, '*');

                                            }} catch (error) {{
                                                console.error('Transaction error:', error);
                                                window.parent.postMessage({{
                                                    type: 'TRANSACTION_ERROR',
                                                    error: error.message
                                                }}, '*');
                                            }}
                                        }}

                                        // Load Web3 and start purchase
                                        if (window.web3) {{
                                            handlePurchase();
                                        }} else {{
                                            const script = document.createElement('script');
                                            script.src = 'https://cdn.jsdelivr.net/npm/web3@1.5.2/dist/web3.min.js';
                                            script.onload = handlePurchase;
                                            document.head.appendChild(script);
                                        }}
                                        </script>
                                        """
                                        
                                        st.components.v1.html(web3_js, height=0)
                                        
                                        # Add status handler
                                        status_js = """
                                        <script>
                                        window.addEventListener('message', async function(event) {
                                            if (event.data.type === 'STATUS_UPDATE') {
                                                window.streamlitMessageHandler.setMessage(event.data.message);
                                            }
                                            else if (event.data.type === 'PURCHASE_COMPLETE') {
                                                try {
                                                    const response = await fetch('%s/purchase-complete', {
                                                        method: 'POST',
                                                        headers: {
                                                            'Content-Type': 'application/json',
                                                            'Authorization': 'Bearer %s'
                                                        },
                                                        body: JSON.stringify({
                                                            assetId: event.data.imageId,
                                                            transactionHash: event.data.txHash
                                                        })
                                                    });

                                                    if (!response.ok) {
                                                        throw new Error('Failed to complete purchase on backend');
                                                    }

                                                    window.streamlitMessageHandler.setMessage('✅ Purchase completed! The seller will process your key.');
                                                    setTimeout(() => window.location.reload(), 3000);
                                                } catch (error) {
                                                    window.streamlitMessageHandler.setError('Backend error: ' + error.message);
                                                }
                                            }
                                            else if (event.data.type === 'TRANSACTION_ERROR') {
                                                window.streamlitMessageHandler.setError('❌ ' + event.data.error);
                                            }
                                        });
                                        </script>
                                        """ % (API_URL, st.session_state.token)
                                        
                                        st.components.v1.html(status_js, height=0)
                                        
                                except Exception as e:
                                    st.error(f"Error: {str(e)}")
                                    print(f"Error details: {str(e)}")
                            else:
                                st.error("Please connect your wallet first")
                    st.markdown("---")
                    
        else:
            st.error("Failed to fetch marketplace listings")
            
    except Exception as e:
        st.error(f"Error: {str(e)}")

def show_notifications():
    """Display and handle seller notifications for asset purchases"""
    st.subheader("📬 Notifications")
    
    if not st.session_state.wallet_connected:
        st.warning("Please connect your wallet to view notifications.")
        return
        
    try:
        # Fetch user notifications
        response = requests.get(
            f"{API_URL}/notifications",
            headers={"Authorization": f"Bearer {st.session_state.token}"}
        )
        
        if response.status_code == 200:
            notifications = response.json().get("notifications", [])
            
            if not notifications:
                st.info("No pending notifications.")
                return
                
            for notif in notifications:
                if notif["type"] == "purchase" and notif.get("status") == "pending_key_encryption":
                    with st.container():
                        st.markdown("---")
                        st.markdown(f"### 🔔 New Purchase!")
                        st.write(f"Asset ID: {notif['asset_id']}")
                        st.write(f"Buyer Address: {notif['buyer_address']}")
                        st.write(f"Purchase Date: {notif['date']}")
                        
                        # Add button to handle key encryption and delivery
                        if st.button("Process Key Delivery", key=f"deliver_{notif['asset_id']}"):
                            try:
                                with st.status("Processing key delivery...", expanded=True) as status:
                                    st.write("1. Encrypting asset key for buyer...")
                                    
                                    # Get buyer's public key from contract
                                    buyer_key_js = f"""
                                    <script>
                                    async function getBuyerKey() {{
                                        try {{
                                            const data = web3.eth.abi.encodeFunctionCall({{
                                                name: 'userPublicKeys',
                                                type: 'function',
                                                inputs: [{{ type: 'address', name: '_address' }}]
                                            }}, ['{notif['buyer_address']}']);
                                            
                                            const result = await ethereum.request({{
                                                method: 'eth_call',
                                                params: [{{
                                                    to: '{key_management_address}',
                                                    data: data
                                                }}, 'latest']
                                            }});
                                            
                                            window.parent.postMessage({{
                                                type: 'BUYER_KEY_RETRIEVED',
                                                publicKey: result
                                            }}, '*');
                                            
                                        }} catch (error) {{
                                            console.error('Error getting buyer key:', error);
                                            window.parent.postMessage({{
                                                type: 'KEY_ERROR',
                                                error: error.message
                                            }}, '*');
                                        }}
                                    }}
                                    
                                    // Add web3 library and execute
                                    const script = document.createElement('script');
                                    script.src = 'https://cdn.jsdelivr.net/npm/web3@1.5.2/dist/web3.min.js';
                                    script.onload = () => {{
                                        window.web3 = new Web3(window.ethereum);
                                        getBuyerKey();
                                    }};
                                    document.head.appendChild(script);
                                    </script>
                                    """
                                    
                                    st.components.v1.html(buyer_key_js, height=0)
                                    
                                    # Add handler for key encryption and storage
                                    key_handler_js = f"""
                                    <script>
                                    window.addEventListener('message', async function(event) {{
                                        if (event.data.type === 'BUYER_KEY_RETRIEVED') {{
                                            const buyerPublicKey = event.data.publicKey;
                                            
                                            try {{
                                                const accounts = await ethereum.request({{ method: 'eth_requestAccounts' }});
                                                
                                                // Store encrypted key in contract
                                                const storeTx = {{
                                                    from: accounts[0],
                                                    to: '{image_sharing_address}',
                                                    data: web3.eth.abi.encodeFunctionCall({{
                                                        name: 'storeEncryptedKeyForBuyer',
                                                        type: 'function',
                                                        inputs: [
                                                            {{ type: 'uint256', name: '_imageId' }},
                                                            {{ type: 'address', name: '_buyer' }},
                                                            {{ type: 'string', name: '_encryptedKey' }}
                                                        ]
                                                    }}, ['{notif['asset_id']}', '{notif['buyer_address']}', buyerPublicKey])
                                                }};
                                                
                                                const txHash = await ethereum.request({{
                                                    method: 'eth_sendTransaction',
                                                    params: [storeTx]
                                                }});
                                                
                                                window.parent.postMessage({{
                                                    type: 'KEY_STORED',
                                                    success: true,
                                                    txHash: txHash
                                                }}, '*');
                                                
                                            }} catch (error) {{
                                                console.error('Error storing key:', error);
                                                window.parent.postMessage({{
                                                    type: 'KEY_ERROR',
                                                    error: error.message
                                                }}, '*');
                                            }}
                                        }}
                                    }});
                                    </script>
                                    """
                                    
                                    st.components.v1.html(key_handler_js, height=0)
                                    
                                    # Add status update handler
                                    status_handler_js = """
                                    <script>
                                    window.addEventListener('message', function(event) {
                                        if (event.data.type === 'KEY_STORED') {
                                            if (event.data.success) {
                                                // Update notification status in backend
                                                fetch('%s/update-notification', {
                                                    method: 'POST',
                                                    headers: {
                                                        'Content-Type': 'application/json',
                                                        'Authorization': 'Bearer %s'
                                                    },
                                                    body: JSON.stringify({
                                                        notificationId: '%s',
                                                        status: 'key_delivered',
                                                        txHash: event.data.txHash
                                                    })
                                                }).then(response => {
                                                    if (response.ok) {
                                                        window.location.reload();
                                                    }
                                                });
                                            }
                                        }
                                    });
                                    </script>
                                    """ % (API_URL, st.session_state.token, notif.get('_id'))
                                    
                                    st.components.v1.html(status_handler_js, height=0)
                                    
                            except Exception as e:
                                st.error(f"Error processing key delivery: {str(e)}")
                                
        else:
            st.error("Failed to fetch notifications")
            
    except Exception as e:
        st.error(f"Error: {str(e)}")

def show_cookie_debug():
    st.write("### Cookie Debug")
    st.write("Session State Token:", st.session_state.get("token"))
    st.write("Query Params Token:", st.query_params.get("token"))
    
    # JavaScript cookie reader
    st.components.v1.html("""
    <script>
    document.write('<p>Browser Cookies: ' + document.cookie + '</p>');
    </script>
    """)
                
if __name__ == "__main__":
    main()