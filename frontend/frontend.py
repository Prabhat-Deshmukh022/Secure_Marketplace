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
import sys

# Load environment variables
load_dotenv(override=True)
load_dotenv('.env.test')

# Initialize Web3
w3 = Web3(Web3.HTTPProvider(os.getenv('WEB3_PROVIDER_URL')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.blockchain_manager import BlockchainManager

blockchain_manager = BlockchainManager()
marketplace_address=os.getenv("MARKET_PLACE_ADDRESS")
assetownership_address=os.getenv("ASSET_OWNERSHIP_ADDRESS")

with open(r'D:\6th_Semester\BC_PES1UG22CS419\Project\decentralized_storage_project\contracts\ListMarketPlace.json') as f:
    marketplace_abi = json.load(f)

with open(r'D:\6th_Semester\BC_PES1UG22CS419\Project\decentralized_storage_project\contracts\AssetOwnerShip.json') as f:
    assetownership_abi = json.load(f)

marketplace_abi_json = json.dumps(marketplace_abi)
assetownership_abi_json = json.dumps(assetownership_abi)

# # Load contract ABIs
# with open(r'D:\6th_Semester\BC_PES1UG22CS419\Project\decentralized_storage_project\contracts\SecureImageSharing.json') as f:
#     image_sharing_abi = json.load(f)['abi']
# with open(r'D:\6th_Semester\BC_PES1UG22CS419\Project\decentralized_storage_project\contracts\KeyManagement.json') as f:
#     key_management_abi = json.load(f)['abi']

# # Initialize contracts
# image_sharing_address = os.getenv('IMAGE_SHARING_CONTRACT')
# key_management_address = os.getenv('KEY_MANAGEMENT_CONTRACT')
# image_sharing_contract = w3.eth.contract(address=image_sharing_address, abi=image_sharing_abi)
# key_management_contract = w3.eth.contract(address=key_management_address, abi=key_management_abi)

import time
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Create a session object to handle cookies
session = requests.Session()
session.headers.update({"Content-Type": "application/json"})

# Backend API URL
API_URL = "http://127.0.0.1:5000"

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
    # if st.session_state.get("update_asset_id"):
    #     update_asset_details(st.session_state.update_asset_id)
    # else:
    #     display_user_assets()

    # Route to appropriate page
    if st.session_state.show_signup:
        show_signup()
    elif not st.session_state.authenticated:
        show_login()
    else:
        # register_wallet_listener()
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
                        # st.session_state.current_user = token
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
    page = st.sidebar.radio("Go to", ["My Assets", "Marketplace"])

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

    # Display connection status
    if st.session_state.wallet_connected:
        st.success(f"🔗 Connected: {st.session_state.wallet_address[:6]}...{st.session_state.wallet_address[-4:]}")

    if page == "My Assets":
        upload_and_register_asset()
    elif page == "Marketplace":
        show_marketplace()

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


def upload_and_register_asset():
    st.title("Upload Digital Asset & Register Ownership")

    name = st.text_input("Name")
    uploaded_file = st.file_uploader("Choose your file")
    description = st.text_input("Asset description")
    price = st.text_input("Set price (ETH)", "0.01")
    list_to_marketplace = st.checkbox("List this asset on the marketplace?")

    if st.button("Upload & Register"):
        if not uploaded_file:
            st.error("Please upload a file first.")
            return

        # Step 1: Send file to backend for IPFS upload
        files = {'file': uploaded_file}
        data = {
            'description': description,
            'price': price,
            'list_to_marketplace': list_to_marketplace,
            'name':name
        }
        headers = {'Authorization': f'Bearer {st.session_state.token}'}

        response = requests.post(f"{API_URL}/upload_asset_ipfs", files=files, data=data, headers=headers)

        if response.status_code != 200:
            st.error(f"Upload failed: {response.json().get('error')}")
            return

        resp = response.json()
        file_cid = resp['file_cid']

        st.success(f"Asset uploaded to IPFS! CID: {file_cid}")
        st.info("Now sign the ownership registration transaction with MetaMask...")

        # Step 2: Inject JavaScript to call contract
        assetownership_address_in_js = assetownership_address
        assetownership_abi_json_in_js = assetownership_abi_json # Your ABI here

        tx_js = f"""
        <script>
        async function registerAssetOnBlockchain() {{
            try {{
                const contractABI = {assetownership_abi_json_in_js};

                if (typeof window.ethereum === 'undefined') {{
                    if (window.parent && window.parent.ethereum) {{
                        window.ethereum = window.parent.ethereum;
                    }} else {{
                        alert("MetaMask not detected! Try opening this page in a new tab.");
                        return;
                    }}
                }}

                const web3 = new Web3(window.ethereum);
                const accounts = await window.ethereum.request({{ method: 'eth_requestAccounts' }});

                const contract = new web3.eth.Contract(contractABI, '{assetownership_address_in_js}');
                const transactionData = contract.methods.registerAsset('{file_cid}').encodeABI();

                const transactionParameters = {{
                    to: '{assetownership_address_in_js}',
                    from: accounts[0],
                    data: transactionData,
                    gas: '0x4C4B40'
                }};

                const txHash = await window.ethereum.request({{
                    method: 'eth_sendTransaction',
                    params: [transactionParameters]
                }});

                alert("Transaction sent! Waiting for confirmation...");

                let receipt = null;
                while (!receipt) {{
                    receipt = await web3.eth.getTransactionReceipt(txHash);
                    await new Promise(resolve => setTimeout(resolve, 3000));
                }}

                if (receipt.status) {{
                    fetch("{API_URL}/confirm_asset_registration", {{
                        method: "POST",
                        headers: {{
                            "Content-Type": "application/json",
                            "Authorization": "Bearer {st.session_state.token}"
                        }},
                        body: JSON.stringify({{
                            tx_hash: txHash,
                            ipfs_cid: "{file_cid}",
                            wallet_address: accounts[0]
                        }})
                    }})
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) {{
                            alert("✅ Asset successfully registered and confirmed!");
                        }} else {{
                            alert("❌ Server rejected the transaction: " + data.error);
                        }}
                    }})
                    .catch(err => {{
                        console.error("Error sending confirmation:", err);
                        alert("Failed to confirm registration with server.");
                    }});
                }} else {{
                    alert("❌ Transaction failed on blockchain.");
                }}
            }} catch (error) {{
                console.error("Error during registration:", error);
                alert("Error: " + error.message);
            }}
        }}

        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/web3@1.5.2/dist/web3.min.js';
        script.onload = registerAssetOnBlockchain;
        document.head.appendChild(script);
        </script>
        """
        st.components.v1.html(tx_js, height=0)
    st.header("Assets")
    display_user_assets()


def display_user_assets():
    """Fetch and display user's assets from backend with Update and Put for Sale buttons."""
    st.title("Your Assets")
    try:
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

                            # Disable the button once clicked
                            button_disabled = False

                            if 'listing_in_progress' in st.session_state and st.session_state.listing_in_progress:
                                button_disabled = True
                            
                            if st.button("List to Marketplace", key=list_button_key, disabled=button_disabled):
                                st.session_state.listing_in_progress = True
                                st.info("Please sign the transaction via MetaMask...")

                                # asset_id = int(asset["asset_id"])
                                # price = asset["price"]

                                print("ASSET, IN LISTING", asset['asset_id'])

                                list_js = f"""
                                    <script>
                                    async function safeListAssetForSale() {{
                                        try {{
                                            const contractABI_AssetOwnership = {assetownership_abi_json};  // Replace with actual ABI JSON
                                            const contractABI_Marketplace = {marketplace_abi_json};
                                            const ownershipAddress = "{assetownership_address}";
                                            const marketplaceAddress = "{marketplace_address}";
                                            const ipfsCID = "{asset['ipfs_hash']}";
                                            const priceEth = "{asset['price']}";
                                            const expectedAssetId = "{asset['asset_id']}";

                                            if (typeof window.ethereum === 'undefined') {{
                                                if (window.parent && window.parent.ethereum) {{
                                                    window.ethereum = window.parent.ethereum;
                                                }} else {{
                                                    alert("MetaMask not detected!");
                                                    return;
                                                }}
                                            }}

                                            const web3 = new Web3(window.ethereum);
                                            const accounts = await window.ethereum.request({{ method: 'eth_requestAccounts' }});
                                            const sender = accounts[0];

                                            const ownershipContract = new web3.eth.Contract(contractABI_AssetOwnership, ownershipAddress);
                                            const marketplaceContract = new web3.eth.Contract(contractABI_Marketplace, marketplaceAddress);

                                            let onChainOwner = await ownershipContract.methods.getOwner(expectedAssetId).call();

                                            console.log(`On-chain owner is: ${{onChainOwner}}`);
                                            
                                            if (onChainOwner.toLowerCase() === '0x0000000000000000000000000000000000000000') {{
                                                alert("Asset not registered on-chain. Registering now...");

                                                const registerTx = await ownershipContract.methods.registerAsset(ipfsCID).send({{
                                                    from: sender
                                                }});

                                                console.log('Asset registered:', registerTx.transactionHash);
                                                alert('Asset successfully registered!');
                                            }} else if (onChainOwner.toLowerCase() !== sender.toLowerCase()) {{
                                                alert(`Cannot list asset. Owner mismatch. Contract says: ${{onChainOwner}}`);
                                                return;
                                            }} else {{
                                                console.log('Asset is already owned by you. Proceeding to listing.');
                                            }}

                                            const priceWei = web3.utils.toWei(priceEth, 'ether');
                                            const transactionData = marketplaceContract.methods.listAssetForSale(expectedAssetId, priceWei).encodeABI();

                                            const txParams = {{
                                                to: marketplaceAddress,
                                                from: sender,
                                                data: transactionData,
                                                gas: '0x4C4B40'
                                            }};

                                            const txHash = await window.ethereum.request({{
                                                method: 'eth_sendTransaction',
                                                params: [txParams]
                                            }});

                                            console.log("Transaction sent! Hash:", txHash);

                                            let receipt = null;
                                            while (!receipt) {{
                                                console.log('Waiting for receipt...');
                                                receipt = await web3.eth.getTransactionReceipt(txHash);
                                                await new Promise(resolve => setTimeout(resolve, 3000));
                                            }}

                                            if (receipt.status) {{
                                                alert("Asset listed on blockchain! Confirming with server...");

                                                fetch("{API_URL}/confirm_sale", {{
                                                    method: "POST",
                                                    headers: {{
                                                        "Content-Type": "application/json",
                                                        "Authorization": "Bearer {st.session_state.token}"
                                                    }},
                                                    body: JSON.stringify({{
                                                        tx_hash: txHash,
                                                        ipfs_hash: ipfsCID,
                                                        wallet_address: sender
                                                    }})
                                                }})
                                                .then(response => response.json())
                                                .then(data => {{
                                                    if (data.success) {{
                                                        alert("Sale listing confirmed on server!");
                                                        window.location.reload();
                                                    }} else {{
                                                        alert("Server rejected the sale: " + data.error);
                                                    }}
                                                }})
                                                .catch(err => {{
                                                    console.error("Error confirming with server:", err);
                                                    alert("Could not confirm with server.");
                                                }});
                                            }} else {{
                                                alert("Blockchain transaction failed.");
                                            }}

                                        }} catch (error) {{
                                            console.error("Error during sale listing:", error);
                                            alert("Error: " + error.message);
                                        }}
                                    }}

                                    const script = document.createElement('script');
                                    script.src = 'https://cdn.jsdelivr.net/npm/web3@1.5.2/dist/web3.min.js';
                                    script.onload = safeListAssetForSale;
                                    document.head.appendChild(script);
                                    </script>
                                    """

                                st.components.v1.html(list_js, height=0)

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
                        st.subheader(asset.get("name", "Untitled Asset"))
                        st.write(asset.get("description", "No description available"))
                        st.write(f"👤 Author: {asset.get('author', 'Unknown')}")

                    with col2:
                        price = float(asset.get("price", 0))
                        st.write(f"💰 Price: {price} ETH")

                        asset_id = int(asset.get("asset_id", "null"))

                        print("ASSET ", asset)
                        print("ASSET ID", asset_id)

                        # JavaScript code to trigger MetaMask on button click
                        html_code = f"""
                    <script src="https://cdn.jsdelivr.net/npm/web3@1.10.0/dist/web3.min.js"></script>
                    <script>
                    async function purchaseAsset() {{
                        console.log("Checking for MetaMask...");

                        // Check if MetaMask (window.ethereum) is available
                        if (typeof window.ethereum === 'undefined') {{
                            console.log("MetaMask is not installed!");

                            // If the app is inside an iframe, try accessing window.parent.ethereum
                            if (window.parent && window.parent.ethereum) {{
                                console.log("Detected inside an iframe! Using window.parent.ethereum.");
                                window.ethereum = window.parent.ethereum;
                            }} else {{
                                alert("MetaMask not detected! Try opening this page in a new tab.");
                                return;
                            }}
                        }}

                        // Initialize Web3 with MetaMask provider
                        const web3 = new Web3(window.ethereum);
                        console.log('web3 initialized')

                        // Request MetaMask accounts
                        await window.ethereum.request({{ method: 'eth_requestAccounts' }});
                        console.log('metamask account requested')

                        const contractABI = {marketplace_abi_json}; // Embed the ABI as JSON
                        const contractAddress = "{marketplace_address}";
                        const contract = new web3.eth.Contract(contractABI, contractAddress);
                        console.log('contract here'+contract)

                        const priceInWei = web3.utils.toWei("{price}", 'ether');
                        const accounts = await web3.eth.getAccounts();
                        const sender = accounts[0];
                        console.log('sender is '+sender)

                        try {{
                            // Send the transaction to purchase the asset
                            const tx = await contract.methods.buyAsset("{asset_id}").send({{
                                from: sender,
                                value: priceInWei
                            }});
                            console.log("after sender received"+tx)

                            const txHash = tx.transactionHash;

                            console.log('txHash is'+txHash)

                            // Ownership transfer must happen as a separate transaction after purchase.
                            const assetOwnershipABI = {assetownership_abi_json}; // Embed the ABI for AssetOwnership
                            const assetOwnershipAddress = "{assetownership_address}"; // AssetOwnership contract address
                            const assetOwnershipContract = new web3.eth.Contract(assetOwnershipABI, assetOwnershipAddress);

                            // Transfer ownership to the buyer
                            await assetOwnershipContract.methods.transferOwnership("{asset_id}", sender).send({{
                                from: sender
                            }});

                            // Notify the backend about the purchase
                            fetch("{API_URL}/buy", {{
                                method: "POST",
                                headers: {{
                                    "Content-Type": "application/json",
                                    "Authorization": "Bearer {st.session_state.token}"
                                }},
                                body: JSON.stringify({{
                                    "asset_id": {asset_id},
                                    "tx_hash": txHash,
                                    "sender":sender
                                }})
                            }}).then(res => res.json()).then(data => {{
                                if (data.status === "success") {{
                                    alert("✅ Purchase successful and saved!");
                                    window.location.reload();  // Reload the page to reflect the change
                                }} else {{
                                    alert("⚠️ Error: " + JSON.stringify(data));
                                }}
                            }});

                        }} catch (err) {{
                            console.error(err);
                            alert("Transaction failed or rejected.");
                        }}
                    }}
                    </script>

                    <button onclick="purchaseAsset()">Purchase</button>
                    """
                    st.components.v1.html(html_code, height=150)

                st.markdown("---")
        else:
            st.error("Failed to fetch marketplace listings.")
    except requests.exceptions.RequestException as e:
        st.error(f"Network error: {str(e)}")
    except Exception as e:
        st.error(f"An unexpected error occurred: {str(e)}")

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