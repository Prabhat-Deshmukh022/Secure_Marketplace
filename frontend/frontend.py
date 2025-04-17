import json
import streamlit as st
import requests
from datetime import datetime
import warnings
from streamlit.deprecation_util import make_deprecated_name_warning
from streamlit_javascript import st_javascript
# Suppress experimental query params warning
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

# def show_home():

#     st.sidebar.title("Navigation")
#     page = st.sidebar.radio("Go to", ["My Assets", "Marketplace"])

#     # Display user info and logout button in sidebar
#     st.sidebar.markdown("---")
#     st.sidebar.write(f"Logged in as: **{st.session_state.current_user}**")
#     if st.sidebar.button("Logout"):
#         logout_user()

#     st.title("Welcome to the Secure Marketplace")
#     st.write("This platform allows secure exchange of digital assets using blockchain and IPFS.")

#     # Initialize wallet connection state
#     if 'wallet_connected' not in st.session_state:
#         st.session_state.wallet_connected = False
#     if 'wallet_address' not in st.session_state:
#         st.session_state.wallet_address = None

#     # Wallet Connection Section
#     if not st.session_state.wallet_connected:
#         with st.expander("🔗 Connect MetaMask Wallet"):
#             # Inject JavaScript for MetaMask connection
            # connect_js = """
            # <script>
            # async function requestSignature() {
            #     console.log("Checking for window.ethereum...");
                
            #     if (!window.ethereum) {
            #         console.log("window.ethereum is NOT available. Trying different detection methods...");
            #         if (window.parent && window.parent.ethereum) {
            #             console.log("Detected inside an iframe! Using window.parent.ethereum.");
            #             window.ethereum = window.parent.ethereum;
            #         } else {
            #             alert("MetaMask not detected! Try opening this page in a new tab.");
            #             return null;
            #         }
            #     }

            #     console.log("MetaMask detected, requesting accounts...");
            #     try {
            #         const accounts = await ethereum.request({ method: 'eth_requestAccounts' });
            #         console.log("Accounts:", accounts);
                    
            #         if (accounts.length === 0) {
            #             alert("No accounts found!");
            #             return null;
            #         }
                    
            #         const message = "Auth for " + accounts[0] + " (Testnet)";
            #         console.log("Signing message:", message);

            #         let signature;
            #         try {
            #             signature = await ethereum.request({
            #                 method: 'personal_sign',
            #                 params: [message, accounts[0]]
            #             });
            #         } catch (signError) {
            #             console.error("Error during signing:", signError);
            #             alert("Failed to sign the message. Please check the console.");
            #             return null;
            #         }

            #         if (!signature) {
            #             console.error("Signature is undefined or null.");
            #             return null;
            #         }

            #         console.log("Signature received:", signature);

            #         // Store in localStorage
            #         const walletData = JSON.stringify({
            #             type: 'WALLET_CONNECTED',
            #             address: accounts[0],
            #             signature: signature
            #         });

            #         console.log("Storing wallet data in localStorage:", walletData);
            #         window.localStorage.setItem("walletData", walletData);

            #         return walletData;

            #     } catch (error) {
            #         console.error("MetaMask Error:", error);
            #         alert("MetaMask Signature Failed! Check console.");
            #         return null;
            #     }
            # }

            # function callRequestSignature() {
            #     requestSignature().then(data => {
            #         if (data) {
            #             console.log("Wallet data successfully stored in localStorage.");
            #         } else {
            #             console.log("Failed to store wallet data.");
            #         }
            #     });
            # }
            # </script>

            # <button onclick="callRequestSignature()">Sign with MetaMask</button>
            # """

#             st.components.v1.html(connect_js, height=100)

#             wallet_data= st_javascript("window.localStorage.getItem('walletData')")

#             if wallet_data:
#                 try:
#                     data = json.loads(wallet_data)  # Convert JSON string to dictionary
#                     st.session_state.wallet_data = data  # Store in session state

#                     # Send request to Flask backend for verification
#                     response = requests.post(
#                         f"{API_URL}/verify_wallet",
#                         json={
#                             "wallet_address": data["address"],
#                             "signature": data["signature"]
#                         },
#                         headers={"Authorization": f"Bearer {st.session_state.token}"}
#                     )

#                     if response.status_code == 200:
#                         st.session_state.wallet_connected = True
#                         st.session_state.wallet_address = data["address"]
#                         st.rerun()  # Refresh to show connected state
#                     else:
#                         st.error("❌ Wallet verification failed")
#                 except Exception as e:
#                     st.error(f"Error processing wallet data: {e}")
#             else:
#                 st.warning("⚠️ No wallet data found. Please connect your wallet.")

#     # Display connection status
#     if st.session_state.wallet_connected:
#         st.success(f"🔗 Connected: {st.session_state.wallet_address[:6]}...{st.session_state.wallet_address[-4:]}")

#     if page == "My Assets":
#         show_my_assets()
#     elif page == "Marketplace":
#         show_marketplace()

# def show_home():
#     st.sidebar.title("Navigation")
#     page = st.sidebar.radio("Go to", ["My Assets", "Marketplace"])

#     # Display user info and logout button in sidebar
#     st.sidebar.markdown("---")
#     st.sidebar.write(f"Logged in as: **{st.session_state.current_user}**")
#     if st.sidebar.button("Logout"):
#         logout_user()

#     st.title("Welcome to the Secure Marketplace")
#     st.write("This platform allows secure exchange of digital assets using blockchain and IPFS.")

#     # Initialize wallet connection state
#     if 'wallet_connected' not in st.session_state:
#         st.session_state.wallet_connected = False
#     if 'wallet_address' not in st.session_state:
#         st.session_state.wallet_address = None
#     if 'waiting_for_wallet' not in st.session_state:
#         st.session_state.waiting_for_wallet = False

#     # Wallet Connection Section
#     if not st.session_state.wallet_connected:
#         with st.expander("🔗 Connect MetaMask Wallet"):
#             if st.session_state.waiting_for_wallet:
#                 st.warning("Waiting for wallet connection...")
#                 # Show a spinner while waiting
#                 with st.spinner("Please sign the message in MetaMask..."):
#                     # Poll for wallet data
#                     wallet_data = st_javascript("window.localStorage.getItem('walletData')")
                    
#                     if wallet_data:
#                         try:
#                             data = json.loads(wallet_data)
#                             st.session_state.wallet_data = data
                            
#                             # Send request to Flask backend for verification
#                             response = requests.post(
#                                 f"{API_URL}/verify_wallet",
#                                 json={
#                                     "wallet_address": data["address"],
#                                     "signature": data["signature"]
#                                 },
#                                 headers={"Authorization": f"Bearer {st.session_state.token}"}
#                             )

#                             if response.status_code == 200:
#                                 st.session_state.wallet_connected = True
#                                 st.session_state.wallet_address = data["address"]
#                                 st.session_state.waiting_for_wallet = False
#                                 st.rerun()
#                             else:
#                                 st.error("❌ Wallet verification failed")
#                                 st.session_state.waiting_for_wallet = False
#                         except Exception as e:
#                             st.error(f"Error processing wallet data: {e}")
#                             st.session_state.waiting_for_wallet = False
#                     else:
#                         # If after waiting we still don't have data, show timeout
#                         time.sleep(2)  # Wait a bit before checking again
#                         if not wallet_data:
#                             st.error("Wallet connection timed out. Please try again.")
#                             st.session_state.waiting_for_wallet = False
#                             st.rerun()
#             else:
#                 # Inject JavaScript for MetaMask connection
#                 connect_js = """
#                 <script>
#                 async function requestSignature() {
#                     console.log("Checking for window.ethereum...");
                    
#                     if (!window.ethereum) {
#                         console.log("window.ethereum is NOT available. Trying different detection methods...");
#                         if (window.parent && window.parent.ethereum) {
#                             console.log("Detected inside an iframe! Using window.parent.ethereum.");
#                             window.ethereum = window.parent.ethereum;
#                         } else {
#                             alert("MetaMask not detected! Try opening this page in a new tab.");
#                             return null;
#                         }
#                     }

#                     console.log("MetaMask detected, requesting accounts...");
#                     try {
#                         const accounts = await ethereum.request({ method: 'eth_requestAccounts' });
#                         console.log("Accounts:", accounts);
                        
#                         if (accounts.length === 0) {
#                             alert("No accounts found!");
#                             return null;
#                         }
                        
#                         const message = "Auth for " + accounts[0] + " (Testnet)";
#                         console.log("Signing message:", message);

#                         let signature;
#                         try {
#                             signature = await ethereum.request({
#                                 method: 'personal_sign',
#                                 params: [message, accounts[0]]
#                             });
#                         } catch (signError) {
#                             console.error("Error during signing:", signError);
#                             alert("Failed to sign the message. Please check the console.");
#                             return null;
#                         }

#                         if (!signature) {
#                             console.error("Signature is undefined or null.");
#                             return null;
#                         }

#                         console.log("Signature received:", signature);

#                         // Store in localStorage
#                         const walletData = JSON.stringify({
#                             type: 'WALLET_CONNECTED',
#                             address: accounts[0],
#                             signature: signature
#                         });

#                         console.log("Storing wallet data in localStorage:", walletData);
#                         window.localStorage.setItem("walletData", walletData);

#                         return walletData;

#                     } catch (error) {
#                         console.error("MetaMask Error:", error);
#                         alert("MetaMask Signature Failed! Check console.");
#                         return null;
#                     }
#                 }

#                 function callRequestSignature() {
#                     requestSignature().then(data => {
#                         if (data) {
#                             console.log("Wallet data successfully stored in localStorage.");
#                             // Notify Streamlit that we have data
#                             window.parent.postMessage({type: 'WALLET_CONNECTED'}, '*');
#                         } else {
#                             console.log("Failed to store wallet data.");
#                         }
#                     });
#                 }
#                 </script>

#                 <button onclick="callRequestSignature()">Sign with MetaMask</button>
#                 """

#                 st.components.v1.html(connect_js, height=100)
                
#                 # Check for existing wallet data
#                 wallet_data = st_javascript("window.localStorage.getItem('walletData')")
                
#                 if wallet_data:
#                     try:
#                         data = json.loads(wallet_data)
#                         st.session_state.wallet_data = data
                        
#                         # Send request to Flask backend for verification
#                         response = requests.post(
#                             f"{API_URL}/verify_wallet",
#                             json={
#                                 "wallet_address": data["address"],
#                                 "signature": data["signature"]
#                             },
#                             headers={"Authorization": f"Bearer {st.session_state.token}"}
#                         )

#                         if response.status_code == 200:
#                             st.session_state.wallet_connected = True
#                             st.session_state.wallet_address = data["address"]
#                             st.rerun()
#                         else:
#                             st.error("❌ Wallet verification failed")
#                     except Exception as e:
#                         st.error(f"Error processing wallet data: {e}")
#                 else:
#                     if st.button("Connect Wallet"):
#                         st.session_state.waiting_for_wallet = True
#                         st.rerun()

#     # Display connection status
#     if st.session_state.wallet_connected:
#         st.success(f"🔗 Connected: {st.session_state.wallet_address[:6]}...{st.session_state.wallet_address[-4:]}")

#     if page == "My Assets":
#         show_my_assets()
#     elif page == "Marketplace":
#         show_marketplace()

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
        show_my_assets()
    elif page == "Marketplace":
        show_marketplace()# Function to inject JavaScript to listen for wallet data

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
        price = st.number_input("Price*", value=float(st.session_state.form_data['price']), min_value=0.0, step=0.01)
        file = st.file_uploader("Asset File*", type=["png", "jpg", "jpeg", "gif", "mp4", "mov", "pdf", "glb"])

        submitted = st.form_submit_button("Upload to IPFS")
        
        if submitted:
            if not all([asset_name, file]):
                st.error("Please fill all required fields (*)")
            else:
                try:
                    # Store file bytes immediately
                    file_bytes = file.getvalue()
                    
                    with st.spinner("Uploading to IPFS..."):
                        # Prepare the request properly
                        files = {
                            'file': (file.name, file_bytes, file.type)
                        }
                        data = {
                            'name': asset_name,
                            'description': description,
                            'price': str(price)
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
                            st.success("Upload successful!")
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
                    col1, col2 = st.columns([1, 3])
                    
                    with col1:
                        st.write(f"📄 {asset['file_name']}")
                    
                    with col2:
                        st.subheader(asset["name"])
                        st.write(asset["description"])
                        st.write(f"🆔 IPFS CID: `{asset['ipfs_hash']}`")
                        st.write(f"💰 Price: {asset['price']} ETH")
                        st.write(f"📅 Uploaded: {asset['created_at']}")
                        
                        # Add a Put for Sale button
                        if st.button("Put for Sale", key=f"sale_{asset['ipfs_hash']}"):
                            try:
                                sale_response = session.post(
                                    f"{API_URL}/sale",
                                    json={"ipfs_hash": asset["ipfs_hash"]},
                                    headers={"Authorization": f"Bearer {st.session_state.token}"}
                                )
                                
                                if sale_response.status_code == 200:
                                    st.success(f"Asset '{asset['name']}' is now available for sale!")
                                else:
                                    error_message = sale_response.json().get("message", "Failed to put asset for sale.")
                                    st.error(f"Error: {error_message}")
                            except Exception as e:
                                st.error(f"Error putting asset for sale: {str(e)}")
                    
                    st.markdown("---")
        else:
            st.error("Failed to fetch assets.")
    except Exception as e:
        st.error(f"Error loading assets: {str(e)}")    

def show_marketplace():
    st.title("Marketplace")
    st.write("Browse and buy digital assets from other users.")

    try:
        # Fetch assets from the backend
        response = session.get(
            f"{API_URL}/display-all-assets",
            headers={"Authorization": f"Bearer {st.session_state.token}"}
        )

        # Check if the request was successful
        if response.status_code != 200:
            error_message = response.json().get("error", "Failed to fetch assets")
            st.error(f"Error: {error_message}")
            return

        # Parse the assets from the response
        assets = response.json().get("assets", [])

        # Check if there are any assets available
        if not assets:
            st.info("No assets are currently available for sale.")
            return

        # Display the assets
        for item in assets:
            with st.container():
                st.write(f"**{item.get('name', 'Unnamed Asset')}**")
                st.write(f"👤 Owner: {item.get('author', 'Unknown')}")
                st.write(f"🔗 IPFS ID: {item.get('ipfs_hash', 'N/A')}")
                st.write(f"💰 Price: {item.get('price', 'N/A')} ETH")
                if st.button(f"Buy {item.get('name', 'Unnamed Asset')}", key=f"buy_{item.get('ipfs_hash', '')}"):
                    st.success(f"Purchased {item.get('name', 'Unnamed Asset')} successfully! Transaction will be processed.")
                st.markdown("---")

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

# def update_asset_details(asset_id):
#     st.title("Update Asset Details")
#     st.write(f"Updating asset with ID: {asset_id}")  # Debug log

#     # Fetch the current asset details from the backend
#     try:
#         response = session.get(
#             f"{API_URL}/user_assets",
#             headers={"Authorization": f"Bearer {st.session_state.token}"}
#         )

#         if response.status_code != 200:
#             st.error("Failed to fetch your assets. Please try again.")
#             return

#         # Find the asset by asset_id
#         assets = response.json().get("assets", [])
#         asset = next((a for a in assets if a["ipfs_hash"] == asset_id), None)

#         if not asset:
#             st.error("Asset not found.")
#             return

#     except Exception as e:
#         st.error(f"Error fetching asset details: {str(e)}")
#         return

#     # Display the current asset details
#     st.subheader("Current Asset Details")
#     st.write(f"**Name:** {asset.get('name', 'Unnamed Asset')}")
#     st.write(f"**Description:** {asset.get('description', 'No description available')}")
#     st.write(f"**Price:** {asset.get('price', 'N/A')} ETH")
#     st.write(f"**IPFS Hash:** {asset.get('ipfs_hash', 'N/A')}")

#     # Form to update asset details
#     with st.form("update_asset_form"):
#         new_name = st.text_input("New Name", value=asset.get("name", ""))
#         new_description = st.text_area("New Description", value=asset.get("description", ""))
#         new_price = st.number_input("New Price (ETH)", value=float(asset.get("price", 0.0)), min_value=0.0, step=0.01)

#         submitted = st.form_submit_button("Update Asset")

#         if submitted:
#             payload = {}
#             if new_name:
#                 payload["name"] = new_name
#             if new_description:
#                 payload["description"] = new_description
#             if new_price is not None:
#                 payload["price"] = new_price

#             if not payload:
#                 st.warning("No changes made to the asset.")
#                 return

#             try:
#                 update_response = session.put(
#                     f"{API_URL}/update-asset/{asset_id}",
#                     json=payload,
#                     headers={"Authorization": f"Bearer {st.session_state.token}"}
#                 )

#                 if update_response.status_code == 200:
#                     st.success("Asset updated successfully!")
#                     st.session_state.update_asset_id = None
#                     st.experimental_rerun()
#                 elif update_response.status_code == 404:
#                     st.error("Asset not found.")
#                 elif update_response.status_code == 400:
#                     st.error(update_response.json().get("message", "Invalid request."))
#                 else:
#                     st.error("Failed to update the asset. Please try again.")

#             except Exception as e:
#                 st.error(f"Error updating asset: {str(e)}")

#     # Cancel button
#     if st.button("Cancel"):
#         st.session_state.update_asset_id = None
#         st.experimental_rerun()
                
if __name__ == "__main__":
    main()