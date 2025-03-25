import streamlit as st
import requests
from datetime import datetime
import warnings
from streamlit.deprecation_util import make_deprecated_name_warning

# Suppress experimental query params warning
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
    if "show_signup" not in st.session_state:  # Add this line
        st.session_state.show_signup = False   # Default to showing login page
    
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
    
    wallet_id = st.text_input("Enter your MetaMask Wallet ID to connect", value="0x123456789ABCDEF")
    if st.button("Connect Wallet"):
        st.success("Wallet Connected: " + wallet_id)
    
    if page == "My Assets":
        show_my_assets()
    elif page == "Marketplace":
        show_marketplace()

def logout_user():
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
    st.write("Upload your digital assets securely to IPFS and put them for sale.")
    
    with st.form("upload_asset_form"):
        asset_name = st.text_input("Asset Name")
        asset_description = st.text_area("Description")
        price_range = st.text_input("Price Range (ETH)")
        expiry_date = st.date_input("Expiry Date")
        file = st.file_uploader("Upload Asset", type=["png", "jpg", "mp4", "pdf"])
        submit = st.form_submit_button("Upload Asset")
        
        if submit and file:
            asset_id = "QmTest123..."  # Fake IPFS ID for testing
            st.success(f"Asset uploaded! IPFS ID: {asset_id}")
    
    st.write("**Your Uploaded Assets:**")
    
    # Mock asset data
    mock_assets = [
        {"name": "Digital Art #1", "ipfs_id": "QmArt123...", "price": "0.3 ETH", "status": "Available"},
        {"name": "Rare Music Track", "ipfs_id": "QmMusic456...", "price": "1.2 ETH", "status": "Unavailable"},
    ]
    
    for asset in mock_assets:
        st.write(f"**{asset['name']}**")
        st.write(f"🔗 IPFS ID: {asset['ipfs_id']}") 
        st.write(f"💰 Price: {asset['price']}")
        st.write(f"📌 Status: {asset['status']}")
        if asset["status"] == "Available":
            if st.button(f"Mark '{asset['name']}' as Unavailable", key=f"unavailable_{asset['ipfs_id']}"):
                st.warning(f"{asset['name']} is now unavailable.")
        else:
            if st.button(f"Put '{asset['name']}' for Sale", key=f"available_{asset['ipfs_id']}"):
                st.success(f"{asset['name']} is now available for sale!")
        st.markdown("---")

def show_marketplace():
    st.title("Marketplace")
    st.write("Browse and buy digital assets from other users.")
    
    # Mock marketplace data
    mock_marketplace = [
        {"name": "Exclusive NFT Art", "owner": "0xA1B2C3D4", "ipfs_id": "QmNFT999...", "price": "0.5 ETH"},
        {"name": "Virtual Land Parcel", "owner": "0xF9E8D7C6", "ipfs_id": "QmLand789...", "price": "2.0 ETH"},
    ]
    
    for item in mock_marketplace:
        st.write(f"**{item['name']}**")
        st.write(f"👤 Owner: {item['owner']}")
        st.write(f"🔗 IPFS ID: {item['ipfs_id']}")
        st.write(f"💰 Price: {item['price']}")
        if st.button(f"Buy {item['name']}", key=f"buy_{item['ipfs_id']}"):
            st.success(f"Purchased {item['name']} successfully! Transaction will be processed.")
        st.markdown("---")

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