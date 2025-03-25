# Secure Digital Asset Marketplace

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green)
![Streamlit](https://img.shields.io/badge/Streamlit-1.10%2B-red)
![JWT](https://img.shields.io/badge/JWT-Auth-orange)

A secure platform for trading digital assets using blockchain principles, featuring:
- JWT authentication with Flask backend
- Streamlit frontend with persistent sessions
- MongoDB user management
- IPFS asset storage

## 🌟 Features

### Authentication
- User registration & login/logout
- JWT token validation
- Password hashing with bcrypt
- Persistent sessions across page refreshes

### Marketplace
- Upload digital assets with metadata
- Browse available assets
- Purchase system

### Tech Stack
| Component       | Technology               |
|-----------------|--------------------------|
| Backend         | Flask (Python)           |
| Frontend        | Streamlit                |
| Database        | MongoDB                  |
| Authentication  | JWT (PyJWT)              |
| Security        | bcrypt, HTTP-only cookies|

## 🛠 Setup

### Prerequisites
- Python 3.9+
- MongoDB instance
- Pipenv (recommended)

### Installation
```bash
# Clone repository
git clone https://github.com/yourusername/Secure_Marketplace.git
cd Secure_Marketplace

# Install dependencies
pipenv install
pipenv shell

# Set environment variables
cp .env.example .env
# Edit .env with your MongoDB and secret key
```

### How to run

```bash
# Start Flask backend (port 5000)
python backend/app.py

# Start Streamlit frontend (port 8501)
streamlit run frontend/frontend.py
```

### Folder structure
```bash
.
├── backend/
│   ├── app.py               # Flask main application
│   ├── db_connect.py        # MongoDB connection
│   └── jwt_generate.py      # JWT token utilities
├── frontend/
│   ├── frontend.py               # Streamlit application
├── .env.example             # Environment template
└── README.md
```
