# 🔐 Secure File Exchange System - CMPS 380

A comprehensive cybersecurity demonstration and practical toolkit implementing hybrid cryptography (RSA-OAEP + AES-GCM + RSA-PSS) for secure document exchange.

## 🌟 Project Overview

This project provides **4 interactive screens** for learning and using cryptographic file exchange:

### 1. 🏠 **Landing Page** (`/`)
Professional home page with:
- Hero section introducing the system
- Feature cards for each tool
- Educational content about hybrid cryptography
- Navigation to all three main features

### 2. 👥 **Alice & Bob Demo** (`/demo`)
Interactive demonstration of secure document exchange between two parties:
- **Step 1**: RSA-2048 keypair generation (signing + encryption keys)
- **Step 2**: Public key exchange and binding with digital signatures
- **Step 3**: File encryption using hybrid cryptography (AES-256-GCM + RSA-OAEP)
- **Step 4**: Signature verification with RSA-PSS
- **Step 5**: File decryption and integrity verification
- **Attack simulations**: Tampering, replay, MITM attacks
- Real-time visualization of cryptographic operations

### 3. 🔒 **File Encryption Tool** (`/encrypt`)
Standalone encryption utility:
- Upload any file for encryption
- Automatic AES-256-GCM key generation
- Download encrypted envelope (contains encrypted file + key)
- Share envelope securely with recipients
- View encryption metrics and file hashes

### 4. 🔓 **File Decryption Tool** (`/decrypt`)
Standalone decryption utility:
- Upload encrypted envelope
- Automatic key extraction and validation
- Integrity verification with authentication tags
- Download original decrypted file
- Replay attack protection

## 🚀 Features

### Cryptographic Implementations
- ✅ **RSA-2048** keypair generation
- ✅ **RSA-OAEP** for key wrapping/unwrapping
- ✅ **AES-256-GCM** for authenticated encryption
- ✅ **RSA-PSS** for digital signatures
- ✅ **SHA-256** for hashing
- ✅ Nonce-based replay protection
- ✅ Authentication tag verification

### User Experience
- 🎨 Modern, responsive UI design
- 📱 Mobile-friendly interface
- 🎭 Interactive animations
- 📊 Real-time progress indicators
- 💾 Downloadable encrypted envelopes
- 🔍 Detailed cryptographic metrics

## 🛠️ Technology Stack

- **Backend**: Python 3.x with Flask
- **Cryptography**: `cryptography` library (hazmat primitives)
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Styling**: Custom CSS with CSS Grid and Flexbox
- **Architecture**: RESTful API design

## 📦 Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd cmps380-project
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the application**
```bash
python app.py
```

4. **Open in browser**
Navigate to: `http://127.0.0.1:5000`

## 📂 Project Structure

```
cmps380-project/
├── app.py                      # Flask backend with all routes and crypto logic
├── requirements.txt            # Python dependencies
├── templates/
│   ├── home.html              # Landing page (NEW)
│   ├── demo.html              # Alice-Bob demonstration (renamed from index.html)
│   ├── encrypt.html           # Encryption tool (NEW)
│   └── decrypt.html           # Decryption tool (NEW)
├── static/
│   ├── styles.css             # Unified stylesheet for all screens
│   ├── home.js                # Landing page interactions (NEW)
│   ├── app.js                 # Demo page logic
│   ├── encrypt.js             # Encryption tool logic (NEW)
│   └── decrypt.js             # Decryption tool logic (NEW)
└── README_NEW.md
```

## 🔑 API Endpoints

### Demo Endpoints (Alice-Bob)
- `POST /api/generate-keys` - Generate RSA keypairs
- `POST /api/bind-public-key` - Sign public key with private signing key
- `POST /api/verify-binding` - Verify public key signature
- `POST /api/encrypt-file` - Encrypt file with hybrid cryptography
- `POST /api/verify-signature` - Verify envelope signature
- `POST /api/decrypt-file` - Decrypt and verify file

### Standalone Tool Endpoints (NEW)
- `POST /api/standalone-encrypt` - Encrypt file (returns envelope with key)
- `POST /api/standalone-decrypt` - Decrypt file from envelope

## 🎓 Educational Value

This project demonstrates:

1. **Hybrid Cryptography**: Combining symmetric (AES) and asymmetric (RSA) encryption
2. **Key Management**: Secure key generation, exchange, and binding
3. **Digital Signatures**: Non-repudiation and authenticity verification
4. **Authenticated Encryption**: Confidentiality + integrity with AES-GCM
5. **Attack Prevention**: Replay protection, tampering detection, MITM prevention
6. **Real-world Application**: Practical file encryption/decryption tools

## 🔒 Security Features

- **Confidentiality**: AES-256-GCM encryption
- **Integrity**: Authentication tags prevent tampering
- **Authenticity**: RSA-PSS digital signatures
- **Non-repudiation**: Cryptographic proof of sender identity
- **Replay Protection**: Nonce tracking prevents message replay
- **Key Security**: RSA-OAEP protects symmetric keys

## 📖 How to Use

### Encrypt a File
1. Navigate to `/encrypt`
2. Upload your file (any format)
3. Click "Encrypt File"
4. Download the encrypted envelope (.json)
5. Share envelope with recipient

### Decrypt a File
1. Navigate to `/decrypt`
2. Upload the encrypted envelope (.json)
3. Click "Decrypt File"
4. Download your original file

### See the Demo
1. Navigate to `/demo`
2. Select transfer direction (Alice → Bob or Bob → Alice)
3. Choose a sample file or upload custom file
4. Click "Start Transfer"
5. Follow the step-by-step cryptographic process
6. Try attack simulations to see security in action

## 🎯 Learning Objectives

Students will understand:
- How hybrid encryption systems work
- The role of digital signatures in security
- Public key infrastructure (PKI) concepts
- Authenticated encryption with associated data (AEAD)
- Common cryptographic attacks and countermeasures
- Practical implementation of cryptographic standards

## 🆕 What's New - 4-Screen Enhancement

### Previous Version
- Single demonstration screen (Alice-Bob only)
- Limited to educational demo purposes
- No standalone encryption/decryption tools

### Current Version
✨ **Landing Page**: Professional entry point with clear navigation
✨ **Alice-Bob Demo**: Enhanced educational demonstration (preserved)
✨ **Encryption Tool**: Practical standalone file encryption utility
✨ **Decryption Tool**: Practical standalone file decryption utility
✨ **Unified Design**: Consistent, modern UI across all screens
✨ **Mobile Responsive**: Works seamlessly on all devices
✨ **Enhanced UX**: Progress indicators, animations, detailed feedback

## 🤝 Contributing

This is a course project for CMPS 380 - Cybersecurity Fundamentals.

## 📝 License

Educational use - CMPS 380 Project

## 👥 Authors

Course: Cybersecurity Fundamentals (CMPS 380)

---

**⚠️ Note**: This is an educational demonstration. For production use, additional security measures and proper key management systems would be required.

## 🐛 Troubleshooting

### Port Already in Use
If port 5000 is occupied:
```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Or run on different port
flask run --port 5001
```

### Module Not Found
```bash
pip install -r requirements.txt
```

### Browser Caching Issues
Hard refresh: `Ctrl + Shift + R` (Windows) or `Cmd + Shift + R` (Mac)
