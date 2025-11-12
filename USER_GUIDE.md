# Secure Document Exchange System - User Guide

## 🎯 Overview

This is a visual demonstration of hybrid cryptography showing secure file transfer between Alice and Bob using RSA-OAEP, AES-GCM, and RSA-PSS. Perfect for educational purposes and classroom demonstrations.

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- pip package manager
- Modern web browser (Chrome, Firefox, Edge, Safari)

### Installation

1. **Activate Virtual Environment** (if not already activated):
   ```bash
   # Windows
   .venv\Scripts\activate
   
   # macOS/Linux
   source .venv/bin/activate
   ```

2. **Install Dependencies** (if not already installed):
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**:
   ```bash
   python app.py
   ```

4. **Open in Browser**:
   Navigate to `http://127.0.0.1:5000`

## 📖 How to Use

### Step 0: Setup Phase
1. **Select a File**:
   - Click on any preset file from Alice's or Bob's file lists
   - Options: 1KB, 1MB, or 10MB files
   - Or click "Choose File" to upload your own file

2. **Choose Transfer Direction**:
   - Select "Alice → Bob" (Alice sends to Bob)
   - Or "Bob → Alice" (Bob sends to Alice)

3. **Start Transfer**:
   - Click the "▶ Start Transfer" button
   - This will begin the cryptographic process

### Step 1: Generate Keys
- Watch as RSA-2048 keypairs are generated for both Alice and Bob
- Each person gets two keypairs:
  * **Signing keypair** (RSA-PSS) - for digital signatures
  * **Encryption keypair** (RSA-OAEP) - for key wrapping
- Keys are displayed with shimmer animation
- Click "Continue →" when ready

### Step 2: Exchange & Bind Public Keys
- See how public keys are bound to identities to prevent MITM attacks
- Each party:
  1. Hashes their encryption public key (SHA-256)
  2. Signs the hash with their signing private key
- Keys are exchanged and signatures verified
- Click "Continue →" when ready

### Step 3: Encrypt File (AES-GCM)
- Watch the encryption process:
  1. **Left**: Original file preview
  2. **Center**: Encryption details (AES key, nonce, AAD)
  3. **Right**: Encrypted ciphertext preview
- Note the encryption time displayed
- Click "Continue →" when ready

### Step 4: Wrap AES Key (RSA-OAEP)
- See how the AES key is encrypted using receiver's public key
- Flow: AES Key → RSA-OAEP Encryption → Wrapped Key
- Only the receiver can unwrap this key with their private key
- Click "Continue →" when ready

### Step 5: Sign Envelope (RSA-PSS)
- View the complete envelope contents (JSON format)
- Watch as the envelope is:
  1. Hashed (SHA-256)
  2. Signed with sender's signing private key
- This ensures authenticity and integrity
- Click "Continue →" when ready

### Step 6: Transfer 🔴
- Watch the animated packet transfer from sender to receiver
- **INTERCEPT BUTTON** is now active!

#### Using the Intercept Feature
1. Click the **"🔴 INTERCEPT"** button (it pulses red)
2. A modal window appears showing:
   - The encrypted envelope (unreadable to attackers)
   - Attack simulation options

3. **Try These Attacks**:
   - ☑️ **Tamper with Ciphertext**: Modify encrypted data
   - ☑️ **Replay Attack**: Try to resend old envelope
   - ☑️ **Man-in-the-Middle**: Attempt to swap public keys
   - ☑️ **Timing Attack**: Try to measure verification time

4. See how each attack is **BLOCKED** with explanation
5. Click "Release Packet" to continue transfer
6. Click "Continue →" when ready

### Step 7: Verify Signature
- Receiver verifies the digital signature:
  1. Recreates the hash from received envelope
  2. Verifies using sender's signing public key
- **✅ VERIFIED** means the envelope is authentic and untampered
- Note the verification time
- Click "Continue →" when ready

### Step 8: Decrypt File
- Two-phase decryption process:

  **Phase 1 - Unwrap AES Key**:
  - Receiver uses their encryption private key
  - Wrapped key → RSA-OAEP Decrypt → AES key

  **Phase 2 - Decrypt File**:
  - Use unwrapped AES key
  - Ciphertext + Nonce + Tag → AES-GCM Decrypt → Original file
  
- Note the decryption time
- Click "Continue →" when ready

### Step 9: Verify Integrity ✅
- **File Integrity Check**:
  - Original file hash (SHA-256)
  - Received file hash (SHA-256)
  - **PERFECT MATCH!** confirms zero data loss

- **Performance Metrics**:
  - File size
  - Total time (encryption + verification + decryption)
  - Security level (RSA-2048 + AES-256-GCM)

- **Attack Defense Summary**:
  - ✅ MITM Attack blocked
  - ✅ Replay Attack blocked
  - ✅ Tampering blocked
  - ✅ Timing Attack blocked

- Click **"🔄 Start New Transfer"** to reset and try again

## 🎓 Educational Use

### For Instructors
This demo is perfect for teaching:
- Hybrid cryptography concepts
- Public key infrastructure (PKI)
- Digital signatures and authentication
- Symmetric vs. asymmetric encryption
- Attack vectors and defenses
- Cryptographic best practices

### Key Learning Points
1. **Why Two RSA Keypairs?**
   - Signing keys: Prove identity and prevent repudiation
   - Encryption keys: Secure key transport

2. **Why Bind Public Keys?**
   - Prevents MITM from swapping attacker's public key
   - Signature verification ensures key authenticity

3. **Why Hybrid Cryptography?**
   - RSA is slow for large files
   - AES is fast but needs secure key distribution
   - Combine both: Use RSA to send AES key, use AES to encrypt file

4. **Why Sign the Envelope?**
   - Proves sender identity (authentication)
   - Ensures envelope hasn't been modified (integrity)
   - Non-repudiation (sender can't deny sending)

5. **Why AES-GCM?**
   - Authenticated encryption (AEAD)
   - Built-in integrity check with authentication tag
   - Prevents tampering automatically

## 🔍 Understanding the Output

### Key Displays
- Keys shown as truncated PEM format
- Real keys are much longer (displayed with "...")
- "***" indicates hidden sensitive data

### Hash Displays
- SHA-256 produces 64 hexadecimal characters
- Displayed with middle truncated for readability
- Example: `a3f8d9e2...7b4c9e1f`

### Ciphertext Preview
- Shows first 128 bytes in hexadecimal
- Grouped by 4 bytes for readability
- Real ciphertext is full file length

### Timing Metrics
- Milliseconds (ms) for each operation
- Shows real cryptographic performance
- Will vary based on file size and system

## 🛡️ Security Notes

### What This Demonstrates
✅ Production-grade cryptography
✅ Real cryptographic operations (not simulated)
✅ Industry-standard algorithms (RSA-2048, AES-256)
✅ Proper key management and binding
✅ Attack resistance and defense

### Important Reminders
- Keys are stored in memory only (session-based)
- This is a demonstration tool, not production system
- Real systems would need secure key storage
- Certificate authorities would verify identities in practice

## ❓ Troubleshooting

### Server Won't Start
```bash
# Make sure you're in the project directory
cd "D:\Visual Studio DDrive\cmps380-project"

# Activate virtual environment
.venv\Scripts\activate

# Reinstall dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

### Page Won't Load
- Ensure server is running (should see "Running on http://127.0.0.1:5000")
- Check firewall isn't blocking port 5000
- Try a different browser
- Clear browser cache

### Images Not Loading
- Ensure `alice-image.jpg` and `bob-image.jpg` exist in `/static/`
- Check file permissions
- Refresh the page

### "File Too Large" Error
- Default max file size is 50MB
- For larger files, modify `app.py`:
  ```python
  app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
  ```

### Slow Performance
- Large files (10MB+) take longer to encrypt/decrypt
- This is normal cryptographic overhead
- Performance metrics show actual timing

## 🎨 Customization

### Change Colors
Edit `static/styles.css`:
```css
:root {
    --alice-color: #ec4899;  /* Alice's accent color */
    --bob-color: #3b82f6;    /* Bob's accent color */
    --primary-color: #4f46e5; /* Main theme color */
}
```

### Add More Sample Files
Edit file lists in `templates/index.html`:
```html
<div class="file-item" data-filename="new_file.txt" data-size="2048" data-owner="alice">
    <span class="file-icon">📄</span>
    <span class="file-name">new_file.txt</span>
    <span class="file-size">2 KB</span>
</div>
```

### Modify Cryptographic Settings
Edit `app.py` to change:
- Key sizes (currently RSA-2048)
- Algorithms (currently AES-256-GCM, RSA-OAEP, RSA-PSS)
- Hash functions (currently SHA-256)

## 📚 References

### Cryptographic Standards
- **RSA**: [PKCS #1](https://tools.ietf.org/html/rfc8017)
- **AES-GCM**: [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- **SHA-256**: [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final)

### Python Libraries
- **Flask**: [https://flask.palletsprojects.com/](https://flask.palletsprojects.com/)
- **Cryptography**: [https://cryptography.io/](https://cryptography.io/)

## 💡 Tips for Best Demo Experience

1. **Start with Small Files** (1KB) for quick demonstration
2. **Use the Intercept Feature** to show attack resistance
3. **Explain Each Step** before clicking Continue
4. **Point Out Visual Elements** (animations, colors, icons)
5. **Discuss Real-World Applications** (HTTPS, email encryption, VPNs)
6. **Try Both Directions** (Alice→Bob and Bob→Alice)
7. **Upload Custom Files** to show versatility
8. **Compare Hashes** at the end to prove integrity

## 🎬 Conclusion

This application provides a comprehensive, visual demonstration of secure file transfer using hybrid cryptography. All cryptographic operations are real and production-grade, making it an excellent educational tool for understanding how secure communication works in practice.

Enjoy your secure file transfers! 🔒✨
