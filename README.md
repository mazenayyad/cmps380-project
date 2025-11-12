# Secure Document Exchange System — CMPS 380# Secure Document Exchange System — CMPS 380Secure Note Courier — Team README (Internal)



**Goal**: Visual demonstration of hybrid cryptography (RSA-OAEP + AES-GCM + RSA-PSS) applied to secure file transfer between two parties with real-time attack simulation.



Local-only, classroom-focused. No servers or accounts required.**Goal**: Visual demonstration of hybrid cryptography (RSA-OAEP + AES-GCM + RSA-PSS) applied to secure file transfer between two parties with real-time attack simulation.Goal: a clear, visual demo of hybrid cryptography using RSA-OAEP (to move a symmetric key), AES-GCM (to encrypt the note), and RSA-PSS (to sign the “envelope” so the receiver can verify origin + integrity).





## What This Demo Does

Local-only, classroom-focused. No servers or accounts required.This app is purposely local-only and classroom-focused. No servers, databases, or accounts. Just run and click through the steps.

**Secure File Transfer**: Alice and Bob exchange files (1KB, 1MB, 10MB, or custom uploads) using production-grade cryptography.



**Visual Step-by-Step Flow**: Every cryptographic operation is visualized clearly:

- Key generation (RSA signing + encryption keys)

- Public key exchange with identity binding

- AES key generation and RSA-OAEP wrapping## What This Demo Does# TL;DR (what to say in class)

- File encryption with AES-GCM

- Digital signature with RSA-PSS

- Transfer visualization with file state display

- Signature verification and decryption**Secure File Transfer**: Alice and Bob exchange files (1KB, 1MB, 10MB, or custom uploads) using production-grade cryptography.- We generate RSA keys (signing + encryption) for Alice and Bob.

- File integrity comparison

- We bind each person’s encryption public key to their identity by signing its hash (prevents MITM swapping keys).

**Attack Defense Demonstrations**: Mid-transfer "Intercept" button allows real-time simulation of:

- Man-in-the-Middle (MITM) attacks**Visual Step-by-Step Flow**: Every cryptographic operation is visualized clearly:- Alice makes a fresh AES key, wraps it to Bob using RSA-OAEP, then uses that AES key to encrypt the note with AES-GCM (nonce + ciphertext + tag + AAD).

- Replay attacks

- Timing attacks- Key generation (RSA signing + encryption keys)- Alice signs the whole envelope (JSON with wrapped key + ciphertext + etc.) using RSA-PSS over SHA-256 of the envelope.

- Tampering attempts

- Public key exchange with identity binding- Bob verifies signature first (authenticity + integrity), then unwraps the AES key and decrypts.

All attacks are defeated by the cryptographic protocol, proving security.

- AES key generation and RSA-OAEP wrapping- Tamper toggles show verification or decryption failures instantly.



## Quick Start- File encryption with AES-GCM



**Requirements**: Python 3.10+, pip- Digital signature with RSA-PSS



**Install & Run**:- Transfer visualization with file state display# 1. Quick start

```bash

python -m venv .venv- Signature verification and decryption

.venv\Scripts\activate          # Windows

# source .venv/bin/activate     # macOS/Linux- File integrity comparisonRequirements

pip install -r requirements.txt

python app.py- Python 3.10+ (3.11 recommended)

```

Open `http://127.0.0.1:5000`**Attack Defense Demonstrations**: Mid-transfer "Intercept" button allows real-time simulation of:- pip and a working venv



- Man-in-the-Middle (MITM) attacks- OS: macOS, Linux, or Windows

## Project Structure

- Replay attacks

```

├─ app.py                 # Flask backend: RSA-OAEP, RSA-PSS, AES-GCM, file handling- Timing attacksInstall & run

├─ requirements.txt       # Dependencies: Flask + cryptography

├─ templates/- Tampering attempts    python -m venv .venv

│   └─ index.html         # UI: Alice/Bob panels, stepper, file selector, intercept modal

└─ static/    # macOS/Linux

    ├─ styles.css         # Styling: light/dark theme, animations

    └─ app.js             # Frontend logic: step controller, file upload, attack simulationAll attacks are defeated by the cryptographic protocol, proving security.    source .venv/bin/activate

```

    # Windows



## How It Works (Step-by-Step)    # .venv\Scripts\activate



### 1. Setup Phase## Quick Start

**File Selection**: User picks a file (pre-loaded 1KB/1MB/10MB samples or custom upload) and chooses sender (Alice or Bob).

    pip install -r requirements.txt

**Key Generation**: Both Alice and Bob generate two RSA-2048 keypairs each:

- **Signing keypair** (for RSA-PSS signatures)**Requirements**: Python 3.10+, pip    python app.py

- **Encryption keypair** (for RSA-OAEP key wrapping)

    # Open http://127.0.0.1:5000

### 2. Key Exchange with Identity Binding

Each party:**Install & Run**:

- Hashes their encryption public key (SHA-256)

- Signs the hash with their signing private key (RSA-PSS)```bashIf cryptography fails to install on an older Python/pip, try:

- Exchanges signed public keys

python -m venv .venv    python -m pip install --upgrade pip setuptools wheel

**Why**: Prevents MITM attacks by cryptographically binding public keys to identities.

.venv\Scripts\activate          # Windows

### 3. File Encryption & Packaging

**Sender (Alice) does**:# source .venv/bin/activate     # macOS/Linux

1. Generates random 32-byte AES key

2. Encrypts file using AES-256-GCM (produces: nonce + ciphertext + auth tag)pip install -r requirements.txt# 2. What’s in this repo

3. Wraps AES key using receiver's RSA public key (RSA-OAEP)

4. Creates envelope: `{wrapped_key, nonce, ciphertext, tag, aad, filename, size}`python app.py

5. Signs entire envelope with RSA-PSS (SHA-256 hash)

``````

**File state visualization**: Shows original file → encrypted bytes (hex preview).

Open 
`
http://127.0.0.1:5000
`

├─ app.py                 # Flask backend: RSA-OAEP, RSA-PSS, AES-GCM, file handling

### 4. Transfer with Attack Simulation

**Visual transfer**: Animated packet moving from Alice to Bob.
├─ requirements.txt       # Dependencies: Flask + cryptography



**Intercept Feature**: Mid-transfer button reveals:
├─ templates/

- Current encrypted file state (unreadable ciphertext)

- Attack simulation toggles:
## Project Structure
│   
└─ index.html         # UI: Alice/Bob panels, stepper, file selector, intercept modal

  
- **MITM**: Try to swap public keys → signature verification fails

  
- **Replay**: Resend old envelope → timestamp/nonce check fails
└─ static/

  
- **Timing**: Show constant-time verification (no timing leaks)

  
- **Tampering**: Modify ciphertext → authentication tag verification fails
`

`

`
    
├─ styles.css         # Styling: light/dark theme, animations



All attacks are blocked and visualized as failures.
├─ app.py                 # Flask backend: RSA-OAEP, RSA-PSS, AES-GCM, file handling    
└─ app.js             # Frontend logic: step controller, file upload, attack simulation



### 5. Verification & Decryption
├─ requirements.txt       # Dependencies: Flask + cryptography
`

`

`


**Receiver (Bob) does**:

1. Verifies envelope signature using Alice's signing public key (RSA-PSS)
├─ templates/

2. Unwraps AES key using Bob's encryption private key (RSA-OAEP)

3. Decrypts file using AES-256-GCM (verifies auth tag)
│   
└─ index.html         # UI: Alice/Bob panels, stepper, file selector, intercept modal

4. Displays decrypted file

└─ static/
## How It Works (Step-by-Step)

### 6. Integrity Verification

**File comparison**: SHA-256 hash of original vs. received file → proves bit-perfect transfer.    
├─ styles.css         # Styling: light/dark theme, animations



**Performance metrics**: Shows encryption/decryption time for different file sizes.    
└─ app.js             # Frontend logic: step controller, file upload, attack simulation
1) Generate Keys




`

`

`
   
- Each side creates two RSA-2048 keypairs:

## UI Layout

     
- Identity (RSA-PSS) for signing.


`

`

`


┌─────────────────────────────────────────────────────────────
┐
     
- Encryption (RSA-OAEP) for wrapping the AES key.

│  [ALICE] 👤                                      👤 [BOB]    
│

│  Status: Ready                              Status: Ready    
│
## How It Works (Step-by-Step)   
- Nothing is sent yet.

│  Public Keys: [view]                     Public Keys: [view] 
│

└─────────────────────────────────────────────────────────────
┘



┌─────────────────────────────────────────────────────────────
┐
### 1. Setup Phase
2) Exchange (bind encryption keys to identities)

│  FILE SELECTION                                              
│

│  ○ Alice → Bob    ○ Bob → Alice                             
│**File Selection**: User picks a file (pre-loaded 1KB/1MB/10MB samples or custom upload) and chooses sender (Alice or Bob).   
- Each side hashes its encryption public key and signs that hash with its identity private key.

│                                                              
│

│  Alice's Files:              Bob's Files:                    
│   
- The other side verifies this.

│  • sample_1kb.txt (1 KB)     • report_1kb.pdf (1 KB)        
│

│  • document_1mb.pdf (1 MB)   • data_1mb.json (1 MB)         
│**Key Generation**: Both Alice and Bob generate two RSA-2048 keypairs each:   
- Purpose: prevents a man-in-the-middle from swapping in a fake public key.

│  • video_10mb.mp4 (10 MB)    • archive_10mb.zip (10 MB)     
│

│                                                              
│
- **Signing keypair** (for RSA-PSS signatures)

│  [📁 Upload Custom File]                                    
│

│  [▶ Start Transfer]                                         
│
- **Encryption keypair** (for RSA-OAEP key wrapping)
3) Establish Shared Key (Key transport)

└─────────────────────────────────────────────────────────────
┘

   
- Alice generates a random 32-byte AES key.

┌─────────────────────────────────────────────────────────────
┐

│  STEP-BY-STEP PROGRESS                                       
│
### 2. Key Exchange with Identity Binding   
- Alice wraps (encrypts) that AES key with Bob’s RSA-OAEP public key.

│  ✓ 1. Generate Keys                                          
│

│  ✓ 2. Exchange & Bind Public Keys                            
│Each party:   
- Only Bob can unwrap (decrypt) it with his RSA private key.

│  → 3. Encrypt File (AES-GCM)                                 
│

│    4. Wrap Key (RSA-OAEP)                                    
│
- Hashes their encryption public key (SHA-
2
5
6)

│    5. Sign Envelope (RSA-PSS)                                
│

│    6. Transfer ────→ [🔴 INTERCEPT] ────→                    
│
- Signs the hash with their signing private key (RSA-PSS)
4) Encrypt (AES-GCM)

│    7. Verify Signature                                       
│

│    8. Decrypt File                                           
│
- Exchanges signed public keys   
- Using the AES key, Alice encrypts the note with AES-GCM:

│    9. Compare Hashes                                         
│

└─────────────────────────────────────────────────────────────
┘
     
- Picks a fresh nonce (12 bytes, must be unique per key).



┌─────────────────────────────────────────────────────────────
┐
**Why**: Prevents MITM attacks by cryptographically binding public keys to identities.     
- Produces ciphertext and a 16-byte tag (tamper seal).

│  FILE STATE VIEWER                                           
│

│  Original: sample_1kb.txt (1,024 bytes)                      
│     
- Uses AAD (associated authenticated data) for context (authenticated, not encrypted).

│  Current:  Encrypted (preview first 256 bytes hex)           
│

│  a3f8d9e2 b47c1a56 9f3e8d2a 7b4c9e1f ...                     
│
### 3. File Encryption & Packaging

│  [View Full Envelope JSON] [Download Encrypted]              
│

└─────────────────────────────────────────────────────────────
┘
**Sender (Alice) does**:
## UI Layout


`

`

`


1. Generates random 32-byte AES key

**Intercept Modal** (appears during step 6):


`

`

`

2. Encrypts file using AES-256-GCM (produces: nonce + ciphertext + auth tag)
`

`

`


┌─────────────────────────────────────────────────────────────
┐

│  🔴 PACKET INTERCEPTED                              [Close]  
│
3. Wraps AES key using receiver's RSA public key (RSA-OAEP)
┌─────────────────────────────────────────────────────────────
┐

├─────────────────────────────────────────────────────────────
┤

│  Encrypted Payload (read-only):                              
│
4. Creates envelope: 
`
{wrapped_key, nonce, ciphertext, tag, aad, filename, size}
`

│  [ALICE]                                           [BOB]     
│

│  {                                                           
│

│    "wrapped_key": "a3f8d9e2b47c1a56...",                     
│
5. Signs entire envelope with RSA-PSS (SHA-256 hash)
│  👤 Icon                                          👤 Icon    
│

│    "nonce": "9f3e8d2a7b4c9e1f",                              
│

│    "ciphertext": "f4a8c3d7e9b2f5a1...",                      
│
│  Status: Ready                                    Status: ..  
│

│    "tag": "1b7c3e8a4d9f2c5b",                                
│

│    "signature": "2a9f8e3c7d4b1a6e..."                        
│**File state visualization**: Shows original file → encrypted bytes (hex preview).
│  Public Keys: [view]                              Public Keys 
│

│  }                                                           
│

├─────────────────────────────────────────────────────────────
┤
└─────────────────────────────────────────────────────────────
┘

│  ATTACK SIMULATIONS:                                         
│

│  [Test Attack] MITM: Swap Public Key     → ❌ Sig Fails      
│
### 4. Transfer with Attack Simulation

│  [Test Attack] Replay: Resend Old Packet → ❌ Nonce Fails    
│

│  [Test Attack] Timing: Side-Channel      → 
✅ Protected      
│**Visual transfer**: Animated packet moving from Alice to Bob.
┌─────────────────────────────────────────────────────────────
┐

│  [Test Attack] Tamper: Modify Ciphertext → ❌ Auth Fails     
│

├─────────────────────────────────────────────────────────────
┤
│  FILE SELECTION                                              
│

│  [Continue Transfer]                                         
│

└─────────────────────────────────────────────────────────────
┘
**Intercept Feature**: Mid-transfer button reveals:
│  ○ Alice → Bob    ○ Bob → Alice                             
│


`

`

`


- Current encrypted file state (unreadable ciphertext)
│  • Alice's 1KB file   • Bob's 1KB file                       
│



## Cryptographic Primitives Used
- Attack simulation toggles:
│  • Alice's 1MB file   • Bob's 1MB file                       
│



| Component 
| Algorithm 
| Purpose 
|  
- **MITM**: Try to swap public keys → signature verification fails
│  • Alice's 10MB file  • Bob's 10MB file                      
│

|-----------|-----------|---------|

| Key Exchange 
| RSA-2048 + OAEP (SHA-256, MGF
1) 
| Wrap AES session key 
|  
- **Replay**: Resend old envelope → timestamp/nonce check fails
│  • [Upload Custom File]                                      
│

| File Encryption 
| AES-256-GCM 
| Fast symmetric encryption with authentication |

| Digital Signature 
| RSA-PSS (SHA-
2
5
6) 
| Verify sender identity + envelope integrity 
|  
- **Timing**: Show constant-time verification (no timing leaks)
│  [Start Transfer]                                            
│

| Key Binding 
| RSA-PSS over SHA-256(public_key) 
| Prevent MITM key substitution |

| Integrity Check 
| SHA-256 hash comparison 
| Prove bit-perfect file transfer 
|  
- **Tampering**: Modify ciphertext → authentication tag verification fails
└─────────────────────────────────────────────────────────────
┘





## Educational Value

All attacks are blocked and visualized as failures.
┌─────────────────────────────────────────────────────────────
┐

✅ **Visual Learning**: Every crypto step is animated and explained in real-time  

✅ **Practical Application**: Real file encryption (not toy examples)  
│  STEP-BY-STEP PROGRESS                                       
│

✅ **Security Proofs**: Attack simulations demonstrate protocol security  

✅ **Performance Analysis**: Compare encryption times across file sizes  
### 5. Verification & Decryption
│  ✓ 1. Generate Keys                                          
│

✅ **Industry Standards**: Uses same crypto as TLS, PGP, Signal protocol

**Receiver (Bob) does**:
│  ✓ 2. Exchange & Bind Public Keys                            
│



## For the Report
1. Verifies envelope signature using Alice's signing public key (RSA-PSS)
│  → 3. Encrypt File (AES-GCM)                                 
│



**Mathematical Foundations to Cover**:
2. Unwraps AES key using Bob's encryption private key (RSA-OAEP)
│    4. Wrap Key (RSA-OAEP)                                    
│

- **RSA hardness**: Integer factorization problem (can't derive 
`
d
`
 from 
`
e,n
`
 without factoring 
`
n
`
)

- **AES security**: Substitution-permutation network resists differential/linear cryptanalysis
3. Decrypts file using AES-256-GCM (verifies auth tag)
│    5. Sign Envelope (RSA-PSS)                                
│

- **GCM mode**: Combines CTR encryption + GHASH authentication (prevents tampering)

- **SHA-256**: Avalanche effect (one bit change → 50% output bits flip)
4. Displays decrypted file
│    6. Transfer → [🔴 INTERCEPT] ←                            
│



**Performance Benchmarks to Include**:
│    7. Verify Signature                                       
│

- RSA-2048 key generation: ~100-200ms

- AES-GCM throughput: ~500 MB/s (hardware-accelerated)
### 6. Integrity Verification
│    8. Decrypt File                                           
│

- RSA operations: ~1-2ms (public key), ~10-50ms (private key)

- File size impact: Linear scaling for AES, constant for RSA (only wraps 32-byte key)**File comparison**: SHA-256 hash of original vs. received file → proves bit-perfect transfer.
│    9. Compare Hashes                                         
│



└─────────────────────────────────────────────────────────────
┘

## API Endpoints

**Performance metrics**: Shows encryption/decryption time for different file sizes.

| Endpoint 
| Method 
| Purpose |

|----------|--------|---------|
┌─────────────────────────────────────────────────────────────
┐

| 
`
/
`
 
| GET 
| Serve main UI |

| 
`
/api/reset
`
 
| GET 
| Clear session state |
│  FILE STATE VIEWER                                           
│

| 
`
/api/generate
`
 
| POST 
| Generate RSA keypairs for Alice & Bob |

| 
`
/api/exchange
`
 
| POST 
| Exchange and bind public keys |
## UI Layout
│  Current: Encrypted (preview first 256 bytes hex)            
│

| 
`
/api/derive
`
 
| POST 
| Generate AES key |

| 
`
/api/encrypt
`
 
| POST 
| Encrypt file with AES-GCM |
│  [View Full Envelope JSON]                                   
│

| 
`
/api/sign
`
 
| POST 
| Sign envelope with RSA-PSS |

| 
`
/api/verify
`
 
| POST 
| Verify signature |
`

`

`

└─────────────────────────────────────────────────────────────
┘

| 
`
/api/decrypt
`
 
| POST 
| Decrypt file |

| 
`
/api/tamper
`
 
| POST 
| Simulate attack (MITM/Replay/Timing/Tamper) |
┌─────────────────────────────────────────────────────────────
┐

`

`

`


| 
`
/api/upload_file
`
 
| POST 
| Upload custom file |

| 
`
/api/download_envelope
`
 
| GET 
| Download encrypted envelope |
│  [ALICE] 👤                                      👤 [BOB]    
│



│  Status: Ready                              Status: Ready    
│**Intercept Modal** (appears during step 6):

## Implementation Notes

│  Public Keys: [view]                     Public Keys: [view] 
│
`

`

`


**Session Management**: Each browser session gets a unique ID. All cryptographic keys are stored server-side in memory (cleared on reset).

└─────────────────────────────────────────────────────────────
┘
┌─────────────────────────────────────────────────────────────
┐

**File Handling**: 

- Pre-loaded files are generated on first access (random bytes of specified size)
│  🔴 PACKET INTERCEPTED                              [Close]  
│

- Custom uploads are limited to 50MB to prevent memory issues

- All files are processed in-memory (no disk writes)
┌─────────────────────────────────────────────────────────────
┐
├─────────────────────────────────────────────────────────────
┤



**Timing Attack Protection**: Signature verification uses constant-time comparison to prevent timing side-channels.
│  FILE SELECTION                                              
│
│  Encrypted Payload (read-only):                              
│



**Replay Attack Prevention**: Each envelope includes a timestamp and nonce. Receiver tracks seen nonces and rejects duplicates within a time window.
│  ○ Alice → Bob    ○ Bob → Alice                             
│
│  {                                                           
│



│                                                              
│
│    "wrapped_key": "a3f8d9...",                               
│

## Demo Script (10-minute presentation)

│  Alice's Files:              Bob's Files:                    
│
│    "ciphertext": "9f4e2a...",                                
│

1. **Intro (1 min)**: "We're demonstrating hybrid cryptography in a file transfer system"

2. **Theory (2 min)**: Explain RSA-OAEP, AES-GCM, RSA-PSS briefly
│  • sample_1kb.txt (1 KB)     • report_1kb.pdf (1 KB)        
│
│    "signature": "1b7c3e..."                                  
│

3. **Setup (1 min)**: Show Alice/Bob UI, file selection

4. **Transfer Demo (3 min)**: Step through encryption → transfer → decryption
│  • document_1mb.pdf (1 MB)   • data_1mb.json (1 MB)         
│
│  }                                                           
│

5. **Attack Simulations (2 min)**: Trigger MITM, replay, tamper attacks → all fail

6. **Performance (1 min)**: Compare 1KB vs 10MB file encryption times
│  • video_10mb.mp4 (10 MB)    • archive_10mb.zip (10 MB)     
│
├─────────────────────────────────────────────────────────────
┤

7. **Wrap-up (30 sec)**: Real-world applications (TLS, PGP, secure messaging)

│                                                              
│
│  ATTACK SIMULATIONS:                                         
│



## Troubleshooting
│  [📁 Upload Custom File]                                    
│
│  [❌ MITM: Swap Public Key]     → ❌ Signature Fails         
│



**Issue**: 
`
cryptography
`
 fails to install  
│  [▶ Start Transfer]                                         
│
│  [❌ Replay: Resend Old Packet] → ❌ Nonce Check Fails       
│

**Fix**: 
`
python -m pip install --upgrade pip setuptools wheel
`


└─────────────────────────────────────────────────────────────
┘
│  [❌ Timing: Side-Channel]      → ✓ Constant-Time Protected 
│

**Issue**: Flask port already in use  

**Fix**: Change port in 
`
app.py
`
: 
`
app.run(debug=True, port=5001)
`

│  [❌ Tamper: Modify Ciphertext] → ❌ Auth Tag Fails          
│



**Issue**: Large file upload hangs  
┌─────────────────────────────────────────────────────────────
┐
├─────────────────────────────────────────────────────────────
┤

**Fix**: Reduce file size or increase timeout in 
`
app.js
`


│  STEP-BY-STEP PROGRESS                                       
│
│  [Continue Transfer]                                         
│

│  ✓ 1. Generate Keys                                          
│
└─────────────────────────────────────────────────────────────
┘

│  ✓ 2. Exchange & Bind Public Keys                            
│
`

`

`


│  → 3. Encrypt File (AES-GCM)                                 
│

│    4. Wrap Key (RSA-OAEP)                                    
│

│    5. Sign Envelope (RSA-PSS)                                
│
## Cryptographic Primitives Used

│    6. Transfer ────→ [🔴 INTERCEPT] ────→                    
│

│    7. Verify Signature                                       
│
| Component 
| Algorithm 
| Purpose |

│    8. Decrypt File                                           
│|-----------|-----------|---------|

│    9. Compare Hashes                                         
│
| Key Exchange 
| RSA-2048 + OAEP (SHA-256, MGF
1) 
| Wrap AES session key |

└─────────────────────────────────────────────────────────────
┘
| File Encryption 
| AES-256-GCM 
| Fast symmetric encryption with authentication |

| Digital Signature 
| RSA-PSS (SHA-
2
5
6) 
| Verify sender identity + envelope integrity |

┌─────────────────────────────────────────────────────────────
┐
| Key Binding 
| RSA-PSS over SHA-256(public_key) 
| Prevent MITM key substitution |

│  FILE STATE VIEWER                                           
│
| Integrity Check 
| SHA-256 hash comparison 
| Prove bit-perfect file transfer |

│  Original: sample_1kb.txt (1,024 bytes)                      
│

│  Current:  Encrypted (preview first 256 bytes hex)           
│

│  a3f8d9e2 b47c1a56 9f3e8d2a 7b4c9e1f ...                     
│
## Educational Value

│  [View Full Envelope JSON] [Download Encrypted]              
│

└─────────────────────────────────────────────────────────────
┘
✅ **Visual Learning**: Every crypto step is animated and explained in real-time  


`

`

`

✅ **Practical Application**: Real file encryption (not toy examples)  

✅ **Security Proofs**: Attack simulations demonstrate protocol security  

**Intercept Modal** (appears during step 6):
✅ **Performance Analysis**: Compare encryption times across file sizes  


`

`

`

✅ **Industry Standards**: Uses same crypto as TLS, PGP, Signal protocol

┌─────────────────────────────────────────────────────────────
┐

│  🔴 PACKET INTERCEPTED                              [Close]  
│

├─────────────────────────────────────────────────────────────
┤
## For the Report

│  Encrypted Payload (read-only):                              
│

│  {                                                           
│**Mathematical Foundations to Cover**:

│    "wrapped_key": "a3f8d9e2b47c1a56...",                     
│
- RSA hardness: integer factorization problem (can't derive 
`
d
`
 from 
`
e,n
`
)

│    "nonce": "9f3e8d2a7b4c9e1f",                              
│
- AES security: substitution-permutation network resists differential cryptanalysis

│    "ciphertext": "f4a8c3d7e9b2f5a1...",                      
│
- GCM mode: combines CTR encryption + GHASH authentication (prevents tampering)

│    "tag": "1b7c3e8a4d9f2c5b",                                
│
- SHA-256: avalanche effect (one bit change → 50% output bits flip)

│    "signature": "2a9f8e3c7d4b1a6e..."                        
│

│  }                                                           
│**Performance Benchmarks to Include**:

├─────────────────────────────────────────────────────────────
┤
- RSA-2048 key generation: ~100-200ms

│  ATTACK SIMULATIONS:                                         
│
- AES-GCM throughput: ~500 MB/s (hardware-accelerated)

│  [Test Attack] MITM: Swap Public Key     → ❌ Sig Fails      
│
- RSA operations: ~1-2ms (public key), ~10-50ms (private key)

│  [Test Attack] Replay: Resend Old Packet → ❌ Nonce Fails    
│
- File size impact: Linear scaling for AES, constant for RSA (only wraps 32-byte key)

│  [Test Attack] Timing: Side-Channel      → 
✅ Protected      
│   
- We build an envelope JSON containing: algorithms, pubkeys, wrapped key, nonce, AAD, ciphertext, tag.

│  [Test Attack] Tamper: Modify Ciphertext → ❌ Auth Fails     
│   
- Compute SHA-256 of the envelope (without the signature field) → sign that digest with RSA-PSS (identity key).

├─────────────────────────────────────────────────────────────
┤
   
- This proves origin and protects the whole package from tampering.

│  [Continue Transfer]                                         
│

└─────────────────────────────────────────────────────────────
┘
6) Send


`

`

`
   
- The envelope JSON is exactly what would go over the network (you can download/copy it).



7) Verify

## Cryptographic Primitives Used   
- Bob computes the same SHA-256 over the envelope and verifies Alice’s RSA-PSS signature.

   
- If anything changed, verification fails here (we stop before decrypting).

| Component 
| Algorithm 
| Purpose |

|-----------|-----------|---------|
8) Decrypt

| Key Exchange 
| RSA-2048 + OAEP (SHA-256, MGF
1) 
| Wrap AES session key 
|   
- Bob unwraps the AES key (RSA-OAEP) and decrypts the ciphertext with AES-GCM using the nonce and AAD.

| File Encryption 
| AES-256-GCM 
| Fast symmetric encryption with authentication 
|   
- If key/nonce/AAD/ciphertext are wrong, GCM rejects with an auth failure; otherwise, plaintext appears.

| Digital Signature 
| RSA-PSS (SHA-
2
5
6) 
| Verify sender identity + envelope integrity |

| Key Binding 
| RSA-PSS over SHA-256(public_key) 
| Prevent MITM key substitution |

| Integrity Check 
| SHA-256 hash comparison 
| Prove bit-perfect file transfer |
# 4. UI map



Left column: Alice & Bob cards (encryption pubkeys + signatures), your Note input.

## Educational Value
Right column:

- Step Explainer (plain bullets for each step).

✅ **Visual Learning**: Every crypto step is animated and explained in real-time  
- Artifacts (copyable values):

✅ **Practical Application**: Real file encryption (not toy examples)    
- AES key id (short hash) — short hash of the AES key (for display only).

✅ **Security Proofs**: Attack simulations demonstrate protocol security    
- Wrapped key (RSA-OAEP) — AES key encrypted to Bob’s public key.

✅ **Performance Analysis**: Compare encryption times across file sizes    
- Nonce — 12-byte random per encryption.

✅ **Industry Standards**: Uses same crypto as TLS, PGP, Signal protocol  
- AAD — authenticated context (not encrypted).

  
- Ciphertext — encrypted message.

  
- GCM tag — tamper detection code for AES-GCM.

## For the Report  
- Envelope hash — SHA-256 of the envelope (without signature) that we sign.

  
- Signature — Alice’s RSA-PSS signature of that hash.

**Mathematical Foundations to Cover**:
- Tamper toggles: flip one byte in ciphertext or signature to observe failure modes.

- **RSA hardness**: Integer factorization problem (can't derive 
`
d
`
 from 
`
e,n
`
 without factoring 
`
n
`
)

- **AES security**: Substitution-permutation network resists differential/linear cryptanalysis

- **GCM mode**: Combines CTR encryption + GHASH authentication (prevents tampering)
# 5. Crypto choices (short rationale)

- **SHA-256**: Avalanche effect (one bit change → 50% output bits flip)

- RSA-OAEP-2048 (SHA-256/MGF
1) for key transport: simple to teach and widely standardized.

**Performance Benchmarks to Include**:
- AES-256-GCM for payload: AEAD gives confidentiality + integrity with a single API.

- RSA-2048 key generation: ~100-200ms
- RSA-PSS (SHA-256, Prehashed) for signatures: modern RSA signature scheme; we show the exact digest we sign—great for learning.

- AES-GCM throughput: ~500 MB/s (hardware-accelerated)

- RSA operations: ~1-2ms (public key), ~10-50ms (private key)Out of scope (by design): PKI/certificates, persistent key storage, multiple messages per session, replay protection, network transport security (we’re local).

- File size impact: Linear scaling for AES, constant for RSA (only wraps 32-byte key)



# 6. API reference (for devs/debuggers)

## API Endpoints

- POST /api/generate → returns Alice/Bob signing and encryption pubkeys (SPKI base64).

| Endpoint 
| Method 
| Purpose |
- POST /api/exchange → signs hash(encryption pubkey) with RSA-PSS; returns signatures and digests.

|----------|--------|---------|
- POST /api/derive → verifies those signatures, generates AES key, and returns:

| 
`
/
`
 
| GET 
| Serve main UI 
|  {

| 
`
/api/reset
`
 
| GET 
| Clear session state 
|    "shared_key_fingerprint": "<short hex>",   // shown as "AES key id (short hash)"

| 
`
/api/generate
`
 
| POST 
| Generate RSA keypairs for Alice & Bob 
|    "wrapped_key_b64": "<base64url>"

| 
`
/api/exchange
`
 
| POST 
| Exchange and bind public keys 
|  }

| 
`
/api/derive
`
 
| POST 
| Generate AES key |
- POST /api/encrypt (body: { "plaintext": "..." }) → returns nonce_b64, aad_b64, ciphertext_b64, tag_b64 (+ timing + hashes).

| 
`
/api/encrypt
`
 
| POST 
| Encrypt file with AES-GCM |
- POST /api/sign → returns the envelope including envelope_hash_hex + signature_b
6
4.

| 
`
/api/sign
`
 
| POST 
| Sign envelope with RSA-PSS |
- POST /api/verify → recomputes the digest and verifies signature; returns { "ok": true/false, "computed_hash_hex": "..." }.

| 
`
/api/verify
`
 
| POST 
| Verify signature |
- POST /api/decrypt → unwraps AES key (RSA-OAEP) and decrypts GCM; returns { "ok": true, "plaintext": "..." } or an auth error.

| 
`
/api/decrypt
`
 
| POST 
| Decrypt file |
- POST /api/tamper (body: { "kind": "ciphertext" 
| "signature" }) → flips one byte to demonstrate failures.

| 
`
/api/tamper
`
 
| POST 
| Simulate attack (MITM/Replay/Timing/Tamper) |
- GET /api/download_envelope → downloads the current envelope JSON.

| 
`
/api/upload_file
`
 
| POST 
| Upload custom file |

| 
`
/api/download_envelope
`
 
| GET 
| Download encrypted envelope |Canonical JSON: we always sign/verify sorted, compact JSON (sort_keys=True, separators=(",", ":")) to stay deterministic.





## Implementation Notes
# 7. Envelope format (example)



**Session Management**: Each browser session gets a unique ID. All cryptographic keys are stored server-side in memory (cleared on reset).{

  "v": "1",

**File Handling**:   "alg": {

- Pre-loaded files are generated on first access (random bytes of specified size)    "kex": "RSA-OAEP-2048",

- Custom uploads are limited to 50MB to prevent memory issues    "aead": "AES-256-GCM",

- All files are processed in-memory (no disk writes)    "sig": "RSA-PSS-SHA256-Prehashed"

  },

**Timing Attack Protection**: Signature verification uses constant-time comparison to prevent timing side-channels.  "session_id": "c4b7...-uuid",

  "ts": 1731139200123,

**Replay Attack Prevention**: Each envelope includes a timestamp and nonce. Receiver tracks seen nonces and rejects duplicates within a time window.  "sender": {

    "id": "Alice",

    "sign_pub_spki_b64": "<base64 DER>",

## Demo Script (10-minute presentation)    "enc_pub_spki_b64": "<base64 DER>"

  },

1. **Intro (1 min)**: "We're demonstrating hybrid cryptography in a file transfer system"  "receiver": {

2. **Theory (2 min)**: Explain RSA-OAEP, AES-GCM, RSA-PSS briefly    "id": "Bob",

3. **Setup (1 min)**: Show Alice/Bob UI, file selection    "sign_pub_spki_b64": "<base64 DER>",

4. **Transfer Demo (3 min)**: Step through encryption → transfer → decryption    "enc_pub_spki_b64": "<base64 DER>"

5. **Attack Simulations (2 min)**: Trigger MITM, replay, tamper attacks → all fail  },

6. **Performance (1 min)**: Compare 1KB vs 10MB file encryption times  "wrapped_key_b64": "<base64url>",

7. **Wrap-up (30 sec)**: Real-world applications (TLS, PGP, secure messaging)  "aad_b64": "<base64url>",

  "nonce_b64": "<base64url 12B>",

  "ciphertext_b64": "<base64url>",

## Troubleshooting  "tag_b64": "<base64url 16B>",

  "envelope_hash_hex": "<sha256 of envelope without signature>",

**Issue**: 
`
cryptography
`
 fails to install    "signature_b64": "<RSA-PSS base64 DER>"

**Fix**: 
`
python -m pip install --upgrade pip setuptools wheel
`
}



**Issue**: Flask port already in use  Note: in the UI we label shared_key_fingerprint as “AES key id (short hash)”, but it is not part of the envelope—just an artifact we display.

**Fix**: Change port in 
`
app.py
`
: 
`
app.run(debug=True, port=5001)
`




**Issue**: Large file upload hangs  
# 8. How to present (speaker notes)

**Fix**: Reduce file size or increase timeout in 
`
app.js
`


- Why hybrid? Asymmetric (RSA) to securely move a random AES key; symmetric (AES-GCM) to efficiently encrypt data.
- Why sign? We want to prove who sent the package and that nothing changed.
- Tamper demo: flip a byte in the signature → Verify fails; flip a byte in ciphertext → Decrypt fails (GCM auth error).
- Nonce reminder: must be unique per AES key. We generate a new random nonce on each encrypt.


# 9. Troubleshooting

- Page loads but buttons do nothing → check the browser console; ensure app.py shows no errors; refresh.
- “AES-GCM authentication failed” on Decrypt → expected if you toggled ciphertext tamper or changed AAD/nonce/key.
- RSA generation seems slow → normal on some laptops. It’s local and one-time per run.
- pip errors installing cryptography → upgrade pip, setuptools, wheel. Use Python ≥ 3.
1
0.


# 1
0. Testing checklist

- Happy path: Run all steps → Verify ok → Decrypt shows plaintext.
- Tamper signature: Toggle “Break signature” → Verify should fail.
- Tamper ciphertext: Toggle “Tamper ciphertext” → Verify ok (signature remains unchanged), then Decrypt fails with GCM auth error.
- Re-run: Click Restart or Reset; confirm new RSA keys and a new AES key id (short hash).


# 1
1. Customize (optional)

- Rename “AES key id (short hash)” in the UI? Change only the <b> label in templates/index.html.
- Show fewer artifacts for a cleaner screen? Remove their rows from index.html; the app logic keeps working.
- Different AAD? In app.py → /api/encrypt, change aad = b"cmps380/context" (keep it consistent for decrypt).


# 1
2. Why we don’t show identity fingerprints

We removed identity “fingerprints” (short hashes of identity public keys) to match the lecture scope. The demo still binds each encryption key to an identity via a signature on its hash (that’s the important MITM protection for the transport key).


# 1
3. Security notes (what this demo is / isn’t)

Provides:
- Confidentiality + integrity of the note (AES-GCM).
- Authenticity + integrity of the envelope (RSA-PSS).
- Protection against key-swap MITM on the transport key (signed encryption pubkeys).

Not included:
- PKI/certificates or real identity proof (we just show public keys).
- Persistent keys/storage, revocation, multiple message sessions.
- Full anti-replay (we include session_id + ts mostly for teaching).


# 1
4. Credits & licenses

- Uses Python cryptography and Flask.
- Designed for CMPS 380 teaching/demo use.
