Secure Note Courier — Team README (Internal)

Goal: a clear, visual demo of hybrid cryptography using RSA-OAEP (to move a symmetric key), AES-GCM (to encrypt the note), and RSA-PSS (to sign the “envelope” so the receiver can verify origin + integrity).

This app is purposely local-only and classroom-focused. No servers, databases, or accounts. Just run and click through the steps.

============================================================
TL;DR (what to say in class)
============================================================
- We generate RSA keys (signing + encryption) for Alice and Bob.
- We bind each person’s encryption public key to their identity by signing its hash (prevents MITM swapping keys).
- Alice makes a fresh AES key, wraps it to Bob using RSA-OAEP, then uses that AES key to encrypt the note with AES-GCM (nonce + ciphertext + tag + AAD).
- Alice signs the whole envelope (JSON with wrapped key + ciphertext + etc.) using RSA-PSS over SHA-256 of the envelope.
- Bob verifies signature first (authenticity + integrity), then unwraps the AES key and decrypts.
- Tamper toggles show verification or decryption failures instantly.

============================================================
1) Quick start
============================================================
Requirements
- Python 3.10+ (3.11 recommended)
- pip and a working venv
- OS: macOS, Linux, or Windows

Install & run
    python -m venv .venv
    # macOS/Linux
    source .venv/bin/activate
    # Windows
    # .venv\Scripts\activate

    pip install -r requirements.txt
    python app.py
    # Open http://127.0.0.1:5000

If cryptography fails to install on an older Python/pip, try:
    python -m pip install --upgrade pip setuptools wheel

============================================================
2) What’s in this repo
============================================================
.
├─ app.py                 # Flask backend + cryptography logic (RSA-OAEP, RSA-PSS, AES-GCM)
├─ requirements.txt       # Flask + cryptography
├─ templates/
│   └─ index.html         # UI layout + stepper + artifacts panel
└─ static/
    ├─ styles.css         # Modern, compact styles (light/dark)
    └─ app.js             # Client-side logic, step-by-step controller, copy-to-clipboard, etc.

============================================================
3) The demo flow (what each step does)
============================================================
1) Generate Keys
   - Each side creates two RSA-2048 keypairs:
     - Identity (RSA-PSS) for signing.
     - Encryption (RSA-OAEP) for wrapping the AES key.
   - Nothing is sent yet.

2) Exchange (bind encryption keys to identities)
   - Each side hashes its encryption public key and signs that hash with its identity private key.
   - The other side verifies this.
   - Purpose: prevents a man-in-the-middle from swapping in a fake public key.

3) Establish Shared Key (Key transport)
   - Alice generates a random 32-byte AES key.
   - Alice wraps (encrypts) that AES key with Bob’s RSA-OAEP public key.
   - Only Bob can unwrap (decrypt) it with his RSA private key.

4) Encrypt (AES-GCM)
   - Using the AES key, Alice encrypts the note with AES-GCM:
     - Picks a fresh nonce (12 bytes, must be unique per key).
     - Produces ciphertext and a 16-byte tag (tamper seal).
     - Uses AAD (associated authenticated data) for context (authenticated, not encrypted).

5) Sign (RSA-PSS)
   - We build an envelope JSON containing: algorithms, pubkeys, wrapped key, nonce, AAD, ciphertext, tag.
   - Compute SHA-256 of the envelope (without the signature field) → sign that digest with RSA-PSS (identity key).
   - This proves origin and protects the whole package from tampering.

6) Send
   - The envelope JSON is exactly what would go over the network (you can download/copy it).

7) Verify
   - Bob computes the same SHA-256 over the envelope and verifies Alice’s RSA-PSS signature.
   - If anything changed, verification fails here (we stop before decrypting).

8) Decrypt
   - Bob unwraps the AES key (RSA-OAEP) and decrypts the ciphertext with AES-GCM using the nonce and AAD.
   - If key/nonce/AAD/ciphertext are wrong, GCM rejects with an auth failure; otherwise, plaintext appears.

============================================================
4) UI map
============================================================
Left column: Alice & Bob cards (encryption pubkeys + signatures), your Note input.
Right column:
- Step Explainer (plain bullets for each step).
- Artifacts (copyable values):
  - AES key id (short hash) — short hash of the AES key (for display only).
  - Wrapped key (RSA-OAEP) — AES key encrypted to Bob’s public key.
  - Nonce — 12-byte random per encryption.
  - AAD — authenticated context (not encrypted).
  - Ciphertext — encrypted message.
  - GCM tag — tamper detection code for AES-GCM.
  - Envelope hash — SHA-256 of the envelope (without signature) that we sign.
  - Signature — Alice’s RSA-PSS signature of that hash.
- Tamper toggles: flip one byte in ciphertext or signature to observe failure modes.

============================================================
5) Crypto choices (short rationale)
============================================================
- RSA-OAEP-2048 (SHA-256/MGF1) for key transport: simple to teach and widely standardized.
- AES-256-GCM for payload: AEAD gives confidentiality + integrity with a single API.
- RSA-PSS (SHA-256, Prehashed) for signatures: modern RSA signature scheme; we show the exact digest we sign—great for learning.

Out of scope (by design): PKI/certificates, persistent key storage, multiple messages per session, replay protection, network transport security (we’re local).

============================================================
6) API reference (for devs/debuggers)
============================================================
- POST /api/generate → returns Alice/Bob signing and encryption pubkeys (SPKI base64).
- POST /api/exchange → signs hash(encryption pubkey) with RSA-PSS; returns signatures and digests.
- POST /api/derive → verifies those signatures, generates AES key, and returns:
  {
    "shared_key_fingerprint": "<short hex>",   // shown as "AES key id (short hash)"
    "wrapped_key_b64": "<base64url>"
  }
- POST /api/encrypt (body: { "plaintext": "..." }) → returns nonce_b64, aad_b64, ciphertext_b64, tag_b64 (+ timing + hashes).
- POST /api/sign → returns the envelope including envelope_hash_hex + signature_b64.
- POST /api/verify → recomputes the digest and verifies signature; returns { "ok": true/false, "computed_hash_hex": "..." }.
- POST /api/decrypt → unwraps AES key (RSA-OAEP) and decrypts GCM; returns { "ok": true, "plaintext": "..." } or an auth error.
- POST /api/tamper (body: { "kind": "ciphertext" | "signature" }) → flips one byte to demonstrate failures.
- GET /api/download_envelope → downloads the current envelope JSON.

Canonical JSON: we always sign/verify sorted, compact JSON (sort_keys=True, separators=(",", ":")) to stay deterministic.

============================================================
7) Envelope format (example)
============================================================
{
  "v": "1",
  "alg": {
    "kex": "RSA-OAEP-2048",
    "aead": "AES-256-GCM",
    "sig": "RSA-PSS-SHA256-Prehashed"
  },
  "session_id": "c4b7...-uuid",
  "ts": 1731139200123,
  "sender": {
    "id": "Alice",
    "sign_pub_spki_b64": "<base64 DER>",
    "enc_pub_spki_b64": "<base64 DER>"
  },
  "receiver": {
    "id": "Bob",
    "sign_pub_spki_b64": "<base64 DER>",
    "enc_pub_spki_b64": "<base64 DER>"
  },
  "wrapped_key_b64": "<base64url>",
  "aad_b64": "<base64url>",
  "nonce_b64": "<base64url 12B>",
  "ciphertext_b64": "<base64url>",
  "tag_b64": "<base64url 16B>",
  "envelope_hash_hex": "<sha256 of envelope without signature>",
  "signature_b64": "<RSA-PSS base64 DER>"
}

Note: in the UI we label shared_key_fingerprint as “AES key id (short hash)”, but it is not part of the envelope—just an artifact we display.

============================================================
8) How to present (speaker notes)
============================================================
- Why hybrid? Asymmetric (RSA) to securely move a random AES key; symmetric (AES-GCM) to efficiently encrypt data.
- Why sign? We want to prove who sent the package and that nothing changed.
- Tamper demo: flip a byte in the signature → Verify fails; flip a byte in ciphertext → Decrypt fails (GCM auth error).
- Nonce reminder: must be unique per AES key. We generate a new random nonce on each encrypt.

============================================================
9) Troubleshooting
============================================================
- Page loads but buttons do nothing → check the browser console; ensure app.py shows no errors; refresh.
- “AES-GCM authentication failed” on Decrypt → expected if you toggled ciphertext tamper or changed AAD/nonce/key.
- RSA generation seems slow → normal on some laptops. It’s local and one-time per run.
- pip errors installing cryptography → upgrade pip, setuptools, wheel. Use Python ≥ 3.10.

============================================================
10) Testing checklist
============================================================
- Happy path: Run all steps → Verify ok → Decrypt shows plaintext.
- Tamper signature: Toggle “Break signature” → Verify should fail.
- Tamper ciphertext: Toggle “Tamper ciphertext” → Verify ok (signature remains unchanged), then Decrypt fails with GCM auth error.
- Re-run: Click Restart or Reset; confirm new RSA keys and a new AES key id (short hash).

============================================================
11) Customize (optional)
============================================================
- Rename “AES key id (short hash)” in the UI? Change only the <b> label in templates/index.html.
- Show fewer artifacts for a cleaner screen? Remove their rows from index.html; the app logic keeps working.
- Different AAD? In app.py → /api/encrypt, change aad = b"cmps380/context" (keep it consistent for decrypt).

============================================================
12) Why we don’t show identity fingerprints
============================================================
We removed identity “fingerprints” (short hashes of identity public keys) to match the lecture scope. The demo still binds each encryption key to an identity via a signature on its hash (that’s the important MITM protection for the transport key).

============================================================
13) Security notes (what this demo is / isn’t)
============================================================
Provides:
- Confidentiality + integrity of the note (AES-GCM).
- Authenticity + integrity of the envelope (RSA-PSS).
- Protection against key-swap MITM on the transport key (signed encryption pubkeys).

Not included:
- PKI/certificates or real identity proof (we just show public keys).
- Persistent keys/storage, revocation, multiple message sessions.
- Full anti-replay (we include session_id + ts mostly for teaching).

============================================================
14) Credits & licenses
============================================================
- Uses Python cryptography and Flask.
- Designed for CMPS 380 teaching/demo use.
