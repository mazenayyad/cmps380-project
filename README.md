I created your README as a **.txt** file with Markdown formatting.

**[Download README.txt](sandbox:/mnt/data/README.txt)**

---

````markdown
# Secure Document Exchange (Alice ↔ Bob) — README

Course: **Cybersecurity Fundamentals**  
Topic: **Cryptographic Algorithms & Proof‑of‑Concept**

> A visual, step‑by‑step web app that shows how modern cryptography securely moves a document from **Alice** to **Bob**, with an **Intercept** mode that simulates attacks and demonstrates defenses.

---

## 1) What this app demonstrates
- **Hybrid cryptography**: public‑key for key agreement + symmetric AEAD for speed.
- **Clear visualization** of every stage: key use, hashing, signing, segmenting, encrypting, transferring, verifying, and viewing.
- **Attack simulator** during transfer (timing, replay, man‑in‑the‑middle, bit‑flip, truncation, reordering) to show **defenses in action**.
- **Integrity proof**: side‑by‑side file comparison and SHA‑256 match at the end.
- **Performance panel**: transfer timings for **1 KB**, **1 MB**, **10 MB**, or a user‑uploaded file; optional algorithm toggle to compare speed/efficiency.

---

## 2) Cryptographic design (concise)
- **Identity keys (long‑term)**: **Ed25519** for digital signatures.  
  *Security basis*: hardness of the **elliptic‑curve discrete logarithm problem (ECDLP)** on Curve25519.
- **Ephemeral key agreement**: **X25519 (ECDH)** to derive a fresh session key per transfer.  
  *Security basis*: hardness of ECDLP; forward secrecy from ephemeral keys.
- **Symmetric encryption (AEAD)**: default **ChaCha20‑Poly1305**; toggle **AES‑256‑GCM** for comparison.  
  *Why*: both provide **authenticated encryption** (confidentiality + integrity) and are fast; ChaCha20 is consistently fast on CPUs without AES acceleration.
- **Hash & KDF**: **SHA‑256** (hash) and **HKDF‑SHA256** (key derivation).  
- **Chunking**: file is split into chunks (default **256 KiB**). Each chunk carries:
  - `session_id`, `seq_no`, `nonce`, `ciphertext`, `tag`
  - Nonces derived from HKDF(counter) to ensure **uniqueness**.
- **Authentication & MITM defense**:
  1) Alice and Bob **sign** their ephemeral public keys with their **Ed25519 identity keys**.
  2) Both sides **verify peer signatures** before any data encryption.
  3) A **key‑confirmation MAC** over the handshake transcript aborts on tampering.

> We use well‑reviewed primitives from the Python `cryptography` library; no custom crypto.

---

## 3) End‑to‑end pipeline (what the UI shows)
1. **Pick sender/receiver** (Alice→Bob or Bob→Alice) and **choose file**  
   Options: **1 KB**, **1 MB**, **10 MB**, or **Upload**. Preview plaintext (e.g., PDF thumbnail/text snippet).
2. **Pre‑hash**: show **SHA‑256** of the whole file.
3. **Handshake & identity**  
   - Generate **ephemeral X25519** key pair.  
   - **Sign** the ephemeral public key with **Ed25519**.  
   - Exchange signed ephemerals; **verify signatures**.  
   - Derive session keys via **HKDF**; display key‑confirmation check ✅.
4. **Segment** the file into chunks; show a progress bar and per‑chunk metadata (seq_no, size).
5. **Encrypt + authenticate** each chunk with **AEAD**; show base64 snippet of ciphertext + tag.
6. **Transfer** over a WebSocket; **Intercept** button appears **only during this stage**.
7. **Receive & verify** each chunk (tag, seq_no, nonce uniqueness). Out‑of‑order or duplicate chunks are flagged and handled.
8. **Reassemble** chunks into the original file.
9. **Final verification**: recompute SHA‑256 and compare with the sender’s pre‑hash (green check or red X).
10. **View**: show the decrypted document preview next to the original.

---

## 4) Intercept & attack simulator (during transfer)
Click **Intercept** (center between Alice and Bob) to open a modal showing the **current encrypted chunk** (base64 preview). Toggles:

| Attack toggle | What it simulates | Expected defense/visual |
|---|---|---|
| **Timing attack** | Adds variable network delays and measures response variance. | Crypto ops use constant‑time primitives; **no key leakage**. UI shows jitter graph but **no compromise**. |
| **Replay attack** | Re‑injects a previously sent chunk. | Duplicate `seq_no`/nonce detected; chunk **ignored** and event logged; stream continues. |
| **Man‑in‑the‑middle** | Replaces a peer’s ephemeral public key mid‑flight. | **Signature/handshake check fails** → session **aborts** before data decrypt; banner explains MITM blocked. |
| **Bit‑flip corruption** | Flips bits in ciphertext. | **AEAD tag** fails → chunk rejected; user sees “Tamper detected.” |
| **Truncation/Drop** | Drops last N chunks. | Receiver waits; on timeout, shows **incomplete transfer**; final hash mismatch prevents success. |
| **Reordering** | Shuffles chunk order. | Receiver buffers and reorders; AEAD checks still pass; **no data loss**. |

> The intercept view never shows plaintext during transit—only **encrypted state**.

---

## 5) Why these algorithms (speed & efficiency, at a glance)
- **Ed25519 vs RSA‑2048**: Ed25519 offers **faster signing/verification**, smaller keys/signatures, and simpler constant‑time implementations.
- **X25519 (ECDH)**: compact keys, fast, and widely standardized; good for **ephemeral key exchange**.
- **ChaCha20‑Poly1305 vs AES‑GCM**:  
  - On devices without AES acceleration, **ChaCha20** is often **faster and more consistent**.  
  - With AES‑NI, **AES‑GCM** can be equally fast or faster.  
  - The app lets you **toggle** to compare end‑to‑end times on 1 KB / 1 MB / 10 MB.

---

## 6) UI/UX spec (keep it intuitive)
- **Alice** and **Bob** appear as labeled cards with avatars. Sender is accented; receiver is muted until handshake completes.
- **File picker** offers 1 KB, 1 MB, 10 MB, or **Upload**; shows preview or byte/hex peek.
- **Timeline panel** (left‑to‑right): *Select → Pre‑hash → Handshake → Segment → Encrypt → Transfer → Verify → Reassemble → Compare → View*.
- **Live inspectors**: hover tooltips for keys, nonces, tags; click to expand base64/hex snippets.
- **Intercept button** centered; visible **only** while status = **Transferring**.
- **Completion screen**: green “Integrity Verified” badge, SHA‑256 equality, and side‑by‑side file preview.

---

## 7) How to run (quick)
**Prereqs**: Python 3.12+, Node 20+  
```bash
# Backend (FastAPI + cryptography)
cd backend
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload

# Frontend (React + Vite)
cd ../frontend
npm install
npm run dev


Defaults: backend at `http://localhost:8000`, frontend at `http://localhost:5173`.

---

## 8) Project structure

```
/frontend
  src/
    components/ (AliceCard, BobCard, Timeline, InterceptModal, FilePreview, MetricsPanel)
    pages/ (Home, Transfer)
    lib/ (crypto-api.ts, formatters.ts)
  vite.config.ts

/backend
  app.py (FastAPI, WebSocket endpoints)
  crypto/
    identities.py   (Ed25519 load/generate)
    handshake.py    (X25519 + signatures + key confirm)
    aead.py         (ChaCha20-Poly1305 & AES-GCM)
    chunking.py     (split/merge, seq_no, nonce derivation via HKDF)
    hashes.py       (SHA-256)
  tests/ (unit tests for hashing, AEAD, handshake)
  requirements.txt

/data
  sample-1kb.bin, sample-1mb.bin, sample-10mb.bin
```

---

## 9) Demo script (for class)

1. **Alice→Bob**, pick **1 KB**, default **ChaCha20‑Poly1305**. Show handshake verify ✅, transfer completes, hashes match.
2. Click **Intercept**, enable **Bit‑flip** → see **AEAD failure**; stop attack and resume success.
3. Enable **Replay** → duplicate chunk ignored; transfer still completes correctly.
4. Try **MITM** during handshake → session aborts with clear error; restart a clean session.
5. Switch to **AES‑GCM**; send **10 MB**; compare timing vs ChaCha20‑Poly1305 in **Metrics panel**.
6. Upload your own PDF; end with **file comparison view** (hash match + preview).

---

## 10) Notes & limits

* Educational PoC; do **not** reuse keys or transcripts outside this demo.
* Libraries handle constant‑time operations; we avoid writing cryptographic primitives ourselves.
* Large files stream in chunks to avoid memory spikes and to keep the UI responsive.

---

## 11) References (starter set)

* Python `cryptography` docs — [https://cryptography.io/en/latest/](https://cryptography.io/en/latest/)
* PyPI: `cryptography` — [https://pypi.org/project/cryptography/](https://pypi.org/project/cryptography/)
* Crypto‑Tool (visual learning) — [https://www.cryptool.org/en/](https://www.cryptool.org/en/)
* RFC 7748 — *Elliptic Curves for Security* (X25519/Ed25519)
* RFC 8439 — *ChaCha20 and Poly1305 for IETF Protocols*
* NIST SP 800‑38D — *Galois/Counter Mode (GCM)*

```
```
