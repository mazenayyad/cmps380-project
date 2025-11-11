import base64, json, os, time, uuid
from flask import Flask, render_template, request, jsonify, session, make_response
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
app.secret_key = os.urandom(32)

SESSIONS = {}

# ---------- helpers ----------

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def sha256(b: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(b)
    return h.finalize()

def pub_spki_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def canonical_json(obj: dict) -> bytes:
    # Deterministic JSON for hashing/signing
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def get_state():
    sid = session.get("sid")
    if not sid:
        sid = str(uuid.uuid4())
        session["sid"] = sid
    if sid not in SESSIONS:
        SESSIONS[sid] = {}
    return SESSIONS[sid]

# ---------- routes ----------

@app.route("/")
def index():
    return render_template("index.html")

@app.get("/api/reset")
def api_reset():
    st = get_state()
    st.clear()
    return jsonify({"ok": True, "message": "Reset complete."})

@app.post("/api/generate")
def api_generate():
    """
    Generate for each party:
      - RSA signing key (RSA-PSS)
      - RSA encryption key (RSA-OAEP)
    """
    st = get_state()

    # Alice keys
    st["alice_sign_sk"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    st["alice_sign_pk"] = st["alice_sign_sk"].public_key()
    st["alice_enc_sk"]  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    st["alice_enc_pk"]  = st["alice_enc_sk"].public_key()

    # Bob keys
    st["bob_sign_sk"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    st["bob_sign_pk"] = st["bob_sign_sk"].public_key()
    st["bob_enc_sk"]  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    st["bob_enc_pk"]  = st["bob_enc_sk"].public_key()

    return jsonify({
        "ok": True,
        "alice": {
            "sign_pub_spki_b64": b64u(pub_spki_bytes(st["alice_sign_pk"])),
            "enc_pub_spki_b64":  b64u(pub_spki_bytes(st["alice_enc_pk"])),
        },
        "bob": {
            "sign_pub_spki_b64": b64u(pub_spki_bytes(st["bob_sign_pk"])),
            "enc_pub_spki_b64":  b64u(pub_spki_bytes(st["bob_enc_pk"])),
        }
    })

@app.post("/api/exchange")
def api_exchange():
    """
    Bind each party's RSA-OAEP encryption public key to their identity by signing its hash with RSA-PSS.
    """
    st = get_state()
    a_enc_pub = pub_spki_bytes(st["alice_enc_pk"])
    b_enc_pub = pub_spki_bytes(st["bob_enc_pk"])
    a_digest = sha256(a_enc_pub)
    b_digest = sha256(b_enc_pub)

    a_sig = st["alice_sign_sk"].sign(
        a_digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        asym_utils.Prehashed(hashes.SHA256())
    )
    b_sig = st["bob_sign_sk"].sign(
        b_digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        asym_utils.Prehashed(hashes.SHA256())
    )

    st["alice_enc_sig"] = a_sig
    st["bob_enc_sig"]   = b_sig

    return jsonify({
        "ok": True,
        "alice_enc": {
            "pub_spki_b64": b64u(a_enc_pub),
            "digest_hex": a_digest.hex(),
            "signature_b64": b64u(a_sig)
        },
        "bob_enc": {
            "pub_spki_b64": b64u(b_enc_pub),
            "digest_hex": b_digest.hex(),
            "signature_b64": b64u(b_sig)
        }
    })

@app.post("/api/derive")
def api_derive():
    """
    RSA key transport:
      - Verify signatures over each party's encryption public key.
      - Generate random AES-256 key for this message.
      - Wrap (encrypt) the AES key for Bob using Bob's RSA-OAEP public key.
    """
    st = get_state()
    a_enc_pub = pub_spki_bytes(st["alice_enc_pk"])
    b_enc_pub = pub_spki_bytes(st["bob_enc_pk"])
    a_digest = sha256(a_enc_pub)
    b_digest = sha256(b_enc_pub)

    try:
        st["alice_sign_pk"].verify(
            st["alice_enc_sig"], a_digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            asym_utils.Prehashed(hashes.SHA256())
        )
        st["bob_sign_pk"].verify(
            st["bob_enc_sig"], b_digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            asym_utils.Prehashed(hashes.SHA256())
        )
    except InvalidSignature:
        return jsonify({"ok": False, "error": "Encryption key signatures failed."}), 400

    aes_key = os.urandom(32)
    st["aes_key"] = aes_key

    wrapped = st["bob_enc_pk"].encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    st["wrapped_key"] = wrapped

    return jsonify({
        "ok": True,
        "shared_key_fingerprint": sha256(aes_key).hex()[:16],  # used by UI as "AES key id (short hash)"
        "wrapped_key_b64": b64u(wrapped)
    })

@app.post("/api/encrypt")
def api_encrypt():
    st = get_state()
    data = request.get_json(silent=True) or {}
    plaintext = (data.get("plaintext") or "").encode()

    aad = b"cmps380/context"
    nonce = os.urandom(12)
    aesgcm = AESGCM(st["aes_key"])

    t0 = time.time()
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
    ms = int((time.time() - t0) * 1000)

    ct = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    st["nonce"] = nonce
    st["aad"] = aad
    st["ct"] = ct
    st["tag"] = tag
    st["plaintext"] = plaintext

    return jsonify({
        "ok": True,
        "nonce_b64": b64u(nonce),
        "aad_b64": b64u(aad),
        "ciphertext_b64": b64u(ct),
        "tag_b64": b64u(tag),
        "plaintext_sha256_hex": sha256(plaintext).hex(),
        "ciphertext_sha256_hex": sha256(ct).hex(),
        "ms_encrypt": ms
    })

@app.post("/api/sign")
def api_sign():
    """
    Sign the envelope (without the signature field) using RSA-PSS over SHA-256 (prehashed).
    """
    st = get_state()
    sid = session["sid"]
    envelope = {
        "v": "1",
        "alg": {
            "kex": "RSA-OAEP-2048",
            "aead": "AES-256-GCM",
            "sig": "RSA-PSS-SHA256-Prehashed"
        },
        "session_id": sid,
        "ts": int(time.time() * 1000),
        "sender": {
            "id": "Alice",
            "sign_pub_spki_b64": b64u(pub_spki_bytes(st["alice_sign_pk"])),
            "enc_pub_spki_b64":  b64u(pub_spki_bytes(st["alice_enc_pk"])),
        },
        "receiver": {
            "id": "Bob",
            "sign_pub_spki_b64": b64u(pub_spki_bytes(st["bob_sign_pk"])),
            "enc_pub_spki_b64":  b64u(pub_spki_bytes(st["bob_enc_pk"])),
        },
        "wrapped_key_b64": b64u(st["wrapped_key"]),
        "aad_b64": b64u(st["aad"]),
        "nonce_b64": b64u(st["nonce"]),
        "ciphertext_b64": b64u(st["ct"]),
        "tag_b64": b64u(st["tag"]),
    }

    c14n = canonical_json(envelope)
    digest = sha256(c14n)

    t0 = time.time()
    signature = st["alice_sign_sk"].sign(
        digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        asym_utils.Prehashed(hashes.SHA256())
    )
    ms = int((time.time() - t0) * 1000)

    envelope["envelope_hash_hex"] = digest.hex()
    envelope["signature_b64"] = b64u(signature)

    st["envelope"] = envelope
    st["envelope_hash"] = digest
    st["signature"] = signature

    return jsonify({
        "ok": True,
        "envelope": envelope,
        "ms_sign": ms
    })

@app.post("/api/verify")
def api_verify():
    st = get_state()
    env = st.get("envelope")
    if not env:
        return jsonify({"ok": False, "error": "No envelope to verify."}), 400

    env_no_sig = {k: v for k, v in env.items() if k not in ("signature_b64", "envelope_hash_hex")}
    c14n = canonical_json(env_no_sig)
    digest = sha256(c14n)
    sig = b64d(env["signature_b64"])

    try:
        st["alice_sign_pk"].verify(
            sig, digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            asym_utils.Prehashed(hashes.SHA256())
        )
        ok = True
    except InvalidSignature:
        ok = False

    return jsonify({"ok": ok, "computed_hash_hex": digest.hex()})

@app.post("/api/decrypt")
def api_decrypt():
    st = get_state()
    try:
        aes_key = st["bob_enc_sk"].decrypt(
            st["wrapped_key"],
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    except Exception:
        return jsonify({"ok": False, "error": "Failed to unwrap AES key (RSA-OAEP)."}), 400

    aesgcm = AESGCM(aes_key)
    try:
        pt = aesgcm.decrypt(st["nonce"], st["ct"] + st["tag"], st["aad"])
        return jsonify({"ok": True, "plaintext": pt.decode(errors="replace")})
    except Exception:
        return jsonify({"ok": False, "error": "AES-GCM authentication failed (tamper or wrong key/nonce/AAD)."}), 400

@app.post("/api/tamper")
def api_tamper():
    st = get_state()
    data = request.get_json(silent=True) or {}
    kind = data.get("kind")
    if kind == "ciphertext":
        ct = bytearray(st["ct"])
        if ct:
            ct[0] ^= 0x01
            st["ct"] = bytes(ct)
            if "envelope" in st:
                st["envelope"]["ciphertext_b64"] = b64u(st["ct"])
        return jsonify({"ok": True, "what": "ciphertext"})
    elif kind == "signature":
        sig = bytearray(b64d(st["envelope"]["signature_b64"]))
        if sig:
            sig[0] ^= 0x01
            st["envelope"]["signature_b64"] = b64u(bytes(sig))
        return jsonify({"ok": True, "what": "signature"})
    else:
        return jsonify({"ok": False, "error": "Unknown tamper kind."}), 400

@app.get("/api/download_envelope")
def api_download():
    st = get_state()
    env = st.get("envelope")
    if not env:
        return jsonify({"ok": False, "error": "No envelope."}), 400
    data = json.dumps(env, indent=2).encode()
    resp = make_response(data)
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Content-Disposition"] = "attachment; filename=envelope.json"
    return resp

if __name__ == "__main__":
    app.run(debug=True)
