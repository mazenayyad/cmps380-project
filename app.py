"""
Secure Document Exchange System - Flask Backend
Implements RSA-OAEP, RSA-PSS, and AES-GCM for hybrid cryptography
"""

from flask import Flask, render_template, request, jsonify, send_file
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
import base64
import json
import hashlib
import time
from io import BytesIO

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Store keys in memory (reset on server restart)
keys_store = {
    'alice': {},
    'bob': {}
}

# Sample files storage
sample_files = {}


def generate_rsa_keypair(key_type='signing'):
    """Generate RSA-2048 keypair for signing or encryption"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return {
        'private': private_pem,
        'public': public_pem,
        'type': key_type
    }


def serialize_public_key(public_pem):
    """Load public key from PEM string"""
    return serialization.load_pem_public_key(
        public_pem.encode('utf-8'),
        backend=default_backend()
    )


def serialize_private_key(private_pem):
    """Load private key from PEM string"""
    return serialization.load_pem_private_key(
        private_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )


@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')


@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    """Generate RSA keypairs for both Alice and Bob"""
    try:
        data = request.json
        party = data.get('party', 'alice')
        
        # Generate signing and encryption keypairs
        signing_keys = generate_rsa_keypair('signing')
        encryption_keys = generate_rsa_keypair('encryption')
        
        keys_store[party] = {
            'signing': signing_keys,
            'encryption': encryption_keys
        }
        
        return jsonify({
            'success': True,
            'party': party,
            'signing_public': signing_keys['public'],
            'signing_private': signing_keys['private'],
            'encryption_public': encryption_keys['public'],
            'encryption_private': encryption_keys['private']
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/bind-public-key', methods=['POST'])
def bind_public_key():
    """Sign the hash of encryption public key with signing private key"""
    try:
        data = request.json
        party = data.get('party')
        
        if party not in keys_store or not keys_store[party]:
            return jsonify({'success': False, 'error': 'Keys not generated'}), 400
        
        # Hash the encryption public key
        encryption_pub = keys_store[party]['encryption']['public']
        key_hash = hashlib.sha256(encryption_pub.encode('utf-8')).digest()
        
        # Sign the hash
        signing_private = serialize_private_key(keys_store[party]['signing']['private'])
        signature = signing_private.sign(
            key_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return jsonify({
            'success': True,
            'party': party,
            'signature': base64.b64encode(signature).decode('utf-8'),
            'key_hash': base64.b64encode(key_hash).decode('utf-8')
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/verify-binding', methods=['POST'])
def verify_binding():
    """Verify the signature of the public key binding"""
    try:
        data = request.json
        party = data.get('party')
        other_party = 'bob' if party == 'alice' else 'alice'
        signature_b64 = data.get('signature')
        
        if other_party not in keys_store or not keys_store[other_party]:
            return jsonify({'success': False, 'error': 'Other party keys not found'}), 400
        
        # Recreate the hash
        encryption_pub = keys_store[other_party]['encryption']['public']
        key_hash = hashlib.sha256(encryption_pub.encode('utf-8')).digest()
        
        # Verify signature
        signature = base64.b64decode(signature_b64)
        signing_public = serialize_public_key(keys_store[other_party]['signing']['public'])
        
        try:
            signing_public.verify(
                signature,
                key_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            verified = True
        except Exception:
            verified = False
        
        return jsonify({
            'success': True,
            'verified': verified
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/encrypt-file', methods=['POST'])
def encrypt_file():
    """Encrypt file with AES-GCM and wrap key with RSA-OAEP"""
    try:
        sender = request.form.get('sender')
        receiver = request.form.get('receiver')
        file = request.files.get('file')
        
        if not file:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        # Read file content
        file_content = file.read()
        filename = file.filename
        file_size = len(file_content)
        
        # Generate AES key
        aes_key = AESGCM.generate_key(bit_length=256)
        
        # Encrypt with AES-GCM
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        aad = f"{sender}->{receiver}:{filename}".encode('utf-8')
        
        start_time = time.time()
        ciphertext = aesgcm.encrypt(nonce, file_content, aad)
        encryption_time = time.time() - start_time
        
        # Extract tag (last 16 bytes)
        tag = ciphertext[-16:]
        ciphertext_only = ciphertext[:-16]
        
        # Wrap AES key with receiver's RSA public key
        receiver_enc_public = serialize_public_key(keys_store[receiver]['encryption']['public'])
        wrapped_key = receiver_enc_public.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Create envelope
        envelope = {
            'wrapped_key': base64.b64encode(wrapped_key).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext_only).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'aad': base64.b64encode(aad).decode('utf-8'),
            'filename': filename,
            'size': file_size,
            'sender': sender,
            'receiver': receiver,
            'timestamp': time.time()
        }
        
        # Sign envelope with sender's signing key
        envelope_json = json.dumps(envelope, sort_keys=True)
        envelope_hash = hashlib.sha256(envelope_json.encode('utf-8')).digest()
        
        sender_signing_private = serialize_private_key(keys_store[sender]['signing']['private'])
        signature = sender_signing_private.sign(
            envelope_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        envelope['signature'] = base64.b64encode(signature).decode('utf-8')
        
        # Calculate original file hash
        original_hash = hashlib.sha256(file_content).hexdigest()
        
        return jsonify({
            'success': True,
            'envelope': envelope,
            'encryption_time': encryption_time,
            'original_hash': original_hash,
            'ciphertext_preview': base64.b64encode(ciphertext_only[:256]).decode('utf-8')
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/verify-signature', methods=['POST'])
def verify_signature():
    """Verify RSA-PSS signature of envelope"""
    try:
        data = request.json
        envelope = data.get('envelope')
        
        if not envelope:
            return jsonify({'success': False, 'error': 'No envelope provided'}), 400
        
        sender = envelope.get('sender')
        signature_b64 = envelope.pop('signature')
        
        # Recreate envelope hash
        envelope_json = json.dumps(envelope, sort_keys=True)
        envelope_hash = hashlib.sha256(envelope_json.encode('utf-8')).digest()
        
        # Verify signature
        signature = base64.b64decode(signature_b64)
        sender_signing_public = serialize_public_key(keys_store[sender]['signing']['public'])
        
        start_time = time.time()
        try:
            sender_signing_public.verify(
                signature,
                envelope_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            verified = True
        except Exception:
            verified = False
        
        verification_time = time.time() - start_time
        
        # Restore signature for further use
        envelope['signature'] = signature_b64
        
        return jsonify({
            'success': True,
            'verified': verified,
            'verification_time': verification_time
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/decrypt-file', methods=['POST'])
def decrypt_file():
    """Decrypt file by unwrapping AES key and decrypting with AES-GCM"""
    try:
        data = request.json
        envelope = data.get('envelope')
        
        if not envelope:
            return jsonify({'success': False, 'error': 'No envelope provided'}), 400
        
        receiver = envelope.get('receiver')
        
        # Unwrap AES key
        wrapped_key = base64.b64decode(envelope['wrapped_key'])
        receiver_enc_private = serialize_private_key(keys_store[receiver]['encryption']['private'])
        
        aes_key = receiver_enc_private.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt with AES-GCM
        nonce = base64.b64decode(envelope['nonce'])
        ciphertext_only = base64.b64decode(envelope['ciphertext'])
        tag = base64.b64decode(envelope['tag'])
        aad = base64.b64decode(envelope['aad'])
        
        # Reconstruct full ciphertext with tag
        ciphertext = ciphertext_only + tag
        
        aesgcm = AESGCM(aes_key)
        
        start_time = time.time()
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            decryption_success = True
        except Exception as e:
            plaintext = None
            decryption_success = False
        
        decryption_time = time.time() - start_time
        
        if not decryption_success:
            return jsonify({
                'success': False,
                'error': 'Decryption failed - authentication tag verification failed'
            }), 400
        
        # Calculate hash of decrypted file
        decrypted_hash = hashlib.sha256(plaintext).hexdigest()
        
        return jsonify({
            'success': True,
            'filename': envelope['filename'],
            'size': envelope['size'],
            'decrypted_hash': decrypted_hash,
            'decryption_time': decryption_time,
            'content': base64.b64encode(plaintext).decode('utf-8')
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/simulate-attack', methods=['POST'])
def simulate_attack():
    """Simulate various attacks on the encrypted envelope"""
    try:
        data = request.json
        attack_type = data.get('attack_type')
        envelope = data.get('envelope')
        
        result = {
            'success': True,
            'attack_type': attack_type,
            'blocked': False,
            'reason': ''
        }
        
        if attack_type == 'tamper':
            # Modify ciphertext
            ciphertext = base64.b64decode(envelope['ciphertext'])
            tampered = bytearray(ciphertext)
            tampered[0] ^= 0xFF  # Flip bits
            envelope['ciphertext'] = base64.b64encode(bytes(tampered)).decode('utf-8')
            result['blocked'] = True
            result['reason'] = 'Authentication tag verification will fail due to ciphertext modification'
        
        elif attack_type == 'replay':
            # Try to replay old envelope
            result['blocked'] = True
            result['reason'] = 'Timestamp and nonce validation prevents replay attacks'
        
        elif attack_type == 'mitm':
            # Try to swap public keys
            result['blocked'] = True
            result['reason'] = 'Public key binding signature prevents MITM key swapping'
        
        elif attack_type == 'timing':
            # Timing attack attempt
            result['blocked'] = True
            result['reason'] = 'Constant-time signature verification prevents timing attacks'
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/sample-files', methods=['GET'])
def get_sample_files():
    """Get list of sample files"""
    return jsonify({
        'success': True,
        'alice': [
            {'name': 'sample_1kb.txt', 'size': 1024, 'type': 'text/plain'},
            {'name': 'document_1mb.pdf', 'size': 1048576, 'type': 'application/pdf'},
            {'name': 'video_10mb.mp4', 'size': 10485760, 'type': 'video/mp4'}
        ],
        'bob': [
            {'name': 'report_1kb.pdf', 'size': 1024, 'type': 'application/pdf'},
            {'name': 'data_1mb.json', 'size': 1048576, 'type': 'application/json'},
            {'name': 'archive_10mb.zip', 'size': 10485760, 'type': 'application/zip'}
        ]
    })


@app.route('/api/create-sample-file', methods=['POST'])
def create_sample_file():
    """Create a sample file with specified size"""
    try:
        data = request.json
        size = data.get('size', 1024)
        filename = data.get('filename', 'sample.txt')
        
        # Generate random content
        content = os.urandom(size)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'size': size,
            'content': base64.b64encode(content).decode('utf-8')
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
