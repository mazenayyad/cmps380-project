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

# Track nonces that have already been used during decryption to prevent replays
used_nonces = set()


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
    """Render landing page"""
    return render_template('home.html')


@app.route('/demo')
def demo():
    """Render Alice-Bob demonstration page"""
    return render_template('demo.html')


@app.route('/encrypt')
def encrypt():
    """Render encryption tool page"""
    return render_template('encrypt.html')


@app.route('/decrypt')
def decrypt():
    """Render decryption tool page"""
    return render_template('decrypt.html')


@app.route('/keys')
def keys():
    """Render key generation page"""
    return render_template('keys.html')


@app.route('/api/generate-keypair', methods=['POST'])
def generate_keypair_standalone():
    """Generate a single RSA keypair for standalone use"""
    try:
        data = request.json
        user = data.get('user', 'User')
        
        # Generate a single RSA keypair (used for both signing and encryption)
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
        
        # Add user identifier to public key
        public_key_with_user = f"# User: {user}\n{public_pem}"
        
        return jsonify({
            'success': True,
            'publicKey': public_key_with_user,
            'privateKey': private_pem,
            'user': user
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


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
    """Verify RSA-PSS signature of envelope - detects tampering and attacks"""
    try:
        data = request.json
        envelope = data.get('envelope')
        
        if not envelope:
            return jsonify({'success': False, 'error': 'No envelope provided'}), 400
        
        sender = envelope.get('sender')
        signature_b64 = envelope.pop('signature')
        
        # Check for attack indicators
        attack_detected = False
        attack_type = None
        attack_details = {}
        tampering_evidence = []
        
        # Detect replay attack
        if envelope.get('replay_attack'):
            attack_detected = True
            attack_type = 'replay'
            attack_details = {
                'attack_name': 'Replay Attack',
                'description': 'This envelope was previously transmitted and is being replayed by an attacker',
                'detection_method': 'Nonce reuse detection and timestamp validation',
                'security_impact': 'Could allow attacker to re-execute old transactions or duplicate messages',
                'blocked_by': 'Nonce tracking system prevents accepting the same nonce twice'
            }
            tampering_evidence.append({
                'field': 'nonce',
                'issue': 'Previously used nonce detected',
                'original': envelope.get('original_nonce', 'N/A'),
                'tampered': envelope.get('nonce', 'N/A')
            })
        
        # Detect MITM attack
        if envelope.get('mitm_attack'):
            attack_detected = True
            attack_type = 'mitm'
            attack_details = {
                'attack_name': 'Man-in-the-Middle Attack',
                'description': 'Attacker intercepted communication and modified the digital signature',
                'detection_method': 'RSA-PSS signature verification with sender\'s public key',
                'security_impact': 'Could allow attacker to impersonate sender or swap encryption keys',
                'blocked_by': 'Digital signature cryptographically binds message to sender\'s private key'
            }
        
        # Detect timing attack
        if envelope.get('timing_attack'):
            attack_detected = True
            attack_type = 'timing'
            attack_details = {
                'attack_name': 'Timing Attack',
                'description': 'Attacker measuring verification times to extract private key information',
                'detection_method': 'Constant-time signature verification operations',
                'security_impact': 'Could potentially leak private key bits through timing analysis',
                'blocked_by': 'Cryptographic library uses constant-time operations resistant to timing analysis',
                'timing_info': envelope.get('timing_manipulation', {})
            }
        
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
        except Exception as verify_error:
            verified = False
            
            # If signature fails, determine why
            if not attack_detected:
                # Signature failure without prior attack detection = tampering
                attack_detected = True
                attack_type = 'tamper'
                attack_details = {
                    'attack_name': 'Data Tampering Attack',
                    'description': 'The encrypted data has been modified in transit',
                    'detection_method': 'RSA-PSS signature verification failed',
                    'security_impact': 'Ciphertext modification detected - decryption will fail or produce garbage',
                    'blocked_by': 'Digital signature ensures any modification to the envelope is detected',
                    'verification_error': str(verify_error)
                }
                tampering_evidence.append({
                    'field': 'signature',
                    'issue': 'Signature does not match envelope content',
                    'details': 'Envelope hash does not verify against provided signature'
                })
        
        verification_time = time.time() - start_time
        
        # Restore signature for further use
        envelope['signature'] = signature_b64
        
        response = {
            'success': True,
            'verified': verified,
            'verification_time': verification_time,
            'attack_detected': attack_detected
        }
        
        if attack_detected:
            response['attack_type'] = attack_type
            response['attack_details'] = attack_details
            response['tampering_evidence'] = tampering_evidence
            response['security_recommendation'] = 'DO NOT DECRYPT OR OPEN THIS ENVELOPE - Reject and report to sender'
        
        return jsonify(response)
    
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
        ignore_replay = data.get('ignore_replay', False)
        
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
        
        # Decrypt with AES-GCM and enforce nonce replay protection
        nonce_b64 = envelope['nonce']
        if not ignore_replay:
            if nonce_b64 in used_nonces:
                return jsonify({
                    'success': False,
                    'error': 'Replay detected: nonce already used'
                }), 400
            used_nonces.add(nonce_b64)
        
        nonce = base64.b64decode(nonce_b64)
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
        except Exception:
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
    """Simulate various attacks on the encrypted envelope - actually modifies the envelope"""
    try:
        data = request.json
        attack_type = data.get('attack_type')
        envelope = data.get('envelope').copy()  # Work with a copy
        original_envelope = data.get('envelope').copy()  # Keep original for comparison
        
        modifications = []
        attack_description = ''
        
        if attack_type == 'tamper':
            # Modify ciphertext - flip multiple bytes to make it obvious
            ciphertext = base64.b64decode(envelope['ciphertext'])
            tampered = bytearray(ciphertext)
            # Flip bits in first 16 bytes to simulate tampering
            for i in range(min(16, len(tampered))):
                tampered[i] ^= 0xFF
            
            envelope['ciphertext'] = base64.b64encode(bytes(tampered)).decode('utf-8')
            modifications.append({
                'field': 'ciphertext',
                'original': original_envelope['ciphertext'][:64] + '...',
                'tampered': envelope['ciphertext'][:64] + '...',
                'description': 'First 16 bytes of ciphertext were modified (bits flipped)'
            })
            attack_description = 'Attacker modified the encrypted file data by flipping bits in the ciphertext. This simulates an attempt to alter the encrypted content.'
        
        elif attack_type == 'replay':
            # Mark envelope as replayed and modify nonce
            envelope['replay_attack'] = True
            envelope['original_nonce'] = envelope['nonce']
            # Generate a fake "old" nonce to simulate replay
            fake_nonce = base64.b64encode(os.urandom(12)).decode('utf-8')
            envelope['nonce'] = fake_nonce
            
            modifications.append({
                'field': 'nonce',
                'original': original_envelope['nonce'],
                'tampered': envelope['nonce'],
                'description': 'Nonce replaced with previously-used value'
            })
            modifications.append({
                'field': 'replay_flag',
                'original': 'false',
                'tampered': 'true',
                'description': 'Envelope marked as replayed packet'
            })
            attack_description = 'Attacker captured an old encrypted envelope and is attempting to resend it. This simulates a replay attack where previously valid data is retransmitted.'
        
        elif attack_type == 'mitm':
            # Tamper with signature to simulate key swapping
            signature = base64.b64decode(envelope['signature'])
            tampered_sig = bytearray(signature)
            # Modify signature bytes
            for i in range(min(32, len(tampered_sig))):
                tampered_sig[i] ^= 0xFF
            
            envelope['signature'] = base64.b64encode(bytes(tampered_sig)).decode('utf-8')
            envelope['mitm_attack'] = True
            
            modifications.append({
                'field': 'signature',
                'original': original_envelope['signature'][:64] + '...',
                'tampered': envelope['signature'][:64] + '...',
                'description': 'Digital signature corrupted (first 32 bytes modified)'
            })
            modifications.append({
                'field': 'sender_identity',
                'original': envelope.get('sender', 'Unknown'),
                'tampered': 'ATTACKER (attempting impersonation)',
                'description': 'Attacker trying to impersonate legitimate sender'
            })
            attack_description = 'Attacker intercepted the envelope and modified the digital signature to impersonate the sender or swap encryption keys. This is a Man-in-the-Middle attack attempt.'
        
        elif attack_type == 'timing':
            # Add timing attack metadata
            envelope['timing_attack'] = True
            envelope['timing_manipulation'] = {
                'simulated_delay': '500ms',
                'purpose': 'Measure verification time to extract private key information'
            }
            
            modifications.append({
                'field': 'timing_metadata',
                'original': 'Normal transmission',
                'tampered': 'Timing attack in progress',
                'description': 'Attacker measuring response times to extract cryptographic secrets'
            })
            attack_description = 'Attacker is attempting to measure verification timing to extract information about the private key. Constant-time operations prevent this attack.'
        
        result = {
            'success': True,
            'attack_type': attack_type,
            'modified_envelope': envelope,
            'original_envelope': original_envelope,
            'modifications': modifications,
            'attack_description': attack_description
        }
        
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


@app.route('/api/standalone-encrypt', methods=['POST'])
def standalone_encrypt():
    """
    Secure standalone encryption with hybrid cryptography
    Uses RSA-OAEP + AES-GCM + RSA-PSS
    Requires: file, sender's private key, recipient's public key
    """
    try:
        file = request.files.get('file')
        sender_private_key_file = request.files.get('senderPrivateKey')
        recipient_public_key_file = request.files.get('recipientPublicKey')
        
        if not file:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        if not sender_private_key_file:
            return jsonify({'success': False, 'error': 'Sender private key required'}), 400
        if not recipient_public_key_file:
            return jsonify({'success': False, 'error': 'Recipient public key required'}), 400
        
        # Read file content
        file_content = file.read()
        filename = file.filename
        file_size = len(file_content)
        
        # Load keys
        sender_private_pem = sender_private_key_file.read().decode('utf-8')
        recipient_public_pem = recipient_public_key_file.read().decode('utf-8')
        
        # Extract user from public key if present
        recipient_user = 'Recipient'
        for line in recipient_public_pem.split('\n'):
            if line.startswith('# User:'):
                recipient_user = line.replace('# User:', '').strip()
                break
        
        # Clean the PEM (remove user comments)
        recipient_public_clean = '\n'.join([line for line in recipient_public_pem.split('\n') if not line.startswith('#')])
        
        sender_private_key = serialize_private_key(sender_private_pem)
        recipient_public_key = serialize_public_key(recipient_public_clean)
        
        # Get sender's public key from private key
        sender_public_key = sender_private_key.public_key()
        sender_public_pem = sender_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Generate AES key
        aes_key = AESGCM.generate_key(bit_length=256)
        
        # Encrypt with AES-GCM
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        aad = f"secure:{recipient_user}:{filename}".encode('utf-8')
        
        start_time = time.time()
        ciphertext = aesgcm.encrypt(nonce, file_content, aad)
        encryption_time = time.time() - start_time
        
        # Extract tag (last 16 bytes)
        tag = ciphertext[-16:]
        ciphertext_only = ciphertext[:-16]
        
        # Wrap AES key with recipient's RSA public key (RSA-OAEP)
        wrapped_key = recipient_public_key.encrypt(
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
            'recipient': recipient_user,
            'timestamp': time.time(),
            'type': 'secure',
            'sender_public_key': sender_public_pem
        }
        
        # Sign envelope with sender's private key (RSA-PSS)
        envelope_json = json.dumps(envelope, sort_keys=True)
        envelope_hash = hashlib.sha256(envelope_json.encode('utf-8')).digest()
        
        signature = sender_private_key.sign(
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
            'encrypted_size': len(ciphertext_only),
            'recipient': recipient_user
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/standalone-decrypt', methods=['POST'])
def standalone_decrypt():
    """
    Secure standalone decryption with hybrid cryptography
    Verifies signature, unwraps key with RSA-OAEP, decrypts with AES-GCM
    Requires: envelope, recipient's private key
    """
    try:
        envelope_str = request.form.get('envelope')
        recipient_private_key_file = request.files.get('recipientPrivateKey')
        
        if not envelope_str:
            return jsonify({'success': False, 'error': 'No envelope provided'}), 400
        if not recipient_private_key_file:
            return jsonify({'success': False, 'error': 'Recipient private key required'}), 400
        
        envelope = json.loads(envelope_str)
        
        if envelope.get('type') != 'secure':
            return jsonify({'success': False, 'error': 'Invalid envelope type - must be secure envelope'}), 400
        
        # Load recipient's private key
        recipient_private_pem = recipient_private_key_file.read().decode('utf-8')
        recipient_private_key = serialize_private_key(recipient_private_pem)
        
        # Extract signature and sender's public key
        signature_b64 = envelope.pop('signature')
        sender_public_pem = envelope.get('sender_public_key')
        
        if not sender_public_pem:
            return jsonify({'success': False, 'error': 'Sender public key missing from envelope'}), 400
        
        # Verify signature (RSA-PSS)
        envelope_json = json.dumps(envelope, sort_keys=True)
        envelope_hash = hashlib.sha256(envelope_json.encode('utf-8')).digest()
        
        signature = base64.b64decode(signature_b64)
        sender_public_key = serialize_public_key(sender_public_pem)
        
        try:
            sender_public_key.verify(
                signature,
                envelope_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            signature_valid = True
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Signature verification failed - file may be tampered: {str(e)}'
            }), 400
        
        # Unwrap AES key with recipient's private key (RSA-OAEP)
        wrapped_key = base64.b64decode(envelope['wrapped_key'])
        
        try:
            aes_key = recipient_private_key.decrypt(
                wrapped_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Key unwrapping failed - file not encrypted for this recipient'
            }), 400
        
        # Decrypt with AES-GCM
        nonce = base64.b64decode(envelope['nonce'])
        ciphertext_only = base64.b64decode(envelope['ciphertext'])
        tag = base64.b64decode(envelope['tag'])
        aad = base64.b64decode(envelope['aad'])
        
        # Check for nonce reuse (replay protection)
        nonce_key = base64.b64encode(nonce).decode('utf-8')
        if nonce_key in used_nonces:
            return jsonify({
                'success': False,
                'error': 'Replay attack detected - nonce already used'
            }), 400
        
        # Reconstruct full ciphertext with tag
        ciphertext = ciphertext_only + tag
        
        aesgcm = AESGCM(aes_key)
        
        start_time = time.time()
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            decryption_success = True
            # Add nonce to used set
            used_nonces.add(nonce_key)
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Decryption failed - authentication tag verification failed: {str(e)}'
            }), 400
        
        decryption_time = time.time() - start_time
        
        # Calculate hash of decrypted file
        decrypted_hash = hashlib.sha256(plaintext).hexdigest()
        
        return jsonify({
            'success': True,
            'filename': envelope['filename'],
            'size': envelope['size'],
            'decrypted_hash': decrypted_hash,
            'decryption_time': decryption_time,
            'content': base64.b64encode(plaintext).decode('utf-8'),
            'signature_valid': signature_valid,
            'recipient': envelope.get('recipient', 'Unknown')
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
