// Global State Management
const state = {
    currentStep: 0,
    selectedFile: null,
    selectedFileOwner: null,
    sender: 'alice',
    receiver: 'bob',
    keys: {
        alice: {},
        bob: {}
    },
    envelope: null,
    originalHash: null,
    decryptedHash: null,
    timings: {
        encryption: 0,
        verification: 0,
        decryption: 0
    },
    customFile: null
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeEventListeners();
    updateProgressStepper();
});

// Event Listeners
function initializeEventListeners() {
    // File selection
    document.querySelectorAll('.file-item').forEach(item => {
        item.addEventListener('click', () => selectFile(item));
    });
    
    // Transfer direction
    document.querySelectorAll('input[name="direction"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (e.target.value === 'alice-to-bob') {
                state.sender = 'alice';
                state.receiver = 'bob';
            } else {
                state.sender = 'bob';
                state.receiver = 'alice';
            }
        });
    });
    
    // Custom file upload
    document.getElementById('custom-file').addEventListener('change', handleCustomFileUpload);
    
    // Start button
    document.getElementById('start-btn').addEventListener('click', startTransfer);
    
    // Intercept button
    document.getElementById('intercept-btn').addEventListener('click', openInterceptModal);
    
    // Attack checkboxes
    document.querySelectorAll('.attack-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', handleAttackToggle);
    });
}

// File Selection
function selectFile(element) {
    // Remove previous selection
    document.querySelectorAll('.file-item').forEach(item => {
        item.classList.remove('selected');
    });
    
    // Select current file
    element.classList.add('selected');
    state.selectedFile = element.dataset.filename;
    state.selectedFileOwner = element.dataset.owner;
    
    // Clear custom file
    state.customFile = null;
    document.getElementById('custom-file-name').textContent = '';
}

// Custom File Upload
function handleCustomFileUpload(e) {
    const file = e.target.files[0];
    if (file) {
        state.customFile = file;
        state.selectedFile = file.name;
        state.selectedFileOwner = state.sender;
        
        document.getElementById('custom-file-name').textContent = `Selected: ${file.name} (${formatFileSize(file.size)})`;
        
        // Clear preset file selections
        document.querySelectorAll('.file-item').forEach(item => {
            item.classList.remove('selected');
        });
    }
}

// Start Transfer
async function startTransfer() {
    if (!state.selectedFile && !state.customFile) {
        alert('Please select a file first!');
        return;
    }
    
    // Move to step 1 and start key generation
    await goToStep(1);
    await generateKeys();
}

// Navigate to Step
async function goToStep(stepNumber) {
    // Hide all steps
    document.querySelectorAll('.step-section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Show target step
    const targetStep = document.getElementById(`step-${stepNumber}`);
    if (targetStep) {
        targetStep.classList.add('active');
        state.currentStep = stepNumber;
        updateProgressStepper();
        
        // Scroll to top
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
}

// Update Progress Stepper
function updateProgressStepper() {
    document.querySelectorAll('.progress-stepper .step').forEach((step, index) => {
        const stepNum = parseInt(step.dataset.step);
        
        if (stepNum < state.currentStep) {
            step.classList.add('completed');
            step.classList.remove('active');
        } else if (stepNum === state.currentStep) {
            step.classList.add('active');
            step.classList.remove('completed');
        } else {
            step.classList.remove('active', 'completed');
        }
    });
}

// Next Step
function nextStep() {
    if (state.currentStep < 9) {
        const nextStepNum = state.currentStep + 1;
        goToStep(nextStepNum);
        
        // Execute step-specific logic
        executeStepLogic(nextStepNum);
    }
}

// Previous Step
function previousStep() {
    if (state.currentStep > 0) {
        const prevStepNum = state.currentStep - 1;
        goToStep(prevStepNum);
    }
}

// Execute Step Logic
async function executeStepLogic(stepNum) {
    switch(stepNum) {
        case 2:
            await exchangeAndBindKeys();
            break;
        case 3:
            await encryptFile();
            break;
        case 4:
            displayKeyWrapping();
            break;
        case 5:
            displaySigning();
            break;
        case 6:
            startTransferAnimation();
            break;
        case 7:
            await verifySignature();
            break;
        case 8:
            await decryptFile();
            break;
        case 9:
            displayIntegrityCheck();
            break;
    }
}

// Step 1: Generate Keys
async function generateKeys() {
    try {
        // Generate keys for Alice
        const aliceResponse = await fetch('/api/generate-keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ party: 'alice' })
        });
        const aliceData = await aliceResponse.json();
        state.keys.alice = aliceData;
        
        // Animate Alice's keys
        animateKeyGeneration('alice', aliceData);
        
        // Small delay for visual effect
        await delay(500);
        
        // Generate keys for Bob
        const bobResponse = await fetch('/api/generate-keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ party: 'bob' })
        });
        const bobData = await bobResponse.json();
        state.keys.bob = bobData;
        
        // Animate Bob's keys
        animateKeyGeneration('bob', bobData);
        
    } catch (error) {
        console.error('Error generating keys:', error);
        alert('Failed to generate keys. Please try again.');
    }
}

// Animate Key Generation
function animateKeyGeneration(party, data) {
    // Signing keys
    const signingPublicElem = document.getElementById(`${party}-signing-key-public`);
    const signingPrivateElem = document.getElementById(`${party}-signing-key-private`);
    
    // Encryption keys
    const encryptionPublicElem = document.getElementById(`${party}-encryption-key-public`);
    const encryptionPrivateElem = document.getElementById(`${party}-encryption-key-private`);
    
    // Display truncated keys - store FULL key data for reveal
    signingPublicElem.textContent = truncateKey(data.signing_public);
    signingPrivateElem.textContent = '🔒 Click to reveal private key';
    signingPrivateElem.dataset.key = data.signing_private;  // Store full key
    
    encryptionPublicElem.textContent = truncateKey(data.encryption_public);
    encryptionPrivateElem.textContent = '🔒 Click to reveal private key';
    encryptionPrivateElem.dataset.key = data.encryption_private;  // Store full key
    
    // Add animation reset
    [signingPublicElem, signingPrivateElem, encryptionPublicElem, encryptionPrivateElem].forEach(elem => {
        elem.style.animation = 'none';
        setTimeout(() => {
            elem.style.animation = '';
        }, 10);
    });
}

// Toggle Private Key Visibility
function toggleKeyVisibility(element) {
    if (element.classList.contains('hidden')) {
        // Show the key (full, non-truncated)
        element.classList.remove('hidden');
        element.textContent = element.dataset.key || '*** Private Key Data ***';
    } else {
        // Hide the key
        element.classList.add('hidden');
        element.textContent = '🔒 Click to reveal private key';
    }
}

// Step 2: Exchange and Bind Keys
async function exchangeAndBindKeys() {
    try {
        // Update Alice's public key preview
        document.getElementById('alice-pub-key-preview').querySelector('code').textContent = 
            truncateKeyForPreview(state.keys.alice.encryption_public);
        
        // Bind Alice's key
        const aliceBindResponse = await fetch('/api/bind-public-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ party: 'alice' })
        });
        const aliceBindData = await aliceBindResponse.json();
        
        // Display Alice's binding with animation
        await delay(300);
        document.getElementById('alice-key-hash-visual').textContent = 'Hashing...';
        await delay(500);
        document.getElementById('alice-key-hash').textContent = truncateHash(aliceBindData.key_hash);
        document.getElementById('alice-key-hash-visual').textContent = 'Hash (256 bits)';
        
        await delay(500);
        document.getElementById('alice-signature').textContent = truncateHash(aliceBindData.signature);
        
        await delay(500);
        
        // Update Bob's public key preview
        document.getElementById('bob-pub-key-preview').querySelector('code').textContent = 
            truncateKeyForPreview(state.keys.bob.encryption_public);
        
        // Bind Bob's key
        const bobBindResponse = await fetch('/api/bind-public-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ party: 'bob' })
        });
        const bobBindData = await bobBindResponse.json();
        
        // Display Bob's binding with animation
        await delay(300);
        document.getElementById('bob-key-hash-visual').textContent = 'Hashing...';
        await delay(500);
        document.getElementById('bob-key-hash').textContent = truncateHash(bobBindData.key_hash);
        document.getElementById('bob-key-hash-visual').textContent = 'Hash (256 bits)';
        
        await delay(500);
        document.getElementById('bob-signature').textContent = truncateHash(bobBindData.signature);
        
        // Verify both bindings
        await verifyKeyBindings();
        
    } catch (error) {
        console.error('Error binding keys:', error);
        alert('Failed to bind keys. Please try again.');
    }
}

// Truncate key for preview display
function truncateKeyForPreview(key) {
    if (!key) return '';
    const lines = key.split('\n');
    if (lines.length > 3) {
        return lines[0] + '\n' + lines[1] + '\n...\n' + lines[lines.length - 1];
    }
    return key;
}

// Verify Key Bindings
async function verifyKeyBindings() {
    // In a real scenario, each party would verify the other's binding
    // For demo purposes, we'll show successful verification
    await delay(500);
}

// Step 3: Encrypt File
async function encryptFile() {
    try {
        // Update file display
        document.getElementById('selected-filename').textContent = state.selectedFile;
        
        // Prepare file for encryption
        let formData = new FormData();
        formData.append('sender', state.sender);
        formData.append('receiver', state.receiver);
        
        if (state.customFile) {
            formData.append('file', state.customFile);
        } else {
            // Create sample file
            const sampleFileResponse = await fetch('/api/create-sample-file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    filename: state.selectedFile,
                    size: getSampleFileSize(state.selectedFile)
                })
            });
            const sampleData = await sampleFileResponse.json();
            
            // Convert base64 to blob
            const fileBlob = base64ToBlob(sampleData.content);
            formData.append('file', fileBlob, state.selectedFile);
        }
        
        // Encrypt file
        const response = await fetch('/api/encrypt-file', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            state.envelope = data.envelope;
            state.originalHash = data.original_hash;
            state.timings.encryption = data.encryption_time;
            
            // Update display
            document.getElementById('selected-filesize').textContent = formatFileSize(data.envelope.size);
            document.getElementById('aes-key').textContent = '32 random bytes (hidden for security)';
            document.getElementById('nonce-display').textContent = truncateHash(data.envelope.nonce);
            document.getElementById('aad-display').textContent = `${state.sender}->${state.receiver}:${state.selectedFile}`;
            document.getElementById('encrypt-time').textContent = formatTime(data.encryption_time);
            document.getElementById('ciphertext-preview').textContent = formatHexPreview(data.ciphertext_preview);
        } else {
            throw new Error(data.error);
        }
        
    } catch (error) {
        console.error('Error encrypting file:', error);
        alert('Failed to encrypt file. Please try again.');
    }
}

// Step 4: Display Key Wrapping
function displayKeyWrapping() {
    if (!state.envelope) return;
    
    document.getElementById('receiver-name').textContent = state.receiver.charAt(0).toUpperCase() + state.receiver.slice(1);
    document.getElementById('receiver-name-2').textContent = state.receiver.charAt(0).toUpperCase() + state.receiver.slice(1);
    document.getElementById('aes-key-unwrapped').textContent = '*** AES-256 Key (32 bytes) ***';
    document.getElementById('wrapped-key-display').textContent = truncateHash(state.envelope.wrapped_key);
}

// Step 5: Display Signing
function displaySigning() {
    if (!state.envelope) return;
    
    document.getElementById('sender-name').textContent = state.sender.charAt(0).toUpperCase() + state.sender.slice(1);
    
    // Display envelope JSON (without signature for now)
    const envelopeDisplay = {
        wrapped_key: truncateHash(state.envelope.wrapped_key),
        nonce: truncateHash(state.envelope.nonce),
        ciphertext: truncateHash(state.envelope.ciphertext) + '...',
        tag: truncateHash(state.envelope.tag),
        filename: state.envelope.filename,
        size: state.envelope.size,
        sender: state.envelope.sender,
        receiver: state.envelope.receiver
    };
    
    document.getElementById('envelope-json').textContent = JSON.stringify(envelopeDisplay, null, 2);
    
    // Show envelope hash and signature
    const envelopeStr = JSON.stringify(state.envelope, null, 2);
    document.getElementById('envelope-hash').textContent = 'SHA-256 hash of envelope...';
    document.getElementById('envelope-signature').textContent = truncateHash(state.envelope.signature);
}

// Step 6: Transfer Animation
function startTransferAnimation() {
    // Update transfer visualization
    const senderAvatar = document.getElementById('sender-avatar');
    const receiverAvatar = document.getElementById('receiver-avatar');
    const senderLabel = document.getElementById('sender-label');
    const receiverLabel = document.getElementById('receiver-label');
    
    senderAvatar.src = `/static/${state.sender}-image.jpg`;
    receiverAvatar.src = `/static/${state.receiver}-image.jpg`;
    senderLabel.textContent = state.sender.charAt(0).toUpperCase() + state.sender.slice(1);
    receiverLabel.textContent = state.receiver.charAt(0).toUpperCase() + state.receiver.slice(1);
}

// Step 7: Verify Signature
async function verifySignature() {
    try {
        // Display received envelope
        const envelopeDisplay = {
            wrapped_key: truncateHash(state.envelope.wrapped_key),
            nonce: truncateHash(state.envelope.nonce),
            ciphertext: truncateHash(state.envelope.ciphertext) + '...',
            tag: truncateHash(state.envelope.tag),
            filename: state.envelope.filename,
            size: state.envelope.size
        };
        
        document.getElementById('received-envelope').textContent = JSON.stringify(envelopeDisplay, null, 2);
        document.getElementById('verify-sender-name').textContent = state.sender.charAt(0).toUpperCase() + state.sender.slice(1);
        document.getElementById('verify-hash').textContent = 'SHA-256 hash recreated...';
        
        // Verify signature
        const response = await fetch('/api/verify-signature', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ envelope: state.envelope })
        });
        
        const data = await response.json();
        
        if (data.success && data.verified) {
            state.timings.verification = data.verification_time;
            document.getElementById('verify-time').textContent = formatTime(data.verification_time);
        } else {
            document.querySelector('.verification-result').innerHTML = `
                <span class="verify-status" style="background: var(--danger-color);">❌ VERIFICATION FAILED</span>
                <p>Signature is invalid - envelope may have been tampered with</p>
            `;
        }
        
    } catch (error) {
        console.error('Error verifying signature:', error);
        alert('Failed to verify signature. Please try again.');
    }
}

// Step 8: Decrypt File
async function decryptFile() {
    try {
        // Display wrapped key
        document.getElementById('wrapped-key-decrypt').textContent = truncateHash(state.envelope.wrapped_key);
        document.getElementById('decrypt-ciphertext').textContent = truncateHash(state.envelope.ciphertext);
        document.getElementById('decrypt-nonce').textContent = truncateHash(state.envelope.nonce);
        document.getElementById('decrypt-tag').textContent = truncateHash(state.envelope.tag);
        
        // Decrypt file
        const response = await fetch('/api/decrypt-file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ envelope: state.envelope })
        });
        
        const data = await response.json();
        
        if (data.success) {
            state.decryptedHash = data.decrypted_hash;
            state.timings.decryption = data.decryption_time;
            
            // Update display
            document.getElementById('unwrapped-key').textContent = '*** AES-256 Key (32 bytes) ***';
            document.getElementById('decrypt-time').textContent = formatTime(data.decryption_time);
            document.getElementById('decrypted-filename').textContent = data.filename;
            document.getElementById('decrypted-filesize').textContent = formatFileSize(data.size);
        } else {
            throw new Error(data.error);
        }
        
    } catch (error) {
        console.error('Error decrypting file:', error);
        alert('Failed to decrypt file. Please try again.');
    }
}

// Step 9: Display Integrity Check
function displayIntegrityCheck() {
    // Display hashes
    document.getElementById('original-hash').textContent = state.originalHash;
    document.getElementById('received-hash').textContent = state.decryptedHash;
    
    // Calculate total time
    const totalTime = state.timings.encryption + state.timings.verification + state.timings.decryption;
    
    // Display metrics
    document.getElementById('final-size').textContent = formatFileSize(state.envelope.size);
    document.getElementById('final-time').textContent = formatTime(totalTime);
    
    // Check if hashes match
    if (state.originalHash === state.decryptedHash) {
        // Success - already shown in HTML
    } else {
        document.querySelector('.result-box').classList.remove('success');
        document.querySelector('.result-box').style.background = 'var(--danger-color)';
        document.querySelector('.result-box h3').textContent = 'HASH MISMATCH!';
        document.querySelector('.result-box p').textContent = 'File integrity check failed!';
    }
}

// Intercept Modal Functions
function openInterceptModal() {
    const modal = document.getElementById('intercept-modal');
    modal.classList.add('active');
    
    // Display intercepted envelope
    const envelopeDisplay = {
        wrapped_key: state.envelope.wrapped_key.substring(0, 64) + '...',
        nonce: state.envelope.nonce,
        ciphertext: state.envelope.ciphertext.substring(0, 128) + '...',
        tag: state.envelope.tag,
        aad: state.envelope.aad,
        filename: state.envelope.filename,
        size: state.envelope.size,
        signature: state.envelope.signature.substring(0, 64) + '...'
    };
    
    document.getElementById('intercepted-envelope').textContent = JSON.stringify(envelopeDisplay, null, 2);
}

function closeInterceptModal() {
    const modal = document.getElementById('intercept-modal');
    modal.classList.remove('active');
    
    // Reset attack checkboxes
    document.querySelectorAll('.attack-checkbox').forEach(checkbox => {
        checkbox.checked = false;
    });
    
    // Hide attack results
    document.getElementById('attack-results').classList.remove('active');
    document.getElementById('attack-results').innerHTML = '';
}

// Handle Attack Simulation
async function handleAttackToggle(e) {
    const attackType = e.target.id.replace('attack-', '');
    const resultsContainer = document.getElementById('attack-results');
    
    if (e.target.checked) {
        // Simulate attack
        try {
            const response = await fetch('/api/simulate-attack', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    attack_type: attackType,
                    envelope: state.envelope
                })
            });
            
            const data = await response.json();
            
            // Display result
            resultsContainer.classList.add('active');
            
            const resultItem = document.createElement('div');
            resultItem.className = 'attack-result-item';
            resultItem.innerHTML = `
                <h4>🛡️ ${attackType.toUpperCase()} Attack Blocked!</h4>
                <p>${data.reason}</p>
            `;
            
            resultsContainer.appendChild(resultItem);
            
        } catch (error) {
            console.error('Error simulating attack:', error);
        }
    } else {
        // Remove result for this attack
        resultsContainer.querySelector(`[data-attack="${attackType}"]`)?.remove();
        
        if (resultsContainer.children.length === 0) {
            resultsContainer.classList.remove('active');
        }
    }
}

// Restart Demo
function restartDemo() {
    // Reset state
    state.currentStep = 0;
    state.selectedFile = null;
    state.selectedFileOwner = null;
    state.sender = 'alice';
    state.receiver = 'bob';
    state.envelope = null;
    state.originalHash = null;
    state.decryptedHash = null;
    state.customFile = null;
    
    // Reset UI
    document.querySelectorAll('.file-item').forEach(item => {
        item.classList.remove('selected');
    });
    
    document.querySelector('input[value="alice-to-bob"]').checked = true;
    document.getElementById('custom-file-name').textContent = '';
    document.getElementById('custom-file').value = '';
    
    // Go back to step 0
    goToStep(0);
}

// Utility Functions
function truncateKey(key) {
    if (!key) return '';
    const lines = key.split('\n').filter(line => !line.includes('---'));
    return lines.join('').substring(0, 64) + '...';
}

function truncateHash(hash) {
    if (!hash) return '';
    if (hash.length <= 32) return hash;
    return hash.substring(0, 16) + '...' + hash.substring(hash.length - 16);
}

/**
 * Dynamic time formatting function
 * Adjusts decimal places based on where the first non-zero decimal appears
 * @param {number} timeInSeconds - Time value in seconds
 * @returns {string} Formatted time string with appropriate decimal precision
 */
function formatTime(timeInSeconds) {
    if (!timeInSeconds || timeInSeconds === 0) {
        return '0.0 ms';
    }
    
    // Convert to milliseconds
    const timeInMs = timeInSeconds * 1000;
    
    // If time is very small (< 0.001 ms), show in microseconds
    if (timeInMs < 0.001) {
        const timeInMicroseconds = timeInSeconds * 1000000;
        // Find first non-zero decimal position
        const decimalStr = timeInMicroseconds.toString().split('.')[1] || '';
        let precision = 1;
        
        for (let i = 0; i < decimalStr.length; i++) {
            if (decimalStr[i] !== '0') {
                precision = Math.min(i + 2, 6); // At least 2 digits after first non-zero
                break;
            }
        }
        
        return timeInMicroseconds.toFixed(precision) + ' µs';
    }
    
    // For milliseconds, find the first non-zero decimal position
    const decimalPart = timeInMs.toString().split('.')[1] || '';
    let precision = 1;
    
    // If there's a decimal part, find first non-zero digit
    if (decimalPart.length > 0) {
        for (let i = 0; i < decimalPart.length; i++) {
            if (decimalPart[i] !== '0') {
                // Set precision to show at least 1-2 significant digits after first non-zero
                precision = Math.min(i + 2, 6);
                break;
            }
        }
    } else {
        // No decimal part or integer value
        precision = 1;
    }
    
    // Cap precision at 6 decimal places max
    precision = Math.min(precision, 6);
    
    return timeInMs.toFixed(precision) + ' ms';
}

function formatHexPreview(base64Str) {
    if (!base64Str) return '';
    
    // Convert base64 to hex representation
    const binary = atob(base64Str);
    let hex = '';
    for (let i = 0; i < Math.min(binary.length, 128); i++) {
        const byte = binary.charCodeAt(i).toString(16).padStart(2, '0');
        hex += byte;
        if ((i + 1) % 4 === 0) hex += ' ';
        if ((i + 1) % 16 === 0) hex += '\n';
    }
    return hex + '\n...';
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
}

function getSampleFileSize(filename) {
    if (filename.includes('1kb')) return 1024;
    if (filename.includes('1mb')) return 1048576;
    if (filename.includes('10mb')) return 10485760;
    return 1024; // Default
}

function base64ToBlob(base64) {
    const binary = atob(base64);
    const array = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        array[i] = binary.charCodeAt(i);
    }
    return new Blob([array]);
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Export for global access
window.nextStep = nextStep;
window.previousStep = previousStep;
window.restartDemo = restartDemo;
window.openInterceptModal = openInterceptModal;
window.closeInterceptModal = closeInterceptModal;
window.toggleKeyVisibility = toggleKeyVisibility;
