// Global State Management
const state = {
    currentStep: 0,
    bindingStage: 0,
    selectedFile: null,
    selectedFileOwner: null,
    sender: 'alice',
    receiver: 'bob',
    keys: {
        alice: {},
        bob: {}
    },
    envelope: null,
    originalEnvelope: null,  // Store original before attack
    attackApplied: false,
    attackType: null,
    attackDetails: null,
    originalHash: null,
    decryptedHash: null,
    decryptedContent: null,
    decryptedFilename: null,
    bindingSignatures: {
        alice: null,
        bob: null
    },
    bindingVerification: {
        alice: null,
        bob: null
    },
    timings: {
        encryption: 0,
        verification: 0,
        decryption: 0
    },
    customFile: null
};

const bindingStageLabels = [
    'Encryption Public Key',
    'Apply SHA-256 Hash Function',
    'Sign with Private Signing Key (RSA-PSS)',
    'Signed Public Key Package'
];

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeEventListeners();
    updateProgressStepper();
    setupBindingStageControls();
    updateBindingVerificationUI();
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
    
    // Attack simulation handlers
    const interceptBtn = document.getElementById('intercept-btn');
    if (interceptBtn) {
        interceptBtn.addEventListener('click', showAttackPanel);
    }
    
    const cancelAttackBtn = document.getElementById('cancel-attack-btn');
    if (cancelAttackBtn) {
        cancelAttackBtn.addEventListener('click', closeAttackModal);
    }
    
    const applyAttackBtn = document.getElementById('apply-attack-btn');
    if (applyAttackBtn) {
        applyAttackBtn.addEventListener('click', applyAttack);
    }
    
    // Radio button change handlers
    document.querySelectorAll('input[name="attack-type"]').forEach(radio => {
        radio.addEventListener('change', handleAttackSelection);
    });
    
    // Download envelope button removed from demo
    
    const envelopeImportInput = document.getElementById('envelope-import-input');
    if (envelopeImportInput) {
        envelopeImportInput.addEventListener('change', handleEnvelopeImport);
    }
    
    const downloadBtn = document.getElementById('download-decrypted-btn');
    if (downloadBtn) {
        downloadBtn.addEventListener('click', downloadDecryptedFile);
    }
}

function setupBindingStageControls() {
    const prevBtn = document.getElementById('binding-stage-prev');
    const nextBtn = document.getElementById('binding-stage-next');
    
    if (prevBtn) {
        prevBtn.addEventListener('click', () => {
            const prevStage = (state.bindingStage - 1 + bindingStageLabels.length) % bindingStageLabels.length;
            setBindingStage(prevStage);
        });
    }
    
    if (nextBtn) {
        nextBtn.addEventListener('click', () => {
            const nextStage = (state.bindingStage + 1) % bindingStageLabels.length;
            setBindingStage(nextStage);
        });
    }
    setBindingStage(0);
}

function setBindingStage(stageIndex) {
    if (stageIndex < 0 || stageIndex >= bindingStageLabels.length) {
        stageIndex = 0;
    }
    state.bindingStage = stageIndex;
    
    document.querySelectorAll('.binding-step').forEach(step => {
        const stage = parseInt(step.dataset.stage, 10);
        if (Number.isNaN(stage)) return;
        if (stage === state.bindingStage) {
            step.classList.add('visible-stage');
        } else {
            step.classList.remove('visible-stage');
        }
    });
    
    const indicator = document.getElementById('binding-stage-indicator');
    if (indicator) {
        indicator.textContent = `Stage ${stageIndex + 1} of ${bindingStageLabels.length} · ${bindingStageLabels[stageIndex]}`;
    }
    
    // Update exchange center icon and label based on stage
    const exchangeIcon = document.getElementById('exchange-icon');
    const exchangeLabel = document.getElementById('exchange-label');
    
    if (exchangeIcon && exchangeLabel) {
        if (stageIndex === 3) { // Stage 4 (0-indexed as 3)
            exchangeIcon.textContent = '⇄';
            exchangeLabel.textContent = 'Secure Exchange';
        } else if (stageIndex === 0) {
            exchangeIcon.textContent = '🔓';
            exchangeLabel.textContent = 'Public Keys';
        } else if (stageIndex === 1) {
            exchangeIcon.textContent = '🔢';
            exchangeLabel.textContent = 'Hashing Keys';
        } else if (stageIndex === 2) {
            exchangeIcon.textContent = '✍️';
            exchangeLabel.textContent = 'Signing Keys';
        }
    }
    
    // Update verification box based on stage
    updateBindingVerificationUI();
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
    switch (stepNum) {
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
            // Only decrypt if we haven't already (e.g. after importing an envelope)
            if (!state.decryptedContent) {
                await decryptFile();
            }
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
        setBindingStage(0);
        state.bindingSignatures.alice = null;
        state.bindingSignatures.bob = null;
        state.bindingVerification.alice = null;
        state.bindingVerification.bob = null;
        updateBindingVerificationUI();
        
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
        state.bindingSignatures.alice = aliceBindData.signature;
        
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
        state.bindingSignatures.bob = bobBindData.signature;
        
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
    if (!state.bindingSignatures.alice || !state.bindingSignatures.bob) {
        state.bindingVerification.alice = null;
        state.bindingVerification.bob = null;
        updateBindingVerificationUI();
        return;
    }
    
    // Show pending status while verification runs
    state.bindingVerification.alice = null;
    state.bindingVerification.bob = null;
    updateBindingVerificationUI();
    
    const [aliceResult, bobResult] = await Promise.all([
        verifyBindingWithServer('alice', state.bindingSignatures.bob),
        verifyBindingWithServer('bob', state.bindingSignatures.alice)
    ]);
    
    state.bindingVerification.alice = aliceResult;
    state.bindingVerification.bob = bobResult;
    updateBindingVerificationUI();
}

async function verifyBindingWithServer(party, signature) {
    if (!signature) return false;
    
    try {
        const response = await fetch('/api/verify-binding', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ party, signature })
        });
        
        const data = await response.json();
        return data.success && data.verified;
    } catch (error) {
        console.error('Error verifying binding:', error);
        return false;
    }
}

function updateBindingVerificationUI() {
    const box = document.getElementById('binding-verify-box');
    if (!box) return;
    
    const icon = document.getElementById('binding-verify-icon');
    const title = document.getElementById('binding-verify-title');
    const description = document.getElementById('binding-verify-description');
    const aliceStatus = state.bindingVerification.alice;
    const bobStatus = state.bindingVerification.bob;
    
    box.classList.remove('pending', 'error');
    
    // Only show success message in stage 4 (index 3)
    if (state.bindingStage === 3 && aliceStatus === true && bobStatus === true) {
        icon.textContent = '✅';
        title.textContent = 'Keys Successfully Bound & Verified';
        description.textContent = 'Both parties validated each other\'s encryption public keys using RSA-PSS signatures. Man-in-the-Middle attacks are prevented.';
    } else if (aliceStatus === false || bobStatus === false) {
        box.classList.add('error');
        icon.textContent = '⚠️';
        title.textContent = 'Verification Failed';
        description.textContent = 'One or both digital signatures failed verification. Regenerate keys and retry to ensure authenticity.';
    } else {
        box.classList.add('pending');
        icon.textContent = '⏳';
        title.textContent = 'Awaiting Verification';
        description.textContent = 'Once both parties sign each other\'s encryption public keys, we will run RSA-PSS verification to confirm authenticity.';
    }
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
    
    // Display envelope components (before signature is added)
    const envelopeBeforeSigning = {
        wrapped_key: truncateHash(state.envelope.wrapped_key),
        nonce: truncateHash(state.envelope.nonce),
        ciphertext: truncateHash(state.envelope.ciphertext) + '...',
        tag: truncateHash(state.envelope.tag),
        filename: state.envelope.filename,
        size: state.envelope.size,
        sender: state.envelope.sender,
        receiver: state.envelope.receiver,
        timestamp: state.envelope.timestamp
    };
    
    document.getElementById('envelope-json').textContent = JSON.stringify(envelopeBeforeSigning, null, 2);
    
    // Compute and show the SHA-256 hash of the envelope (before signature)
    const envelopeJson = JSON.stringify({
        wrapped_key: state.envelope.wrapped_key,
        nonce: state.envelope.nonce,
        ciphertext: state.envelope.ciphertext,
        tag: state.envelope.tag,
        filename: state.envelope.filename,
        size: state.envelope.size,
        sender: state.envelope.sender,
        receiver: state.envelope.receiver,
        timestamp: state.envelope.timestamp
    }, Object.keys(envelopeBeforeSigning).sort());
    
    // Show a representation of the hash (in reality this is computed server-side)
    document.getElementById('envelope-hash').textContent = 'SHA-256: ' + truncateHash('hash_of_envelope_content', 50);
    
    // Show the RSA-PSS signature
    document.getElementById('envelope-signature').textContent = truncateHash(state.envelope.signature);
    
    // Display the complete signed envelope (original envelope + signature field)
    const signedEnvelopePreview = document.getElementById('signed-envelope-preview');
    if (signedEnvelopePreview) {
        // The signed envelope is the original envelope with signature appended
        const completeEnvelope = {
            wrapped_key: truncateHash(state.envelope.wrapped_key, 60),
            nonce: truncateHash(state.envelope.nonce, 40),
            ciphertext: truncateHash(state.envelope.ciphertext, 80) + '... [truncated for display]',
            tag: truncateHash(state.envelope.tag, 40),
            filename: state.envelope.filename,
            size: state.envelope.size,
            sender: state.envelope.sender,
            receiver: state.envelope.receiver,
            timestamp: state.envelope.timestamp,
            signature: truncateHash(state.envelope.signature, 60)
        };
        signedEnvelopePreview.textContent = JSON.stringify(completeEnvelope, null, 2);
    }
}

function downloadEnvelope() {
    if (!state.envelope) {
        alert('Envelope not available yet. Complete previous steps first.');
        return;
    }
    
    const envelopeJson = JSON.stringify(state.envelope, null, 2);
    const blob = new Blob([envelopeJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const filenameBase = (state.envelope.filename || 'envelope').replace(/\s+/g, '_');
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `${filenameBase}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
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
        // Display the complete received envelope (same as Step 5 signed envelope)
        const completeEnvelope = {
            wrapped_key: truncateHash(state.envelope.wrapped_key, 60),
            nonce: truncateHash(state.envelope.nonce, 40),
            ciphertext: truncateHash(state.envelope.ciphertext, 80) + '... [truncated for display]',
            tag: truncateHash(state.envelope.tag, 40),
            filename: state.envelope.filename,
            size: state.envelope.size,
            sender: state.envelope.sender,
            receiver: state.envelope.receiver,
            timestamp: state.envelope.timestamp,
            signature: truncateHash(state.envelope.signature, 60)
        };
        
        document.getElementById('received-envelope').textContent = JSON.stringify(completeEnvelope, null, 2);
        
        // Show signature being verified
        const verifySignatureElem = document.getElementById('verify-signature');
        if (verifySignatureElem) {
            verifySignatureElem.textContent = truncateHash(state.envelope.signature, 60);
        }
        
        // Show hash being computed
        document.getElementById('verify-hash').textContent = 'SHA-256: ' + truncateHash('hash_of_envelope_content', 50);
        
        // Update sender names
        const senderName = state.sender.charAt(0).toUpperCase() + state.sender.slice(1);
        document.getElementById('verify-sender-name').textContent = senderName;
        const verifySenderName2 = document.getElementById('verify-sender-name-2');
        if (verifySenderName2) {
            verifySenderName2.textContent = senderName;
        }
        
        // Verify signature
        const response = await fetch('/api/verify-signature', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ envelope: state.envelope })
        });
        
        const data = await response.json();
        
        if (data.success) {
            state.timings.verification = data.verification_time;
            
            // Check if attack was detected
            if (data.attack_detected) {
                displayAttackDetection(data);
            } else if (data.verified) {
                // Normal verification success - show success, hide attack alert
                const verificationResult = document.getElementById('verification-result');
                const attackAlert = document.getElementById('attack-detection-alert');
                const nextBtn = document.getElementById('step-7-next-btn');
                const restartBtn = document.getElementById('step-7-restart-btn');
                
                if (verificationResult) {
                    verificationResult.style.display = 'block';
                    verificationResult.classList.remove('error');
                    const verifyTimeElem = document.getElementById('verify-time');
                    if (verifyTimeElem) {
                        verifyTimeElem.textContent = formatTime(data.verification_time);
                    }
                }
                
                if (attackAlert) {
                    attackAlert.style.display = 'none';
                }
                
                // Show Continue button, hide Restart button
                if (nextBtn) {
                    nextBtn.style.display = 'inline-flex';
                }
                if (restartBtn) {
                    restartBtn.style.display = 'none';
                }
            } else {
                // Verification failed but no specific attack detected
                const verificationResult = document.getElementById('verification-result');
                if (verificationResult) {
                    verificationResult.style.display = 'block';
                    verificationResult.classList.add('error');
                    verificationResult.innerHTML = `
                        <div class="verify-status-badge" style="background: var(--danger-color);">❌ VERIFICATION FAILED</div>
                        <div class="verify-details">
                            <p>Signature is invalid - envelope may have been tampered with</p>
                        </div>
                    `;
                }
            }
        }
        
    } catch (error) {
        console.error('Error verifying signature:', error);
        alert('Failed to verify signature. Please try again.');
    }
}

function displayAttackDetection(data) {
    const attackAlert = document.getElementById('attack-detection-alert');
    const verificationResult = document.getElementById('verification-result');
    
    // Hide the success verification result, show attack alert
    if (verificationResult) {
        verificationResult.style.display = 'none';
    }
    
    if (attackAlert) {
        attackAlert.style.display = 'block';
        
        // Populate attack details
        const attackNameElem = document.getElementById('detected-attack-name');
        const attackDescElem = document.getElementById('detected-attack-description');
        const detectionMethodElem = document.getElementById('detection-method');
        const securityImpactElem = document.getElementById('security-impact');
        const blockedByElem = document.getElementById('blocked-by');
        const securityRecElem = document.getElementById('security-recommendation');
        
        if (attackNameElem) {
            attackNameElem.textContent = data.attack_details.attack_name;
        }
        
        if (attackDescElem) {
            attackDescElem.textContent = data.attack_details.description;
        }
        
        if (detectionMethodElem) {
            detectionMethodElem.textContent = data.attack_details.detection_method;
        }
        
        if (securityImpactElem) {
            securityImpactElem.textContent = data.attack_details.security_impact;
        }
        
        if (blockedByElem) {
            blockedByElem.textContent = data.attack_details.blocked_by;
        }
        
        if (securityRecElem) {
            securityRecElem.textContent = data.security_recommendation || 'DO NOT PROCEED TO DECRYPTION - ENVELOPE IS COMPROMISED';
        }
        
        // Display tampering evidence if available
        if (data.tampering_evidence && data.tampering_evidence.length > 0) {
            const evidenceContainer = document.getElementById('tampering-evidence-container');
            const evidenceList = document.getElementById('tampering-evidence-list');
            
            if (evidenceContainer && evidenceList) {
                evidenceContainer.style.display = 'block';
                evidenceList.innerHTML = '';
                
                data.tampering_evidence.forEach(evidence => {
                    const evidenceDiv = document.createElement('div');
                    evidenceDiv.className = 'evidence-item';
                    evidenceDiv.innerHTML = `
                        <div class="evidence-field"><strong>Field:</strong> <code>${evidence.field}</code></div>
                        <div class="evidence-issue"><strong>Issue:</strong> ${evidence.issue}</div>
                        ${evidence.details ? `<div class="evidence-details">${evidence.details}</div>` : ''}
                        ${evidence.original && evidence.tampered ? `
                            <div class="evidence-comparison">
                                <div><strong>Expected:</strong> <code>${evidence.original}</code></div>
                                <div><strong>Found:</strong> <code class="tampered-value">${evidence.tampered}</code></div>
                            </div>
                        ` : ''}
                    `;
                    evidenceList.appendChild(evidenceDiv);
                });
            }
        }
    }
    
    // Replace Continue button with Restart button
    const nextBtn = document.getElementById('step-7-next-btn');
    const restartBtn = document.getElementById('step-7-restart-btn');
    
    if (nextBtn) {
        nextBtn.style.display = 'none';
    }
    
    if (restartBtn) {
        restartBtn.style.display = 'inline-flex';
    }
}

// Step 8: Decrypt File
async function decryptFile(options = {}) {
    const { ignoreReplay = false } = options;

    try {
        // Display wrapped key
        document.getElementById('wrapped-key-decrypt').textContent = truncateHash(state.envelope.wrapped_key);
        document.getElementById('decrypt-ciphertext').textContent = truncateHash(state.envelope.ciphertext);
        document.getElementById('decrypt-nonce').textContent = truncateHash(state.envelope.nonce);
        document.getElementById('decrypt-tag').textContent = truncateHash(state.envelope.tag);
        
        const downloadBtn = document.getElementById('download-decrypted-btn');
        if (downloadBtn) {
            downloadBtn.disabled = true;
        }
        state.decryptedContent = null;
        state.decryptedFilename = null;
        
        // Decrypt file
        const response = await fetch('/api/decrypt-file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                envelope: state.envelope,
                ignore_replay: ignoreReplay
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            state.decryptedHash = data.decrypted_hash;
            state.decryptedContent = data.content;
            state.decryptedFilename = data.filename;
            state.timings.decryption = data.decryption_time;
            
            // Update display
            document.getElementById('unwrapped-key').textContent = '*** AES-256 Key (32 bytes) ***';
            document.getElementById('decrypt-time').textContent = formatTime(data.decryption_time);
            document.getElementById('decrypted-filename').textContent = data.filename;
            document.getElementById('decrypted-filesize').textContent = formatFileSize(data.size);
            
            if (downloadBtn) {
                downloadBtn.disabled = false;
            }
        } else {
            throw new Error(data.error || 'Decryption failed');
        }
        
    } catch (error) {
        console.error('Error decrypting file:', error);
        alert(error?.message ? `Decryption failed: ${error.message}` : 'Decryption failed. Please try again.');
    }
}


async function handleEnvelopeImport(event) {
    const fileInput = event.target;
    const file = fileInput.files[0];
    const statusElem = document.getElementById('import-envelope-status');
    
    if (!file) return;
    if (statusElem) {
        statusElem.textContent = `Loading ${file.name}...`;
    }
    
    const reader = new FileReader();
    reader.onerror = () => {
        if (statusElem) statusElem.textContent = 'Failed to read file';
        alert('Unable to read the selected file.');
        fileInput.value = '';
    };
    
    reader.onload = async (loadEvent) => {
        try {
            const importedEnvelope = JSON.parse(loadEvent.target.result);
            if (!isValidEnvelope(importedEnvelope)) {
                throw new Error('Invalid envelope structure');
            }
            
            state.envelope = importedEnvelope;
            if (importedEnvelope.sender && typeof importedEnvelope.sender === 'string') {
                state.sender = importedEnvelope.sender.toLowerCase();
            }
            if (importedEnvelope.receiver && typeof importedEnvelope.receiver === 'string') {
                state.receiver = importedEnvelope.receiver.toLowerCase();
            }
            state.originalHash = null;
            state.decryptedHash = null;
            state.decryptedContent = null;
            state.decryptedFilename = null;
            
            if (statusElem) {
                statusElem.textContent = `Loaded ${file.name}`;
            }
            
            await verifySignature();
            // When importing, skip replay protection: we expect to decrypt this again
            await decryptFile({ ignoreReplay: true });
        } catch (error) {
            console.error('Error importing envelope:', error);
            if (statusElem) statusElem.textContent = 'Failed to load envelope';
            alert('Unable to import envelope JSON. Please ensure it matches the expected format.');
        } finally {
            fileInput.value = '';
        }
    };
    
    reader.readAsText(file);
}


function isValidEnvelope(envelope) {
    if (!envelope || typeof envelope !== 'object') return false;
    const stringFields = ['wrapped_key', 'nonce', 'ciphertext', 'tag', 'aad', 'signature'];
    if (!stringFields.every(field => typeof envelope[field] === 'string' && envelope[field].length > 0)) {
        return false;
    }
    if (typeof envelope.filename !== 'string') return false;
    if (typeof envelope.size !== 'number') return false;
    return true;
}

function downloadDecryptedFile() {
    if (!state.decryptedContent) {
        alert('Decrypted file not available yet. Complete Step 8 first.');
        return;
    }
    
    try {
        const byteCharacters = atob(state.decryptedContent);
        const sliceSize = 1024;
        const byteArrays = [];
        
        for (let offset = 0; offset < byteCharacters.length; offset += sliceSize) {
            const slice = byteCharacters.slice(offset, offset + sliceSize);
            const byteNumbers = new Array(slice.length);
            for (let i = 0; i < slice.length; i++) {
                byteNumbers[i] = slice.charCodeAt(i);
            }
            byteArrays.push(new Uint8Array(byteNumbers));
        }
        
        const blob = new Blob(byteArrays, { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = state.decryptedFilename || state.envelope?.filename || 'decrypted-file';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Error downloading decrypted file:', error);
        alert('Unable to download decrypted file.');
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

// Attack Simulation Functions
function showAttackPanel() {
    const modal = document.getElementById('attack-modal');
    if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function closeAttackModal() {
    const modal = document.getElementById('attack-modal');
    const resultDisplay = document.getElementById('attack-result-display');
    const attackSelection = document.getElementById('attack-type-selection');
    const attackActions = document.getElementById('attack-actions');
    
    if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
    
    // Only reset if attack was not applied
    if (!state.attackApplied) {
        if (resultDisplay) {
            resultDisplay.style.display = 'none';
        }
        
        // Reset radio buttons
        document.querySelectorAll('input[name="attack-type"]').forEach(radio => {
            radio.checked = false;
            radio.disabled = false;
        });
        
        // Show attack selection
        if (attackSelection) {
            attackSelection.style.display = 'grid';
        }
        if (attackActions) {
            attackActions.style.display = 'flex';
        }
        
        // Show description
        const panelDescription = document.querySelector('.panel-description');
        if (panelDescription) {
            panelDescription.style.display = 'block';
        }
        
        // Reset apply button
        const applyBtn = document.getElementById('apply-attack-btn');
        if (applyBtn) {
            applyBtn.disabled = true;
            applyBtn.textContent = 'Apply Attack';
        }
    }
}

function hideAttackPanel() {
    closeAttackModal();
    
    // Reset state
    state.attackApplied = false;
    state.attackType = null;
    state.attackDetails = null;
    
    const resultDisplay = document.getElementById('attack-result-display');
    const attackSelection = document.getElementById('attack-type-selection');
    const attackActions = document.getElementById('attack-actions');
    const panelDescription = document.querySelector('.panel-description');
    
    if (resultDisplay) {
        resultDisplay.style.display = 'none';
    }
    
    // Reset radio buttons
    document.querySelectorAll('input[name="attack-type"]').forEach(radio => {
        radio.checked = false;
        radio.disabled = false;
    });
    
    // Show attack selection
    if (attackSelection) {
        attackSelection.style.display = 'grid';
    }
    if (attackActions) {
        attackActions.style.display = 'flex';
    }
    if (panelDescription) {
        panelDescription.style.display = 'block';
    }
    
    // Disable apply button
    const applyBtn = document.getElementById('apply-attack-btn');
    if (applyBtn) {
        applyBtn.disabled = true;
        applyBtn.textContent = 'Apply Attack';
    }
}

function handleAttackSelection(e) {
    const applyBtn = document.getElementById('apply-attack-btn');
    if (applyBtn) {
        applyBtn.disabled = false;
    }
}

async function applyAttack() {
    const selectedAttack = document.querySelector('input[name="attack-type"]:checked');
    
    if (!selectedAttack) {
        alert('Please select an attack type');
        return;
    }
    
    const attackType = selectedAttack.value;
    
    try {
        // Store original envelope if not already stored
        if (!state.originalEnvelope) {
            state.originalEnvelope = JSON.parse(JSON.stringify(state.envelope));
        }
        
        // Call backend to simulate attack
        const response = await fetch('/api/simulate-attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                attack_type: attackType,
                envelope: state.originalEnvelope
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Update envelope with attacked version
            state.envelope = data.modified_envelope;
            state.attackApplied = true;
            state.attackType = attackType;
            state.attackDetails = {
                description: data.attack_description,
                modifications: data.modifications
            };
            
            // Hide attack selection UI
            const attackSelection = document.getElementById('attack-type-selection');
            const attackActions = document.getElementById('attack-actions');
            const panelDescription = document.querySelector('.panel-description');
            
            if (attackSelection) {
                attackSelection.style.display = 'none';
            }
            if (attackActions) {
                attackActions.style.display = 'none';
            }
            if (panelDescription) {
                panelDescription.style.display = 'none';
            }
            
            // Display attack results
            displayAttackResults(data);
        } else {
            throw new Error(data.error || 'Attack simulation failed');
        }
        
    } catch (error) {
        console.error('Error applying attack:', error);
        alert('Failed to apply attack: ' + error.message);
    }
}

function displayAttackResults(data) {
    const resultDisplay = document.getElementById('attack-result-display');
    const attackDescription = document.getElementById('attack-description');
    const originalEnvelopeDisplay = document.getElementById('original-envelope-display');
    const tamperedEnvelopeDisplay = document.getElementById('tampered-envelope-display');
    const modificationsList = document.getElementById('modifications-list');
    
    if (!resultDisplay) return;
    
    // Show result display
    resultDisplay.style.display = 'block';
    
    // Set attack description
    if (attackDescription) {
        attackDescription.innerHTML = `<p>${data.attack_description}</p>`;
    }
    
    // Display original envelope
    if (originalEnvelopeDisplay) {
        const originalDisplay = {
            wrapped_key: data.original_envelope.wrapped_key.substring(0, 64) + '...',
            nonce: data.original_envelope.nonce,
            ciphertext: data.original_envelope.ciphertext.substring(0, 64) + '...',
            tag: data.original_envelope.tag,
            signature: data.original_envelope.signature.substring(0, 64) + '...'
        };
        originalEnvelopeDisplay.textContent = JSON.stringify(originalDisplay, null, 2);
    }
    
    // Display tampered envelope with highlighted changes
    if (tamperedEnvelopeDisplay) {
        const tamperedDisplay = {
            wrapped_key: data.modified_envelope.wrapped_key.substring(0, 64) + '...',
            nonce: data.modified_envelope.nonce,
            ciphertext: data.modified_envelope.ciphertext.substring(0, 64) + '...',
            tag: data.modified_envelope.tag,
            signature: data.modified_envelope.signature.substring(0, 64) + '...'
        };
        tamperedEnvelopeDisplay.textContent = JSON.stringify(tamperedDisplay, null, 2);
    }
    
    // Display modifications list
    if (modificationsList && data.modifications) {
        modificationsList.innerHTML = '<h4>Specific Modifications:</h4>';
        data.modifications.forEach(mod => {
            const modDiv = document.createElement('div');
            modDiv.className = 'modification-item';
            modDiv.innerHTML = `
                <div class="mod-header">
                    <strong>Field Modified:</strong> <code>${mod.field}</code>
                </div>
                <div class="mod-description">${mod.description}</div>
                ${mod.original !== mod.tampered ? `
                    <div class="mod-comparison">
                        <div class="mod-before">
                            <span class="mod-label">Before:</span>
                            <code>${mod.original}</code>
                        </div>
                        <div class="mod-after">
                            <span class="mod-label">After:</span>
                            <code class="tampered-value">${mod.tampered}</code>
                        </div>
                    </div>
                ` : ''}
            `;
            modificationsList.appendChild(modDiv);
        });
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
    state.originalEnvelope = null;
    state.attackApplied = false;
    state.attackType = null;
    state.attackDetails = null;
    state.originalHash = null;
    state.decryptedHash = null;
    state.decryptedContent = null;
    state.decryptedFilename = null;
    state.bindingSignatures.alice = null;
    state.bindingSignatures.bob = null;
    state.bindingVerification.alice = null;
    state.bindingVerification.bob = null;
    state.customFile = null;
    
    // Reset UI
    document.querySelectorAll('.file-item').forEach(item => {
        item.classList.remove('selected');
    });
    
    document.querySelector('input[value="alice-to-bob"]').checked = true;
    document.getElementById('custom-file-name').textContent = '';
    document.getElementById('custom-file').value = '';
    
    const downloadBtn = document.getElementById('download-decrypted-btn');
    if (downloadBtn) {
        downloadBtn.disabled = true;
    }
    
    const importInput = document.getElementById('envelope-import-input');
    if (importInput) {
        importInput.value = '';
    }
    const statusElem = document.getElementById('import-envelope-status');
    if (statusElem) {
        statusElem.textContent = 'No envelope loaded';
    }
    
    // Reset attack panel
    hideAttackPanel();
    
    updateBindingVerificationUI();
    
    // Go back to step 0
    goToStep(0);
}

// Utility Functions
function truncateKey(key) {
    if (!key) return '';
    const lines = key.split('\n').filter(line => !line.includes('---'));
    return lines.join('').substring(0, 64) + '...';
}

function truncateHash(hash, maxLength = 32) {
    if (!hash) return '';
    if (hash.length <= maxLength) return hash;
    const sideLength = Math.floor(maxLength / 2) - 2;
    return hash.substring(0, sideLength) + '...' + hash.substring(hash.length - sideLength);
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
window.toggleKeyVisibility = toggleKeyVisibility;
window.closeAttackModal = closeAttackModal;

// AES Details Modal Functions
function showAESDetailsModal() {
    const modal = document.getElementById('aes-details-modal');
    if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function closeAESDetailsModal(event) {
    const modal = document.getElementById('aes-details-modal');
    if (modal && (!event || event.target === modal || event.target.classList.contains('modal-close') || event.target.classList.contains('modal-close-btn'))) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
}

// RSA-OAEP Details Modal Functions
function showRSADetailsModal() {
    const modal = document.getElementById('rsa-details-modal');
    if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function closeRSADetailsModal(event) {
    const modal = document.getElementById('rsa-details-modal');
    if (modal && (!event || event.target === modal || event.target.classList.contains('modal-close') || event.target.classList.contains('modal-close-btn'))) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
}

// RSA-OAEP Decryption Modal Functions
function showRSADecryptModal() {
    const modal = document.getElementById('rsa-decrypt-modal');
    if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function closeRSADecryptModal(event) {
    const modal = document.getElementById('rsa-decrypt-modal');
    if (modal && (!event || event.target === modal || event.target.classList.contains('modal-close') || event.target.classList.contains('modal-close-btn'))) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
}

// AES-GCM Decryption Modal Functions
function showAESDecryptModal() {
    const modal = document.getElementById('aes-decrypt-modal');
    if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function closeAESDecryptModal(event) {
    const modal = document.getElementById('aes-decrypt-modal');
    if (modal && (!event || event.target === modal || event.target.classList.contains('modal-close') || event.target.classList.contains('modal-close-btn'))) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
}

window.showAESDetailsModal = showAESDetailsModal;
window.closeAESDetailsModal = closeAESDetailsModal;
window.showRSADetailsModal = showRSADetailsModal;
window.closeRSADetailsModal = closeRSADetailsModal;
window.showRSADecryptModal = showRSADecryptModal;
window.closeRSADecryptModal = closeRSADecryptModal;
window.showAESDecryptModal = showAESDecryptModal;
window.closeAESDecryptModal = closeAESDecryptModal;
