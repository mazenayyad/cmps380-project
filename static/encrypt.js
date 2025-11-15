// Secure Encryption Tool with Hybrid Cryptography - Multi-File Support

let selectedFiles = []; // Array of files to encrypt
let senderPrivateKey = null;
let recipientPublicKey = null;
let encryptedEnvelopes = []; // Array of encrypted envelopes
let encryptionResults = []; // Track success/failure for each file

document.addEventListener('DOMContentLoaded', () => {
    initializeEventListeners();
    setupDragAndDrop();
});

function initializeEventListeners() {
    const fileInput = document.getElementById('file-input');
    const senderKeyInput = document.getElementById('sender-key-input');
    const recipientKeyInput = document.getElementById('recipient-key-input');
    const encryptBtn = document.getElementById('encrypt-btn');
    const downloadAllBtn = document.getElementById('download-all-btn');
    const downloadIndividualBtn = document.getElementById('download-individual-btn');
    const encryptAnotherBtn = document.getElementById('encrypt-another-btn');
    const retryBtn = document.getElementById('retry-btn');

    if (fileInput) {
        fileInput.addEventListener('change', handleFileSelect);
    }

    if (senderKeyInput) {
        senderKeyInput.addEventListener('change', handleSenderKeySelect);
    }

    if (recipientKeyInput) {
        recipientKeyInput.addEventListener('change', handleRecipientKeySelect);
    }

    if (encryptBtn) {
        encryptBtn.addEventListener('click', encryptFiles);
    }

    if (downloadAllBtn) {
        downloadAllBtn.addEventListener('click', downloadAllAsZip);
    }

    if (downloadIndividualBtn) {
        downloadIndividualBtn.addEventListener('click', downloadIndividualFiles);
    }

    if (encryptAnotherBtn) {
        encryptAnotherBtn.addEventListener('click', resetTool);
    }

    if (retryBtn) {
        retryBtn.addEventListener('click', resetTool);
    }
}

function setupDragAndDrop() {
    const uploadZone = document.getElementById('upload-zone');

    uploadZone.addEventListener('click', () => {
        document.getElementById('file-input').click();
    });

    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('drag-over');
    });

    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('drag-over');
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('drag-over');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleMultipleFiles(files);
        }
    });
}

function handleFileSelect(event) {
    const files = event.target.files;
    if (files.length > 0) {
        handleMultipleFiles(files);
        event.target.value = ''; // Clear input to allow re-selecting
    }
}

function handleMultipleFiles(files) {
    // Add new files to the selected files array
    for (let i = 0; i < files.length; i++) {
        selectedFiles.push(files[i]);
    }
    displayFilesList();
    checkAllInputs();
}

function displayFilesList() {
    const uploadZone = document.getElementById('upload-zone');
    const filesListContainer = document.getElementById('files-list-container');
    const filesList = document.getElementById('files-list');
    const filesCount = document.getElementById('files-count');

    if (selectedFiles.length === 0) {
        uploadZone.style.display = 'flex';
        filesListContainer.style.display = 'none';
        return;
    }

    uploadZone.style.display = 'none';
    filesListContainer.style.display = 'block';
    filesCount.textContent = selectedFiles.length;

    // Build file list HTML
    filesList.innerHTML = selectedFiles.map((file, index) => `
        <div class="file-item" data-index="${index}">
            <span class="file-icon">📄</span>
            <div class="file-item-info">
                <span class="file-item-name">${escapeHtml(file.name)}</span>
                <span class="file-item-size">${formatFileSize(file.size)}</span>
            </div>
            <button class="file-item-remove" onclick="removeFileAt(${index})">✕</button>
        </div>
    `).join('');
}

function removeFileAt(index) {
    selectedFiles.splice(index, 1);
    displayFilesList();
    checkAllInputs();
}

function clearAllFiles() {
    selectedFiles = [];
    displayFilesList();
    checkAllInputs();
}

function handleSenderKeySelect(event) {
    const files = event.target.files;
    if (files.length > 0) {
        senderPrivateKey = files[0];
        displaySenderKeyInfo(senderPrivateKey);
        // Clear the input value to allow re-selecting the same file
        event.target.value = '';
    }
}

function handleRecipientKeySelect(event) {
    const files = event.target.files;
    if (files.length > 0) {
        recipientPublicKey = files[0];
        displayRecipientKeyInfo(recipientPublicKey);
        // Clear the input value to allow re-selecting the same file
        event.target.value = '';
    }
}

function displaySenderKeyInfo(file) {
    const keyInfo = document.getElementById('sender-key-info');
    const keyName = document.getElementById('sender-key-name');
    
    keyName.textContent = file.name;
    keyInfo.style.display = 'flex';
    
    checkAllInputs();
}

function displayRecipientKeyInfo(file) {
    const keyInfo = document.getElementById('recipient-key-info');
    const keyName = document.getElementById('recipient-key-name');
    
    keyName.textContent = file.name;
    keyInfo.style.display = 'flex';
    
    checkAllInputs();
}

function removeFile() {
    selectedFiles = [];
    document.getElementById('file-input').value = '';
    displayFilesList();
    checkAllInputs();
}

function removeSenderKey() {
    senderPrivateKey = null;
    document.getElementById('sender-key-input').value = '';
    document.getElementById('sender-key-info').style.display = 'none';
    checkAllInputs();
}

function removeRecipientKey() {
    recipientPublicKey = null;
    document.getElementById('recipient-key-input').value = '';
    document.getElementById('recipient-key-info').style.display = 'none';
    checkAllInputs();
}

function checkAllInputs() {
    const encryptBtn = document.getElementById('encrypt-btn');
    const actionHint = document.getElementById('action-hint');
    
    if (selectedFiles.length > 0 && senderPrivateKey && recipientPublicKey) {
        encryptBtn.disabled = false;
        if (selectedFiles.length === 1) {
            actionHint.textContent = 'Ready to encrypt 1 file';
        } else {
            actionHint.textContent = `Ready to encrypt ${selectedFiles.length} files`;
        }
    } else {
        encryptBtn.disabled = true;
        actionHint.textContent = 'All three inputs are required to proceed';
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function encryptFiles() {
    if (selectedFiles.length === 0 || !senderPrivateKey || !recipientPublicKey) {
        showError('Please provide all required inputs');
        return;
    }

    showSection('progress-section');
    
    // Initialize progress tracking
    const progressCurrent = document.getElementById('progress-current');
    const progressTotal = document.getElementById('progress-total');
    const filesProgressList = document.getElementById('files-progress-list');
    const batchProgressFill = document.getElementById('batch-progress-fill');
    const batchProgressText = document.getElementById('batch-progress-text');
    
    progressTotal.textContent = selectedFiles.length;
    encryptedEnvelopes = [];
    encryptionResults = [];
    
    // Create progress items for each file
    filesProgressList.innerHTML = selectedFiles.map((file, index) => `
        <div class="file-progress-item" id="progress-item-${index}">
            <span class="file-progress-icon">⏳</span>
            <div class="file-progress-info">
                <span class="file-progress-name">${escapeHtml(file.name)}</span>
                <span class="file-progress-status">Waiting...</span>
            </div>
        </div>
    `).join('');

    const startTime = Date.now();
    let successCount = 0;
    let failCount = 0;

    // Process files sequentially
    for (let i = 0; i < selectedFiles.length; i++) {
        progressCurrent.textContent = i + 1;
        
        const progressItem = document.getElementById(`progress-item-${i}`);
        const statusEl = progressItem.querySelector('.file-progress-status');
        const iconEl = progressItem.querySelector('.file-progress-icon');
        
        // Update status to processing
        progressItem.classList.add('processing');
        iconEl.textContent = '⚙️';
        statusEl.textContent = 'Encrypting...';

        try {
            const result = await encryptSingleFile(selectedFiles[i], senderPrivateKey, recipientPublicKey);
            
            // Success
            encryptedEnvelopes.push(result.envelope);
            encryptionResults.push({
                success: true,
                filename: selectedFiles[i].name,
                size: selectedFiles[i].size,
                encryptedSize: result.encrypted_size,
                time: result.encryption_time,
                hash: result.original_hash
            });
            
            progressItem.classList.remove('processing');
            progressItem.classList.add('completed');
            iconEl.textContent = '✅';
            statusEl.textContent = 'Complete';
            successCount++;
            
        } catch (error) {
            // Failure
            encryptionResults.push({
                success: false,
                filename: selectedFiles[i].name,
                error: error.message
            });
            
            progressItem.classList.remove('processing');
            progressItem.classList.add('failed');
            iconEl.textContent = '❌';
            statusEl.textContent = `Failed: ${error.message}`;
            failCount++;
        }
        
        // Update progress bar
        const progress = ((i + 1) / selectedFiles.length) * 100;
        batchProgressFill.style.width = `${progress}%`;
        batchProgressText.textContent = `${Math.round(progress)}%`;
    }

    const totalTime = (Date.now() - startTime) / 1000;

    // Show results
    await sleep(500);
    showEncryptionResults(successCount, failCount, totalTime);
}

async function encryptSingleFile(file, senderKey, recipientKey) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('senderPrivateKey', senderKey);
    formData.append('recipientPublicKey', recipientKey);

    const response = await fetch('/api/standalone-encrypt', {
        method: 'POST',
        body: formData
    });

    const result = await response.json();

    if (!result.success) {
        throw new Error(result.error || 'Encryption failed');
    }

    return result;
}

function showEncryptionResults(successCount, failCount, totalTime) {
    const successCountEl = document.getElementById('success-count');
    const totalFilesEl = document.getElementById('total-files');
    const successfulCountEl = document.getElementById('successful-count');
    const failedCountEl = document.getElementById('failed-count');
    const totalTimeEl = document.getElementById('total-time');
    const totalSizeEl = document.getElementById('total-size');
    const recipientNameEl = document.getElementById('recipient-name');
    const resultsListEl = document.getElementById('results-list');

    successCountEl.textContent = successCount;
    totalFilesEl.textContent = selectedFiles.length;
    successfulCountEl.textContent = successCount;
    failedCountEl.textContent = failCount;
    totalTimeEl.textContent = totalTime.toFixed(2) + ' sec';
    
    // Calculate total size
    const totalSize = encryptionResults
        .filter(r => r.success)
        .reduce((sum, r) => sum + r.size, 0);
    totalSizeEl.textContent = formatFileSize(totalSize);

    // Get recipient name from first successful envelope
    const firstSuccess = encryptedEnvelopes[0];
    recipientNameEl.textContent = firstSuccess ? (firstSuccess.recipient || 'Unknown') : 'N/A';

    // Build results list
    resultsListEl.innerHTML = '<h4>📋 Individual File Results</h4>' + 
        encryptionResults.map((result, index) => {
            if (result.success) {
                return `
                    <div class="result-item success">
                        <span class="result-icon">✅</span>
                        <div class="result-info">
                            <strong>${escapeHtml(result.filename)}</strong>
                            <span>${formatFileSize(result.size)} → ${formatFileSize(result.encryptedSize)} (${(result.time * 1000).toFixed(2)} ms)</span>
                        </div>
                    </div>
                `;
            } else {
                return `
                    <div class="result-item failed">
                        <span class="result-icon">❌</span>
                        <div class="result-info">
                            <strong>${escapeHtml(result.filename)}</strong>
                            <span class="error-text">${escapeHtml(result.error)}</span>
                        </div>
                    </div>
                `;
            }
        }).join('');

    showSection('result-section');
}

async function downloadAllAsZip() {
    if (encryptedEnvelopes.length === 0) {
        alert('No encrypted envelopes available to download');
        return;
    }

    // Use JSZip library if available, otherwise download individually
    if (typeof JSZip !== 'undefined') {
        const zip = new JSZip();
        
        encryptedEnvelopes.forEach((envelope, index) => {
            const json = JSON.stringify(envelope, null, 2);
            zip.file(`encrypted_${envelope.filename}.json`, json);
        });
        
        const blob = await zip.generateAsync({ type: 'blob' });
        downloadBlob(blob, 'encrypted_files.zip');
    } else {
        // Fallback: download individually
        downloadIndividualFiles();
    }
}

function downloadIndividualFiles() {
    if (encryptedEnvelopes.length === 0) {
        alert('No encrypted envelopes available to download');
        return;
    }

    encryptedEnvelopes.forEach((envelope, index) => {
        setTimeout(() => {
            const json = JSON.stringify(envelope, null, 2);
            const blob = new Blob([json], { type: 'application/json' });
            downloadBlob(blob, `encrypted_${envelope.filename}.json`);
        }, index * 200); // Stagger downloads
    });
}

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function downloadEnvelope() {
    if (!encryptedEnvelope) {
        alert('No envelope available to download');
        return;
    }

    const json = JSON.stringify(encryptedEnvelope, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `encrypted_${encryptedEnvelope.filename}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function showError(message) {
    document.getElementById('error-message').textContent = message;
    showSection('error-section');
}

function showSection(sectionId) {
    // Hide all sections
    const sections = document.querySelectorAll('.tool-section');
    sections.forEach(section => {
        section.style.display = 'none';
    });

    // Show target section
    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.style.display = 'block';
    }
}

function resetTool() {
    selectedFiles = [];
    senderPrivateKey = null;
    recipientPublicKey = null;
    encryptedEnvelopes = [];
    encryptionResults = [];
    
    // Reset file input
    document.getElementById('file-input').value = '';
    displayFilesList();
    
    // Reset key inputs
    document.getElementById('sender-key-input').value = '';
    document.getElementById('sender-key-info').style.display = 'none';
    document.getElementById('recipient-key-input').value = '';
    document.getElementById('recipient-key-info').style.display = 'none';
    
    checkAllInputs();
    showSection('upload-section');
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
