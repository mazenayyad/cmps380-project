// Secure Decryption Tool with Hybrid Cryptography - Multi-File Support

let selectedEnvelopes = []; // Array of envelope files
let envelopesData = []; // Array of parsed envelope data
let recipientPrivateKey = null;
let decryptedFiles = []; // Array of decrypted file data
let decryptionResults = []; // Track success/failure for each file

document.addEventListener('DOMContentLoaded', () => {
    initializeEventListeners();
    setupDragAndDrop();
});

function initializeEventListeners() {
    const envelopeInput = document.getElementById('envelope-input');
    const recipientKeyInput = document.getElementById('recipient-key-input');
    const decryptBtn = document.getElementById('decrypt-btn');
    const downloadAllBtn = document.getElementById('download-all-btn');
    const downloadIndividualBtn = document.getElementById('download-individual-btn');
    const decryptAnotherBtn = document.getElementById('decrypt-another-btn');
    const retryBtn = document.getElementById('retry-btn');

    if (envelopeInput) {
        envelopeInput.addEventListener('change', handleEnvelopeSelect);
    }

    if (recipientKeyInput) {
        recipientKeyInput.addEventListener('change', handleRecipientKeySelect);
    }

    if (decryptBtn) {
        decryptBtn.addEventListener('click', decryptFiles);
    }

    if (downloadAllBtn) {
        downloadAllBtn.addEventListener('click', downloadAllAsZip);
    }

    if (downloadIndividualBtn) {
        downloadIndividualBtn.addEventListener('click', downloadIndividualFiles);
    }

    if (decryptAnotherBtn) {
        decryptAnotherBtn.addEventListener('click', resetTool);
    }

    if (retryBtn) {
        retryBtn.addEventListener('click', resetTool);
    }
}

function setupDragAndDrop() {
    const uploadZone = document.getElementById('upload-zone');

    uploadZone.addEventListener('click', () => {
        document.getElementById('envelope-input').click();
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
            handleMultipleEnvelopes(files);
        }
    });
}

function handleEnvelopeSelect(event) {
    const files = event.target.files;
    if (files.length > 0) {
        handleMultipleEnvelopes(files);
        event.target.value = ''; // Clear input
    }
}

async function handleMultipleEnvelopes(files) {
    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        try {
            const envelope = await loadEnvelopeFile(file);
            selectedEnvelopes.push(file);
            envelopesData.push(envelope);
        } catch (error) {
            console.error(`Failed to load ${file.name}:`, error.message);
            // Continue loading other files even if one fails
        }
    }
    displayEnvelopesList();
    checkAllInputs();
}

function loadEnvelopeFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        
        reader.onload = function(e) {
            try {
                const envelope = JSON.parse(e.target.result);
                
                // Validate envelope structure
                if (!envelope.ciphertext || !envelope.nonce || !envelope.tag) {
                    throw new Error('Invalid envelope structure');
                }

                resolve(envelope);
            } catch (error) {
                reject(error);
            }
        };

        reader.onerror = function() {
            reject(new Error('Failed to read file'));
        };

        reader.readAsText(file);
    });
}

function displayEnvelopesList() {
    const uploadZone = document.getElementById('upload-zone');
    const envelopesListContainer = document.getElementById('envelopes-list-container');
    const envelopesList = document.getElementById('envelopes-list');
    const envelopesCount = document.getElementById('envelopes-count');

    if (envelopesData.length === 0) {
        uploadZone.style.display = 'flex';
        envelopesListContainer.style.display = 'none';
        return;
    }

    uploadZone.style.display = 'none';
    envelopesListContainer.style.display = 'block';
    envelopesCount.textContent = envelopesData.length;

    // Build envelope list HTML
    envelopesList.innerHTML = envelopesData.map((envelope, index) => `
        <div class="file-item" data-index="${index}">
            <span class="file-icon">📦</span>
            <div class="file-item-info">
                <span class="file-item-name">${escapeHtml(envelope.filename || 'Unknown')}</span>
                <span class="file-item-size">${formatFileSize(envelope.size || 0)}</span>
            </div>
            <button class="file-item-remove" onclick="removeEnvelopeAt(${index})">✕</button>
        </div>
    `).join('');
}

function removeEnvelopeAt(index) {
    selectedEnvelopes.splice(index, 1);
    envelopesData.splice(index, 1);
    displayEnvelopesList();
    checkAllInputs();
}

function clearAllEnvelopes() {
    selectedEnvelopes = [];
    envelopesData = [];
    displayEnvelopesList();
    checkAllInputs();
}

function handleRecipientKeySelect(event) {
    const files = event.target.files;
    if (files.length > 0) {
        recipientPrivateKey = files[0];
        displayRecipientKeyInfo(recipientPrivateKey);
        event.target.value = '';
    }
}

function displayRecipientKeyInfo(file) {
    const keyInfo = document.getElementById('recipient-key-info');
    const keyName = document.getElementById('recipient-key-name');
    
    keyName.textContent = file.name;
    keyInfo.style.display = 'flex';
    
    checkAllInputs();
}

function removeEnvelope() {
    selectedEnvelopes = [];
    envelopesData = [];
    displayEnvelopesList();
    checkAllInputs();
}

function removeRecipientKey() {
    recipientPrivateKey = null;
    document.getElementById('recipient-key-input').value = '';
    document.getElementById('recipient-key-info').style.display = 'none';
    checkAllInputs();
}

function checkAllInputs() {
    const decryptBtn = document.getElementById('decrypt-btn');
    const actionHint = document.getElementById('action-hint');
    
    if (envelopesData.length > 0 && recipientPrivateKey) {
        decryptBtn.disabled = false;
        if (envelopesData.length === 1) {
            actionHint.textContent = 'Ready to decrypt 1 file';
        } else {
            actionHint.textContent = `Ready to decrypt ${envelopesData.length} files`;
        }
    } else {
        decryptBtn.disabled = true;
        actionHint.textContent = 'Both inputs are required to proceed';
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

async function decryptFiles() {
    if (envelopesData.length === 0 || !recipientPrivateKey) {
        showError('Please provide both envelope and private key');
        return;
    }

    showSection('progress-section');
    
    // Initialize progress tracking
    const progressCurrent = document.getElementById('progress-current');
    const progressTotal = document.getElementById('progress-total');
    const filesProgressList = document.getElementById('files-progress-list');
    const batchProgressFill = document.getElementById('batch-progress-fill');
    const batchProgressText = document.getElementById('batch-progress-text');
    
    progressTotal.textContent = envelopesData.length;
    decryptedFiles = [];
    decryptionResults = [];
    
    // Create progress items for each file
    filesProgressList.innerHTML = envelopesData.map((envelope, index) => `
        <div class="file-progress-item" id="progress-item-${index}">
            <span class="file-progress-icon">⏳</span>
            <div class="file-progress-info">
                <span class="file-progress-name">${escapeHtml(envelope.filename || 'Unknown')}</span>
                <span class="file-progress-status">Waiting...</span>
            </div>
        </div>
    `).join('');

    const startTime = Date.now();
    let successCount = 0;
    let failCount = 0;

    // Process files sequentially
    for (let i = 0; i < envelopesData.length; i++) {
        progressCurrent.textContent = i + 1;
        
        const progressItem = document.getElementById(`progress-item-${i}`);
        const statusEl = progressItem.querySelector('.file-progress-status');
        const iconEl = progressItem.querySelector('.file-progress-icon');
        
        // Update status to processing
        progressItem.classList.add('processing');
        iconEl.textContent = '⚙️';
        statusEl.textContent = 'Decrypting...';

        try {
            const result = await decryptSingleFile(envelopesData[i], recipientPrivateKey);
            
            // Success
            decryptedFiles.push({
                content: result.content,
                filename: result.filename
            });
            decryptionResults.push({
                success: true,
                filename: result.filename,
                size: result.size,
                time: result.decryption_time,
                hash: result.decrypted_hash
            });
            
            progressItem.classList.remove('processing');
            progressItem.classList.add('completed');
            iconEl.textContent = '✅';
            statusEl.textContent = 'Complete';
            successCount++;
            
        } catch (error) {
            // Failure
            decryptionResults.push({
                success: false,
                filename: envelopesData[i].filename || 'Unknown',
                error: error.message
            });
            
            progressItem.classList.remove('processing');
            progressItem.classList.add('failed');
            iconEl.textContent = '❌';
            statusEl.textContent = `Failed: ${error.message}`;
            failCount++;
        }
        
        // Update progress bar
        const progress = ((i + 1) / envelopesData.length) * 100;
        batchProgressFill.style.width = `${progress}%`;
        batchProgressText.textContent = `${Math.round(progress)}%`;
    }

    const totalTime = (Date.now() - startTime) / 1000;

    // Show results
    await sleep(500);
    showDecryptionResults(successCount, failCount, totalTime);
}

async function decryptSingleFile(envelope, recipientKey) {
    const formData = new FormData();
    formData.append('envelope', JSON.stringify(envelope));
    formData.append('recipientPrivateKey', recipientKey);

    const response = await fetch('/api/standalone-decrypt', {
        method: 'POST',
        body: formData
    });

    const result = await response.json();

    if (!result.success) {
        throw new Error(result.error || 'Decryption failed');
    }

    return result;
}

function showDecryptionResults(successCount, failCount, totalTime) {
    const successCountEl = document.getElementById('success-count');
    const totalFilesEl = document.getElementById('total-files');
    const successfulCountEl = document.getElementById('successful-count');
    const failedCountEl = document.getElementById('failed-count');
    const totalTimeEl = document.getElementById('total-time');
    const totalSizeEl = document.getElementById('total-size');
    const resultsListEl = document.getElementById('results-list');

    successCountEl.textContent = successCount;
    totalFilesEl.textContent = envelopesData.length;
    successfulCountEl.textContent = successCount;
    failedCountEl.textContent = failCount;
    totalTimeEl.textContent = totalTime.toFixed(2) + ' sec';
    
    // Calculate total size
    const totalSize = decryptionResults
        .filter(r => r.success)
        .reduce((sum, r) => sum + r.size, 0);
    totalSizeEl.textContent = formatFileSize(totalSize);

    // Build results list
    resultsListEl.innerHTML = '<h4>📋 Individual File Results</h4>' + 
        decryptionResults.map((result, index) => {
            if (result.success) {
                return `
                    <div class="result-item success">
                        <span class="result-icon">✅</span>
                        <div class="result-info">
                            <strong>${escapeHtml(result.filename)}</strong>
                            <span>${formatFileSize(result.size)} (${(result.time * 1000).toFixed(2)} ms)</span>
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
    if (decryptedFiles.length === 0) {
        alert('No decrypted files available to download');
        return;
    }

    // Use JSZip library if available, otherwise download individually
    if (typeof JSZip !== 'undefined') {
        const zip = new JSZip();
        
        decryptedFiles.forEach((file, index) => {
            const binaryString = atob(file.content);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            zip.file(file.filename, bytes);
        });
        
        const blob = await zip.generateAsync({ type: 'blob' });
        downloadBlob(blob, 'decrypted_files.zip');
    } else {
        // Fallback: download individually
        downloadIndividualFiles();
    }
}

function downloadIndividualFiles() {
    if (decryptedFiles.length === 0) {
        alert('No decrypted files available to download');
        return;
    }

    decryptedFiles.forEach((file, index) => {
        setTimeout(() => {
            const binaryString = atob(file.content);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            
            const blob = new Blob([bytes]);
            downloadBlob(blob, file.filename);
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

function downloadDecryptedFile() {
    if (!decryptedFileData || !decryptedFileData.content || !decryptedFileData.filename) {
        alert('No decrypted file available to download');
        return;
    }

    // Decode base64 content
    const binaryString = atob(decryptedFileData.content);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    
    const blob = new Blob([bytes]);
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = decryptedFileData.filename;
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
    selectedEnvelopes = [];
    envelopesData = [];
    recipientPrivateKey = null;
    decryptedFiles = [];
    decryptionResults = [];
    
    // Reset envelope input
    document.getElementById('envelope-input').value = '';
    displayEnvelopesList();
    
    // Reset key input
    document.getElementById('recipient-key-input').value = '';
    document.getElementById('recipient-key-info').style.display = 'none';
    
    checkAllInputs();
    showSection('upload-section');
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
