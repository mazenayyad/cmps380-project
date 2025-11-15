// Key Generation Tool JavaScript

document.addEventListener('DOMContentLoaded', () => {
    const generateBtn = document.getElementById('generateBtn');
    const generateAnotherBtn = document.getElementById('generateAnotherBtn');
    const userNameInput = document.getElementById('userName');
    const resultsSection = document.getElementById('resultsSection');
    const publicKeyDisplay = document.getElementById('publicKeyDisplay');
    const privateKeyDisplay = document.getElementById('privateKeyDisplay');
    
    // Copy buttons
    const copyPublicBtn = document.getElementById('copyPublicBtn');
    const copyPrivateBtn = document.getElementById('copyPrivateBtn');
    
    // Download buttons
    const downloadPublicBtn = document.getElementById('downloadPublicBtn');
    const downloadPrivateBtn = document.getElementById('downloadPrivateBtn');

    let currentUserName = '';

    // Generate Keypair
    generateBtn.addEventListener('click', async () => {
        const userName = userNameInput.value.trim();
        
        if (!userName) {
            alert('Please enter your name or identifier');
            return;
        }

        currentUserName = userName;
        generateBtn.disabled = true;
        generateBtn.innerHTML = '<span class="btn-icon">⏳</span>Generating...';

        try {
            const response = await fetch('/api/generate-keypair', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ user: userName })
            });

            const data = await response.json();

            if (data.success) {
                // Display keys
                publicKeyDisplay.value = data.publicKey;
                privateKeyDisplay.value = data.privateKey;
                
                // Show results
                resultsSection.style.display = 'block';
                resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                
                // Reset button
                generateBtn.disabled = false;
                generateBtn.innerHTML = '<span class="btn-icon">🔑</span>Generate Keypair';
            } else {
                throw new Error(data.error || 'Failed to generate keypair');
            }
        } catch (error) {
            console.error('Error generating keypair:', error);
            alert('Error generating keypair: ' + error.message);
            generateBtn.disabled = false;
            generateBtn.innerHTML = '<span class="btn-icon">🔑</span>Generate Keypair';
        }
    });

    // Generate Another Keypair
    generateAnotherBtn.addEventListener('click', () => {
        userNameInput.value = '';
        publicKeyDisplay.value = '';
        privateKeyDisplay.value = '';
        resultsSection.style.display = 'none';
        userNameInput.focus();
    });

    // Copy Public Key
    copyPublicBtn.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(publicKeyDisplay.value);
            const originalText = copyPublicBtn.innerHTML;
            copyPublicBtn.innerHTML = '<span class="btn-icon">✅</span>Copied!';
            setTimeout(() => {
                copyPublicBtn.innerHTML = originalText;
            }, 2000);
        } catch (error) {
            console.error('Failed to copy:', error);
            alert('Failed to copy to clipboard');
        }
    });

    // Copy Private Key
    copyPrivateBtn.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(privateKeyDisplay.value);
            const originalText = copyPrivateBtn.innerHTML;
            copyPrivateBtn.innerHTML = '<span class="btn-icon">✅</span>Copied!';
            setTimeout(() => {
                copyPrivateBtn.innerHTML = originalText;
            }, 2000);
        } catch (error) {
            console.error('Failed to copy:', error);
            alert('Failed to copy to clipboard');
        }
    });

    // Download Public Key
    downloadPublicBtn.addEventListener('click', () => {
        downloadKey(publicKeyDisplay.value, `${currentUserName}_public_key.pem`);
    });

    // Download Private Key
    downloadPrivateBtn.addEventListener('click', () => {
        downloadKey(privateKeyDisplay.value, `${currentUserName}_private_key.pem`);
    });

    // Helper function to download keys
    function downloadKey(content, filename) {
        const blob = new Blob([content], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    }

    // Allow Enter key to generate
    userNameInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            generateBtn.click();
        }
    });
});
