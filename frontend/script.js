// script.js
// This script handles the frontend UI and communicates with the Flask backend.

// --- Dynamic Background Animation ---
const canvas = document.getElementById('bg-canvas');
const ctx = canvas.getContext('2d');
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;
const alphabet = 'アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズブプエェケセテネヘメレヱゲゼデベペオォコソトノホモヨョロヲゴゾドボポヴッンABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const fontSize = 16;
const columns = canvas.width / fontSize;
const rainDrops = [];

// Initialize rain drops with different speeds and positions
for (let x = 0; x < columns; x++) {
    rainDrops[x] = {
        y: Math.random() * canvas.height,
        speed: Math.random() * 3 + 1.5, 
    };
}

const draw = () => {
    ctx.fillStyle = 'rgba(10, 10, 15, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#6366f1';
    ctx.font = fontSize + 'px monospace';
    for (let i = 0; i < rainDrops.length; i++) {
        const drop = rainDrops[i];
        const text = alphabet.charAt(Math.floor(Math.random() * alphabet.length));
        ctx.fillText(text, i * fontSize, drop.y * fontSize);

        drop.y += drop.speed / fontSize;
        if (drop.y * fontSize > canvas.height && Math.random() > 0.98) {
            drop.y = 0;
        }
    }
};
setInterval(draw, 33);
window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});
// --- End of Background Code ---


// --- UI Logic with Animated Tabs ---
const embedTabBtn = document.getElementById('embed-tab-btn');
const extractTabBtn = document.getElementById('extract-tab-btn');
const tabGlider = document.getElementById('tab-glider');
const embedSection = document.getElementById('embed-section');
const extractSection = document.getElementById('extract-section');
const statusText = document.getElementById('status-text');
const downloadArea = document.getElementById('download-area');
const extractedTextArea = document.getElementById('extracted-text-area');
const extractedTextOutput = document.getElementById('extracted-text-output');
const glassCard = document.querySelector('.glass-card');

function moveGlider(target) {
    if (tabGlider && target) {
        tabGlider.style.width = `${target.offsetWidth}px`;
        tabGlider.style.transform = `translateX(${target.offsetLeft}px)`;
    }
}

function switchTab(activeTab) { 
    let activeBtn;
    if (activeTab === 'embed') {
        activeBtn = embedTabBtn;
        embedTabBtn.classList.add('active');
        extractTabBtn.classList.remove('active');
        embedSection.classList.remove('hidden');
        extractSection.classList.add('hidden');
    } else {
        activeBtn = extractTabBtn;
        extractTabBtn.classList.add('active');
        embedTabBtn.classList.remove('active');
        extractSection.classList.remove('hidden');
        embedSection.classList.add('hidden');
    }
    moveGlider(activeBtn);
    statusText.textContent = '';
    downloadArea.innerHTML = '';
    if (extractedTextArea) extractedTextArea.classList.add('hidden');
}

// Initialize glider position on page load
document.addEventListener('DOMContentLoaded', () => {
    if(embedTabBtn) {
        moveGlider(embedTabBtn);
    }
});

if(embedTabBtn) embedTabBtn.addEventListener('click', () => switchTab('embed'));
if(extractTabBtn) extractTabBtn.addEventListener('click', () => switchTab('extract'));

document.getElementById('embed-cover-file').addEventListener('change', (e) => { document.getElementById('embed-cover-file-name').textContent = e.target.files[0]?.name || 'Click to upload Image, Audio, Video, etc.'; });
document.getElementById('embed-secret-file').addEventListener('change', (e) => { document.getElementById('embed-secret-file-name').textContent = e.target.files[0]?.name || 'Upload Secret File'; });
document.getElementById('extract-stego-file').addEventListener('change', (e) => { document.getElementById('extract-stego-file-name').textContent = e.target.files[0]?.name || 'Click to upload the file with hidden data'; });
// --- End of UI Logic ---


// --- Backend Communication Logic ---

async function handleApiError(response) {
    const contentType = response.headers.get("content-type");
    let errorMessage;
    if (contentType && contentType.indexOf("application/json") !== -1) {
        const errorData = await response.json();
        errorMessage = errorData.error || `Server error: ${response.status}`;
    } else {
        errorMessage = `Failed to connect to the backend API. Please ensure the server is running correctly. (Status: ${response.status})`;
    }
    throw new Error(errorMessage);
}


document.getElementById('embed-btn').addEventListener('click', async () => {
    const coverFile = document.getElementById('embed-cover-file').files[0];
    const secretFile = document.getElementById('embed-secret-file').files[0];
    const secretText = document.getElementById('embed-secret-text').value;
    const password = document.getElementById('embed-password').value;

    if (!coverFile || (!secretFile && !secretText) || !password) {
        statusText.textContent = "Error: Cover file, secret data, and password are required.";
        return;
    }

    statusText.textContent = "Uploading and processing on server...";
    downloadArea.innerHTML = '';
    if (extractedTextArea) extractedTextArea.classList.add('hidden');

    const formData = new FormData();
    formData.append('coverFile', coverFile);
    formData.append('password', password);
    formData.append('message', secretText); // Always send the message (can be empty)

    if (secretFile) {
        formData.append('secretFile', secretFile);
    } else {
        const secretBlob = new Blob([secretText], { type: 'text/plain' });
        formData.append('secretFile', secretBlob, 'message.txt');
    }

    try {
        const response = await fetch('/api/embed', {
            method: 'POST',
            body: formData,
        });

        if (!response.ok) {
            await handleApiError(response);
        }

        const blob = await response.blob();
        const contentDisposition = response.headers.get('Content-Disposition');
        let filename = 'stego_file';
        if (contentDisposition) {
            const filenameMatch = contentDisposition.match(/filename="?(.+?)"?$/);
            if (filenameMatch && filenameMatch.length > 1) {
                filename = filenameMatch[1];
            }
        }
        createDownloadLink(blob, filename);
        statusText.textContent = "Embedding complete!";

    } catch (error) {
        statusText.textContent = `Error: ${error.message}`;
        console.error(error);
    }
});


document.getElementById('extract-btn').addEventListener('click', async () => {
    const stegoFile = document.getElementById('extract-stego-file').files[0];
    const password = document.getElementById('extract-password').value;

    if (!stegoFile || !password) {
        statusText.textContent = "Error: Stego file and password are required.";
        return;
    }

    statusText.textContent = "Uploading and processing on server...";
    downloadArea.innerHTML = '';
    if (extractedTextArea) extractedTextArea.classList.add('hidden');

    const formData = new FormData();
    formData.append('stegoFile', stegoFile);
    formData.append('password', password);

    try {
        const response = await fetch('/api/extract', {
            method: 'POST',
            body: formData,
        });

        if (!response.ok) {
            await handleApiError(response);
        }

        const data = await response.json();
        // data: { message, filename, download_url }
        if (data.message && extractedTextOutput && extractedTextArea) {
            extractedTextOutput.value = data.message;
            extractedTextArea.classList.remove('hidden');
        }
        if (data.download_url && data.filename) {
            // Fetch the file as a blob for download
            const fileResponse = await fetch(data.download_url);
            if (!fileResponse.ok) throw new Error('Failed to fetch extracted file.');
            const fileBlob = await fileResponse.blob();
            createDownloadLink(fileBlob, data.filename);
        }
        statusText.textContent = "Extraction successful!";
    } catch (error) {
        statusText.textContent = `Error: ${error.message}`;
        console.error(error);
    }
});


function createDownloadLink(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.textContent = `Download ${filename}`;
    a.className = "bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-lg inline-block";
    downloadArea.innerHTML = '';
    downloadArea.appendChild(a);
}

function togglePasswordVisibility(passwordId, iconId) {
    const passwordInput = document.getElementById(passwordId);
    const toggleIcon = document.getElementById(iconId);
    if (!passwordInput || !toggleIcon) return;
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleIcon.classList.remove('fa-eye');
        toggleIcon.classList.add('fa-eye-slash');
    } else {
        passwordInput.type = 'password';
        toggleIcon.classList.remove('fa-eye-slash');
        toggleIcon.classList.add('fa-eye');
    }
}
