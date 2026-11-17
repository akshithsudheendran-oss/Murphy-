// scan.js - Handles AJAX scanning and progress tracking on the dashboard

document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const targetUrlInput = document.getElementById('targetUrl');
    const startScanBtn = document.getElementById('startScanBtn');
    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progressBar');
    const statusText = document.getElementById('statusText');
    const scanLogs = document.getElementById('scanLogs');
    
    let pollInterval;

    if (scanForm) {
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const url = targetUrlInput.value.trim();
            if (!url) return;

            // UI Reset
            scanForm.style.display = 'none';
            progressContainer.classList.remove('hidden');
            progressBar.style.width = '10%';
            statusText.innerText = 'Initializing scan parameters...';
            addLog(`Target locked: ${url}`);

            try {
                // Step 1: Trigger the scan backend via API
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ targetUrl: url })
                });

                const data = await response.json();
                
                if (data.status === 'success') {
                    const scanId = data.scan_id;
                    addLog('Scan initiated successfully. Modules starting...');
                    progressBar.style.width = '25%';
                    
                    // Step 2: Poll for progress every 2 seconds
                    pollInterval = setInterval(() => pollStatus(scanId), 2000);
                } else {
                    handleError(data.message || 'Failed to start scan.');
                }
            } catch (error) {
                handleError('Server connection failed.');
            }
        });
    }

    // Function to check scan progress
    async function pollStatus(scanId) {
        try {
            const response = await fetch(`/api/scan-status/${scanId}`);
            const data = await response.json();

            // Update progress UI based on backend status
            if (data.status === 'running') {
                progressBar.style.width = data.progress + '%';
                statusText.innerText = `Running module: ${data.current_module}...`;
                addLog(`Executing: ${data.current_module}`);
            } else if (data.status === 'completed') {
                clearInterval(pollInterval);
                progressBar.style.width = '100%';
                statusText.innerText = 'Scan Complete!';
                addLog('All modules finished. Redirecting to results...');
                
                // Wait briefly for UX, then redirect to results page
                setTimeout(() => {
                    window.location.href = `/results/${scanId}`;
                }, 1500);
            } else if (data.status === 'failed') {
                clearInterval(pollInterval);
                handleError('Scan failed during execution.');
            }
        } catch (error) {
            clearInterval(pollInterval);
            handleError('Lost connection to backend while polling status.');
        }
    }

    function addLog(msg) {
        const li = document.createElement('li');
        li.innerText = `> ${msg}`;
        scanLogs.appendChild(li);
    }

    function handleError(msg) {
        statusText.innerText = 'Error!';
        statusText.style.color = 'var(--crit-color)';
        progressBar.style.backgroundColor = 'var(--crit-color)';
        addLog(`ERROR: ${msg}`);
        
        // Show form again after delay
        setTimeout(() => {
            progressContainer.classList.add('hidden');
            scanForm.style.display = 'block';
        }, 4000);
    }
});