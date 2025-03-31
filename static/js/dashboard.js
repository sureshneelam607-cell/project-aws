/**
 * Dashboard JavaScript for NaptProxy
 * Handles chart creation and updates for the dashboard
 */

// Charts for the dashboard
let requestMethodsChart = null;
let responseCodesChart = null;
let vulnerabilitiesChart = null;

/**
 * Initialize charts with empty data
 */
function initializeCharts() {
    // Request Methods Chart
    const requestMethodsCtx = document.getElementById('request-methods-chart').getContext('2d');
    requestMethodsChart = new Chart(requestMethodsCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Request Methods',
                data: [],
                backgroundColor: [
                    'rgba(75, 192, 192, 0.5)',  // GET
                    'rgba(54, 162, 235, 0.5)',  // POST
                    'rgba(153, 102, 255, 0.5)', // PUT
                    'rgba(255, 99, 132, 0.5)',  // DELETE
                    'rgba(255, 159, 64, 0.5)',  // HEAD
                    'rgba(255, 205, 86, 0.5)',  // OPTIONS
                    'rgba(201, 203, 207, 0.5)'  // Other
                ],
                borderColor: [
                    'rgb(75, 192, 192)',
                    'rgb(54, 162, 235)',
                    'rgb(153, 102, 255)',
                    'rgb(255, 99, 132)',
                    'rgb(255, 159, 64)',
                    'rgb(255, 205, 86)',
                    'rgb(201, 203, 207)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });

    // Response Codes Chart
    const responseCodesCtx = document.getElementById('response-codes-chart').getContext('2d');
    responseCodesChart = new Chart(responseCodesCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                label: 'Response Codes',
                data: [],
                backgroundColor: [
                    'rgba(75, 192, 192, 0.5)',  // 2xx
                    'rgba(54, 162, 235, 0.5)',  // 3xx
                    'rgba(255, 205, 86, 0.5)',  // 4xx
                    'rgba(255, 99, 132, 0.5)',  // 5xx
                    'rgba(201, 203, 207, 0.5)'  // Other
                ],
                borderColor: [
                    'rgb(75, 192, 192)',
                    'rgb(54, 162, 235)',
                    'rgb(255, 205, 86)',
                    'rgb(255, 99, 132)',
                    'rgb(201, 203, 207)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    });

    // Vulnerabilities Chart
    const vulnerabilitiesCtx = document.getElementById('vulnerabilities-chart').getContext('2d');
    vulnerabilitiesChart = new Chart(vulnerabilitiesCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Detected Vulnerabilities',
                data: [],
                backgroundColor: 'rgba(255, 99, 132, 0.5)',
                borderColor: 'rgb(255, 99, 132)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Update charts with new data
 * @param {Object} data - Traffic statistics
 */
function updateCharts(data) {
    // Update Request Methods Chart
    if (data.request_methods && requestMethodsChart) {
        const methods = Object.keys(data.request_methods);
        const counts = methods.map(method => data.request_methods[method]);
        
        requestMethodsChart.data.labels = methods;
        requestMethodsChart.data.datasets[0].data = counts;
        requestMethodsChart.update();
    }
    
    // Update Response Codes Chart
    if (data.response_codes && responseCodesChart) {
        const codes = Object.keys(data.response_codes);
        const counts = codes.map(code => data.response_codes[code]);
        
        // Group response codes by their first digit
        const groupedCodes = {};
        const groupedLabels = [];
        
        codes.forEach((code, index) => {
            const firstDigit = code.charAt(0);
            const group = `${firstDigit}xx`;
            
            if (!groupedCodes[group]) {
                groupedCodes[group] = 0;
                groupedLabels.push(group);
            }
            
            groupedCodes[group] += counts[index];
        });
        
        const groupedCounts = groupedLabels.map(label => groupedCodes[label]);
        
        responseCodesChart.data.labels = groupedLabels;
        responseCodesChart.data.datasets[0].data = groupedCounts;
        responseCodesChart.update();
    }
    
    // Update Vulnerabilities Chart
    if (data.vulnerability_patterns && vulnerabilitiesChart) {
        const vulnerabilities = Object.keys(data.vulnerability_patterns);
        const counts = vulnerabilities.map(vuln => data.vulnerability_patterns[vuln]);
        
        // Format vulnerability names for display
        const formattedLabels = vulnerabilities.map(formatVulnerabilityName);
        
        vulnerabilitiesChart.data.labels = formattedLabels;
        vulnerabilitiesChart.data.datasets[0].data = counts;
        vulnerabilitiesChart.update();
    }
}

/**
 * Format vulnerability name for display
 * @param {string} vulnType - Vulnerability type
 * @returns {string} Formatted vulnerability name
 */
function formatVulnerabilityName(vulnType) {
    const names = {
        'sql_injection': 'SQL Injection',
        'xss': 'Cross-Site Scripting',
        'path_traversal': 'Path Traversal',
        'command_injection': 'Command Injection',
        'lfi_rfi': 'File Inclusion',
        'scanner_signatures': 'Scanner Signatures',
        'nosql_injection': 'NoSQL Injection'
    };
    
    return names[vulnType] || vulnType;
}

/**
 * Format bytes to human-readable format
 * @param {number} bytes - Number of bytes
 * @returns {string} Formatted size
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    
    return parseFloat((bytes / Math.pow(1024, i)).toFixed(2)) + ' ' + units[i];
}

/**
 * Format duration in seconds to human-readable format
 * @param {number} seconds - Duration in seconds
 * @returns {string} Formatted duration
 */
function formatDuration(seconds) {
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor((seconds % (3600 * 24)) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    
    if (d > 0) {
        return `${d}d ${h}h ${m}m ${s}s`;
    } else if (h > 0) {
        return `${h}h ${m}m ${s}s`;
    } else if (m > 0) {
        return `${m}m ${s}s`;
    } else {
        return `${s}s`;
    }
}

/**
 * Initialize the dashboard
 */
function initDashboard() {
    // Initialize charts if they don't exist
    if (!requestMethodsChart || !responseCodesChart || !vulnerabilitiesChart) {
        initializeCharts();
    }
    
    // Fetch and update data
    fetchDashboardData();
}

/**
 * Fetch dashboard data from API
 */
function fetchDashboardData() {
    // Show loading state
    // You could add loading indicators here
    
    // Fetch proxy status
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            updateProxyStatus(data);
        })
        .catch(error => console.error('Error fetching proxy status:', error));
    
    // Fetch traffic statistics
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            updateTrafficStats(data);
            updateCharts(data);
        })
        .catch(error => console.error('Error fetching traffic stats:', error));
    
    // Fetch vulnerabilities
    fetch('/api/vulnerabilities')
        .then(response => response.json())
        .then(data => {
            updateVulnerabilityStats(data);
        })
        .catch(error => console.error('Error fetching vulnerabilities:', error));
    
    // Fetch recent transactions
    fetch('/api/transactions?limit=10')
        .then(response => response.json())
        .then(data => {
            updateRecentTransactions(data.transactions);
        })
        .catch(error => console.error('Error fetching transactions:', error));
}

/**
 * Update proxy status in the dashboard
 * @param {Object} data - Proxy status data
 */
function updateProxyStatus(data) {
    // Update status badge
    const statusBadge = document.getElementById('status-badge');
    if (data.running) {
        statusBadge.className = 'badge bg-success';
        statusBadge.textContent = 'Running';
    } else {
        statusBadge.className = 'badge bg-danger';
        statusBadge.textContent = 'Stopped';
    }
    
    // Update SSL interception status
    const sslBadge = document.getElementById('ssl-interception');
    if (data.intercept_ssl) {
        sslBadge.className = 'badge bg-success';
        sslBadge.textContent = 'Enabled';
    } else {
        sslBadge.className = 'badge bg-secondary';
        sslBadge.textContent = 'Disabled';
    }
    
    // Update connections
    document.getElementById('active-connections').textContent = data.connections;
    
    // Update proxy address
    document.getElementById('dash-proxy-address').textContent = `${data.host}:${data.port}`;
    
    // Update web interface
    document.getElementById('web-interface').textContent = 
        `${data.web_interface?.host || '0.0.0.0'}:${data.web_interface?.port || 5000}`;
    
    // Update log level
    if (data.logging?.level) {
        document.getElementById('log-level').textContent = data.logging.level;
    }
}

/**
 * Update traffic statistics in the dashboard
 * @param {Object} data - Traffic statistics data
 */
function updateTrafficStats(data) {
    document.getElementById('dash-total-requests').textContent = data.total_requests;
    document.getElementById('total-responses').textContent = data.total_responses;
    document.getElementById('dash-total-bytes-in').textContent = formatBytes(data.total_bytes_in);
    document.getElementById('dash-total-bytes-out').textContent = formatBytes(data.total_bytes_out);
    document.getElementById('dashboard-uptime').textContent = formatDuration(data.uptime);
    document.getElementById('requests-per-second').textContent = data.requests_per_second.toFixed(2);
}

/**
 * Update vulnerability statistics in the dashboard
 * @param {Object} data - Vulnerability data
 */
function updateVulnerabilityStats(data) {
    let totalVulns = 0;
    let scannerSigs = 0;
    
    // Sum all vulnerability types
    for (const vuln in data) {
        totalVulns += data[vuln].total_matches;
        if (vuln === 'scanner_signatures') {
            scannerSigs = data[vuln].total_matches;
        }
    }
    
    document.getElementById('total-vulnerabilities').textContent = totalVulns;
    document.getElementById('scanner-signatures').textContent = scannerSigs;
}

/**
 * Update recent transactions in the dashboard
 * @param {Array} transactions - Recent transactions
 */
function updateRecentTransactions(transactions) {
    const tableBody = document.getElementById('recent-transactions');
    
    if (!transactions || transactions.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="7" class="text-center">No transactions recorded yet</td></tr>';
        return;
    }
    
    let html = '';
    
    transactions.forEach(tx => {
        const time = new Date(tx.timestamp * 1000).toLocaleTimeString();
        const client = tx.client_address;
        const method = tx.request.method || 'Unknown';
        const url = tx.request.url || 'Unknown';
        const status = tx.response.status_code || '-';
        const size = formatBytes(tx.response.size || 0);
        
        // Count vulnerabilities
        const vulnCount = tx.vulnerabilities ? tx.vulnerabilities.length : 0;
        const vulnBadge = vulnCount > 0 
            ? `<span class="badge bg-danger">${vulnCount}</span>` 
            : '<span class="badge bg-secondary">0</span>';
        
        html += `
            <tr>
                <td>${time}</td>
                <td>${client}</td>
                <td>${method}</td>
                <td class="text-truncate" style="max-width: 200px;">${url}</td>
                <td>${status}</td>
                <td>${size}</td>
                <td>${vulnBadge}</td>
            </tr>
        `;
    });
    
    tableBody.innerHTML = html;
}

// Initialize the dashboard when the page loads
document.addEventListener('DOMContentLoaded', function() {
    initDashboard();
    
    // Set up event listeners
    document.getElementById('refresh-dashboard')?.addEventListener('click', function() {
        fetchDashboardData();
    });
    
    // Auto-refresh every 10 seconds
    setInterval(fetchDashboardData, 10000);
});
