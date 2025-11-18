// const API_BASE = 'https://terminalguardrtsd.onrender.com';

// let blockChart = null;

// function renderBlockChart(blocked, allowed) {
//   const ctx = document.getElementById('blockChart').getContext('2d');
//   if (blockChart) blockChart.destroy();
//   blockChart = new Chart(ctx, {
//     type: 'pie',
//     data: {
//       labels: ['Blocked', 'Allowed'],
//       datasets: [{
//         data: [blocked, allowed],
//         backgroundColor: ['#f44336', '#4caf50'],
//       }]
//     },
//     options: {
//       responsive: false,
//       plugins: {
//         legend: { position: 'bottom' }
//       }
//     }
//   });
// }

// async function fetchStats() {
//   try {
//     const res = await fetch(`${API_BASE}/statistics`);
//     if (!res.ok) throw new Error("Failed to fetch stats");
//     const data = await res.json();

//     document.getElementById("totalCommands").textContent = data.total_commands;
//     document.getElementById("blockedCommands").textContent = data.blocked_commands;
//     document.getElementById("allowedCommands").textContent = data.allowed_commands;
//     document.getElementById("totalSecrets").textContent = data.total_secrets_detected;
//     document.getElementById("blockRate").textContent = data.block_rate_percent;

//     renderBlockChart(data.blocked_commands, data.allowed_commands);
//   } catch (error) {
//     console.error(error);
//   }
// }

// async function fetchLogs() {
//   try {
//     const res = await fetch(`${API_BASE}/logs?count=10`);
//     if (!res.ok) throw new Error("Failed to fetch logs");
//     const data = await res.json();

//     const tbody = document.getElementById("logTableBody");
//     tbody.innerHTML = "";

//     if(data.logs.length === 0){
//       tbody.innerHTML = "<tr><td colspan='4'>No logs found</td></tr>";
//       return;
//     }
  
//     data.logs.forEach(log => {
//       const tr = document.createElement("tr");
//       const ts = new Date(log.timestamp).toLocaleString();
//       tr.innerHTML = `
//         <td>${ts}</td>
//         <td title="${log.command}">${log.command.length > 50 ? log.command.substring(0, 50) + "..." : log.command}</td>
//         <td>${log.action}</td>
//         <td>${log.secrets_found}</td>
//       `;
//       tbody.appendChild(tr);
//     });
//   } catch (error) {
//     console.error(error);
//   }
// }

// async function reloadConfig() {
//   try {
//     const res = await fetch(`${API_BASE}/reload_config`, { method: 'POST' });
//     const data = await res.json();
//     document.getElementById('reloadMsg').textContent = data.message || "Reloaded!";
//     setTimeout(() => { document.getElementById('reloadMsg').textContent = ""; }, 2000);
//     refreshDashboard();
//   } catch (err) {
//     document.getElementById('reloadMsg').textContent = "Error reloading config!";
//   }
// }

// function refreshDashboard() {
//   fetchStats();
//   fetchLogs();
// }

// // Initial fetch and auto-refresh every 5 seconds
// refreshDashboard();

const API_BASE = 'https://terminalguardrtsd.onrender.com';

let blockChart = null;
let falsePositiveChart = null;
let falseNegativeChart = null;
let accuracyChart = null;
let logs = [];

async function fetchStats() {
    try {
        const res = await fetch(`${API_BASE}/statistics`);
        if (!res.ok) throw new Error("Failed to fetch stats");
        const data = await res.json();
        document.getElementById("totalCommands").textContent = data.total_commands;
        document.getElementById("blockedCommands").textContent = data.blocked_commands;
        document.getElementById("allowedCommands").textContent = data.allowed_commands;
        document.getElementById("totalSecrets").textContent = data.total_secrets_detected;
        document.getElementById("blockRate").textContent = data.block_rate_percent;
        renderBlockChart(data.blocked_commands, data.allowed_commands);
    } catch (error) {
        console.error(error);
    }
}

function renderBlockChart(blocked, allowed) {
    const ctx = document.getElementById("blockChart").getContext("2d");
    if (blockChart) blockChart.destroy();
    blockChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Blocked', 'Allowed'],
            datasets: [{ data: [blocked, allowed], backgroundColor: ['#f44336', '#4caf50'] }]
        },
        options: { responsive: false, plugins: { legend: { position: 'bottom' } } }
    });
}

async function fetchLogs() {
    try {
        const res = await fetch(`${API_BASE}/logs?count=15`);
        if (!res.ok) throw new Error("Failed to fetch logs");
        const data = await res.json();
        logs = data.logs;
        renderLogsTable(logs);
        calculateAndRenderMetrics();
    } catch (error) {
        console.error(error);
    }
}

function renderLogsTable(logs) {
    const tbody = document.getElementById("logTableBody");
    tbody.innerHTML = "";
    logs.forEach(log => {
        const tr = document.createElement("tr");

        // Timestamp
        const tdTime = document.createElement("td");
        tdTime.textContent = new Date(log.timestamp).toLocaleString();
        tr.appendChild(tdTime);

        // Command (short)
        const tdCmd = document.createElement("td");
        tdCmd.textContent = (log.command || "").slice(0, 60);
        tr.appendChild(tdCmd);

        // Action
        const tdAction = document.createElement("td");
        tdAction.textContent = log.action;
        tdAction.className = log.action === "BLOCKED" ? "status-blocked" : "status-allowed";
        tr.appendChild(tdAction);

        // Secrets Found (Yes/No)
        const tdSecret = document.createElement("td");
        tdSecret.textContent = log.secrets_found > 0 ? "Yes" : "No";
        tdSecret.className = log.secrets_found > 0 ? "secret-yes" : "secret-no";
        tr.appendChild(tdSecret);

        // Mark Detection Buttons
        const tdMark = document.createElement("td");
        const tickBtn = document.createElement("button");
        tickBtn.textContent = "✔️";
        tickBtn.title = "Mark as correctly detected";
        tickBtn.onclick = () => handleMarkDetection(log._id || log.id, "true");
        if (log.mark_detection === "true") tickBtn.style.backgroundColor = "#4caf50";

        const crossBtn = document.createElement("button");
        crossBtn.textContent = "❌";
        crossBtn.title = "Mark as incorrectly detected";
        crossBtn.onclick = () => handleMarkDetection(log._id || log.id, "false");
        if (log.mark_detection === "false") crossBtn.style.backgroundColor = "#f44336";

        tdMark.appendChild(tickBtn);
        tdMark.appendChild(crossBtn);
        tr.appendChild(tdMark);

        tbody.appendChild(tr);
    });
}

async function handleMarkDetection(logId, mark) {
    try {
        await fetch(`${API_BASE}/logs/mark_detection`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ log_id: logId, mark }),
        });
        await fetchLogs(); // Refresh logs & charts on update
    } catch (error) {
        console.error("Failed to update mark detection:", error);
    }
}

function calculateAndRenderMetrics() {
    let TP = 0, TN = 0, FP = 0, FN = 0;
    logs.forEach(log => {
        if (log.mark_detection === "true" || log.mark_detection === "false") {
            const markedTrue = log.mark_detection === "true";
            const secretFound = log.secrets_found > 0;

            if (secretFound) {
                markedTrue ? TP++ : FP++;
            } else {
                markedTrue ? FN++ : TN++;
            }
        }
    });

    const total = TP + TN + FP + FN;
    const accuracy = total ? (TP + TN) / total : 0;

    renderFalsePositiveChart(FP, TP);
    renderFalseNegativeChart(FN, TN);
    renderAccuracyChart(TP + TN, FP + FN);
}

function renderFalsePositiveChart(FP, TP) {
    const ctx = document.getElementById("falsePositiveChart").getContext("2d");
    if (falsePositiveChart) falsePositiveChart.destroy();
    falsePositiveChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['False Positives', 'True Positives'],
            datasets: [{ data: [FP, TP], backgroundColor: ['#f44336', '#4caf50'] }]
        },
        options: { responsive: false, plugins: { legend: { position: 'bottom' } } }
    });
}

function renderFalseNegativeChart(FN, TN) {
    const ctx = document.getElementById("falseNegativeChart").getContext("2d");
    if (falseNegativeChart) falseNegativeChart.destroy();
    falseNegativeChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['False Negatives', 'True Negatives'],
            datasets: [{ data: [FN, TN], backgroundColor: ['#f44336', '#4caf50'] }]
        },
        options: { responsive: false, plugins: { legend: { position: 'bottom' } } }
    });
}

function renderAccuracyChart(correctCount, incorrectCount) {
    const ctx = document.getElementById("accuracyChart").getContext("2d");
    if (accuracyChart) accuracyChart.destroy();
    accuracyChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Correct', 'Incorrect'],
            datasets: [{ data: [correctCount, incorrectCount], backgroundColor: ['#4caf50', '#f44336'] }]
        },
        options: { responsive: false, plugins: { legend: { position: 'bottom' } } }
    });
}

window.onload = async () => {
    await fetchStats();
    await fetchLogs();
};
