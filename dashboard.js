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
        document.getElementById("falsePositiveRate").textContent = data.false_positive_rate;
        document.getElementById("falseNegativeRate").textContent = data.false_negative_rate;
        document.getElementById("accuracyPercent").textContent = data.accuracy_percent;
        renderBlockChart(data.blocked_commands, data.allowed_commands);
    } catch (error) {
        console.error(error);
    }
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

function renderBlockChart(blocked, allowed) {
    const ctx = document.getElementById("blockChart").getContext("2d");
    if (blockChart) blockChart.destroy();
    blockChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Blocked', 'Allowed'],
            datasets: [{
                data: [blocked, allowed],
                backgroundColor: ['#f44336', '#4caf50']
            }]
        },
        options: { responsive: false, plugins: { legend: { position: 'bottom' } } }
    });
}

function renderLogsTable(logs) {
    const tbody = document.getElementById("logTableBody");
    tbody.innerHTML = "";
    logs.forEach(log => {
        const tr = document.createElement("tr");

        const tdCmd = document.createElement("td");
        tdCmd.textContent = (log.command || "").slice(0, 60);
        tr.appendChild(tdCmd);

        const tdAction = document.createElement("td");
        tdAction.textContent = log.action;
        tdAction.className = log.action === "BLOCKED" ? "status-blocked" : "status-allowed";
        tr.appendChild(tdAction);

        const tdSecret = document.createElement("td");
        tdSecret.textContent = log.secrets_found > 0 ? "Yes" : "No";
        tdSecret.className = log.secrets_found > 0 ? "secret-yes" : "secret-no";
        tr.appendChild(tdSecret);

        const tdMark = document.createElement("td");
        if (log.mark_detection === "true") {
            const correctSpan = document.createElement("span");
            correctSpan.textContent = "Correct";
            correctSpan.className = "correct-label";
            tdMark.appendChild(correctSpan);
        } else if (log.mark_detection === "false") {
            const incorrectSpan = document.createElement("span");
            incorrectSpan.textContent = "Incorrect";
            incorrectSpan.className = "incorrect-label";
            tdMark.appendChild(incorrectSpan);
        } else {
            const tickBtn = document.createElement("button");
            tickBtn.textContent = "✔️";
            tickBtn.title = "Mark Correct";
            tickBtn.onclick = () => handleMarkDetection(log._id || log.id, "true");

            const crossBtn = document.createElement("button");
            crossBtn.textContent = "❌";
            crossBtn.title = "Mark Incorrect";
            crossBtn.onclick = () => handleMarkDetection(log._id || log.id, "false");

            tdMark.appendChild(tickBtn);
            tdMark.appendChild(crossBtn);
        }
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
        await fetchLogs();
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

function renderAccuracyChart(correct, incorrect) {
    const ctx = document.getElementById("accuracyChart").getContext("2d");
    if (accuracyChart) accuracyChart.destroy();
    accuracyChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Correct', 'Incorrect'],
            datasets: [{ data: [correct, incorrect], backgroundColor: ['#4caf50', '#f44336'] }]
        },
        options: { responsive: false, plugins: { legend: { position: 'bottom' } } }
    });
}

document.getElementById("refreshButton").onclick = async () => {
    await fetchStats();
    await fetchLogs();
};

window.onload = async () => {
    await fetchStats();
    await fetchLogs();
};
