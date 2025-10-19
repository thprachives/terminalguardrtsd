const API_BASE = 'https://terminalguardrtsd.onrender.com';

let blockChart = null;

function renderBlockChart(blocked, allowed) {
  const ctx = document.getElementById('blockChart').getContext('2d');
  if (blockChart) blockChart.destroy();
  blockChart = new Chart(ctx, {
    type: 'pie',
    data: {
      labels: ['Blocked', 'Allowed'],
      datasets: [{
        data: [blocked, allowed],
        backgroundColor: ['#f44336', '#4caf50'],
      }]
    },
    options: {
      responsive: false,
      plugins: {
        legend: { position: 'bottom' }
      }
    }
  });
}

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

async function fetchLogs() {
  try {
    const res = await fetch(`${API_BASE}/logs?count=10`);
    if (!res.ok) throw new Error("Failed to fetch logs");
    const data = await res.json();

    const tbody = document.getElementById("logTableBody");
    tbody.innerHTML = "";

    if(data.logs.length === 0){
      tbody.innerHTML = "<tr><td colspan='4'>No logs found</td></tr>";
      return;
    }
  
    data.logs.forEach(log => {
      const tr = document.createElement("tr");
      const ts = new Date(log.timestamp).toLocaleString();
      tr.innerHTML = `
        <td>${ts}</td>
        <td title="${log.command}">${log.command.length > 50 ? log.command.substring(0, 50) + "..." : log.command}</td>
        <td>${log.action}</td>
        <td>${log.secrets_found}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (error) {
    console.error(error);
  }
}

async function reloadConfig() {
  try {
    const res = await fetch(`${API_BASE}/reload_config`, { method: 'POST' });
    const data = await res.json();
    document.getElementById('reloadMsg').textContent = data.message || "Reloaded!";
    setTimeout(() => { document.getElementById('reloadMsg').textContent = ""; }, 2000);
    refreshDashboard();
  } catch (err) {
    document.getElementById('reloadMsg').textContent = "Error reloading config!";
  }
}

function refreshDashboard() {
  fetchStats();
  fetchLogs();
}

// Initial fetch and auto-refresh every 5 seconds
refreshDashboard();
setInterval(refreshDashboard, 5000);
