const tableBody = document.getElementById("logTableBody");

const logs = [];
const logIds = new Set();
const MAX_LOGS = 1000;

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (m) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  })[m]);
}

function prependLog(log) {
  const id = Number(log?.id || 0);
  if (id > 0 && logIds.has(id)) return;

  logs.unshift(log);
  if (id > 0) logIds.add(id);
  if (logs.length > MAX_LOGS) {
    const removed = logs.pop();
    const removedId = Number(removed?.id || 0);
    if (removedId > 0) logIds.delete(removedId);
  }

  const status = String(log.status || "").toLowerCase();
  const statusClass =
    status === "success" ? "status-success" :
    status === "error" ? "status-error" :
    status === "warning" ? "status-warning" :
    "status-neutral";

  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${escapeHTML(log.id)}</td>
    <td><span class="status-pill ${statusClass}">${escapeHTML(log.status)}</span></td>
    <td>${escapeHTML(log.message)}</td>
    <td>${escapeHTML(log.log_time)}</td>
  `;
  tableBody.insertBefore(tr, tableBody.firstChild);

  if (tableBody.rows.length > MAX_LOGS) {
    tableBody.deleteRow(-1);
  }
}

function getLastLogId() {
  return logs.length ? Number(logs[0].id || 0) : 0;
}
