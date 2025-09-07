const tableBody = document.getElementById("logTableBody");

const logs = [];
const MAX_LOGS = 1000;

function prependLog(log) {
  logs.unshift(log);
  if (logs.length > MAX_LOGS) logs.pop();

  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${log.id}</td>
    <td>${log.status || ""}</td>
    <td>${log.message || ""}</td>
    <td>${log.log_time || ""}</td>
  `;
  tableBody.insertBefore(tr, tableBody.firstChild);

  if (tableBody.rows.length > MAX_LOGS) {
    tableBody.deleteRow(-1);
  }
}