const alerts = document.getElementById("alerts");

function showAlert(message) {
  const div = document.createElement("div");
  div.textContent = message;
  alerts.prepend(div);

  setTimeout(() => {
    if (alerts.contains(div)) alerts.removeChild(div);
  }, 10000);
}