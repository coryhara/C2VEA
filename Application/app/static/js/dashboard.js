// Chart.js 전역 기본 설정 (모든 차트에 적용)
Chart.defaults.color = "#ffffff";              // 기본 텍스트 색
Chart.defaults.font.size = 14;                 // 기본 폰트 크기
Chart.defaults.font.weight = "bold";           // 기본 폰트 굵기
Chart.defaults.devicePixelRatio = window.devicePixelRatio || 1; // DPI 맞춤

// 요약 카드
fetch("/api/cve/summary")
  .then(r => r.json())
  .then(data => {
    document.getElementById("total").textContent = (data.total ?? 0).toLocaleString();
    document.getElementById("recent").textContent = (data.recent_7d ?? 0).toLocaleString();
    document.getElementById("avg").textContent = data.avg_score ?? 0;
  });

// Helper: total/all/null 제거
function cleanData(data, key) {
  return data.filter(d => {
    const val = (d[key] || "").toString().toLowerCase();
    return val && val !== "total" && val !== "all" && val !== "null";
  });
}

// Severity 분포
fetch("/api/cve/severity")
  .then(r => r.json())
  .then(data => {
    const filtered = cleanData(data, "severity");
    new Chart(document.getElementById("severityChart"), {
      type: "pie",
      data: {
        labels: filtered.map(d => d.severity),
        datasets: [{
          data: filtered.map(d => d.count),
          backgroundColor: ["#ff4d4d", "#ff944d", "#ffd24d", "#99e699"]
        }]
      },
      options: {
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: { color: "#ffffff", font: { size: 14, weight: "bold" } }
          }
        }
      }
    });
  });

// Score 구간별
fetch("/api/cve/scores")
  .then(r => r.json())
  .then(data => {
    const filtered = cleanData(data, "range_label");
    new Chart(document.getElementById("scoreChart"), {
      type: "bar",
      data: {
        labels: filtered.map(d => d.range_label),
        datasets: [{
          label: "Count",
          data: filtered.map(d => d.count),
          backgroundColor: "#74cfc5"
        }]
      },
      options: {
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: "#ffffff", font: { size: 13 } }, grid: { color: "#333" } },
          y: { ticks: { color: "#ffffff", font: { size: 13 } }, grid: { color: "#333" } }
        },
        plugins: {
          legend: {
            labels: { color: "#ffffff", font: { size: 14, weight: "bold" } }
          }
        }
      }
    });
  });

// Attack Vector
fetch("/api/cve/attack-vector")
  .then(r => r.json())
  .then(data => {
    const filtered = cleanData(data, "attack_vector");
    new Chart(document.getElementById("vectorChart"), {
      type: "doughnut",
      data: {
        labels: filtered.map(d => d.attack_vector),
        datasets: [{
          data: filtered.map(d => d.count),
          backgroundColor: ["#74cfc5", "#ff944d", "#ffd24d", "#99e699"]
        }]
      },
      options: {
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: { color: "#ffffff", font: { size: 14, weight: "bold" } }
          }
        }
      }
    });
  });

// Top Tags
fetch("/api/cve/tags")
  .then(r => r.json())
  .then(data => {
    const filtered = cleanData(data, "tag");
    new Chart(document.getElementById("tagsChart"), {
      type: "bar",
      data: {
        labels: filtered.map(d => d.tag),
        datasets: [{
          label: "Count",
          data: filtered.map(d => d.count),
          backgroundColor: "#c77d4c"
        }]
      },
      options: {
        maintainAspectRatio: false,
        indexAxis: "y",
        scales: {
          x: { ticks: { color: "#ffffff", font: { size: 13 } }, grid: { color: "#333" } },
          y: { ticks: { color: "#ffffff", font: { size: 13 } }, grid: { color: "#333" } }
        },
        plugins: {
          legend: {
            labels: { color: "#ffffff", font: { size: 14, weight: "bold" } }
          }
        }
      }
    });
  });

  // PoC 존재 여부 통계
fetch("/api/cve/poc-stats")
  .then(r => r.json())
  .then(data => {
    new Chart(document.getElementById("pocChart"), {
      type: "pie",
      data: {
        labels: ["With PoC", "Without PoC"],
        datasets: [{
          data: [data.poc_count, data.no_poc_count],
          backgroundColor: ["#36A2EB", "#FF6384"]
        }]
      },
      options: {
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: { color: "#ffffff", font: { size: 14, weight: "bold" } }
          }
        }
      }
    });
  });

// 드래그 앤 드롭 (차트 순서 변경 + 저장)
const grid = document.getElementById("charts-grid");

function applySavedOrder() {
  const savedOrder = JSON.parse(localStorage.getItem("chartsOrder") || "[]");
  if (savedOrder.length) {
    savedOrder.forEach(id => {
      const el = document.getElementById(id);
      if (el) grid.appendChild(el);
    });
  }
}

new Sortable(grid, {
  animation: 150,
  ghostClass: "dragging",
  onEnd: () => {
    const order = [...grid.children].map(card => card.id);
    localStorage.setItem("chartsOrder", JSON.stringify(order));
  }
});

// 페이지 로드 시 순서 복원
applySavedOrder();
