const chartGridColor = "rgba(104, 156, 228, 0.28)";
const chartTickColor = "#c4ddff";
const chartLabelColor = "#eaf4ff";
const isCompact = window.matchMedia("(max-width: 920px)").matches;
const CHART_HEIGHT = 360;

const charts = new Map();

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function toCount(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function shortLabel(text, max = 26) {
  const str = String(text || "");
  if (str.length <= max) return str;
  return `${str.slice(0, max - 1)}...`;
}

function cleanData(data, key) {
  return (Array.isArray(data) ? data : []).filter((item) => {
    const val = (item[key] || "").toString().toLowerCase();
    return val && val !== "total" && val !== "all" && val !== "null";
  });
}

function fetchJSON(url) {
  return fetch(url).then((res) => {
    if (!res.ok) throw new Error(`${url} -> ${res.status}`);
    return res.json();
  });
}

function baseOptions(type) {
  return {
    chart: {
      type,
      height: CHART_HEIGHT,
      parentHeightOffset: 0,
      toolbar: { show: false },
      foreColor: chartLabelColor,
      background: "transparent",
      animations: { enabled: true, easing: "easeout", speed: 420 },
      fontFamily: "Manrope, sans-serif",
    },
    theme: { mode: "dark" },
    dataLabels: { enabled: false },
    stroke: { curve: "smooth" },
    tooltip: {
      theme: "dark",
      y: { formatter: (val) => formatNumber(val) },
    },
    legend: {
      position: isCompact ? "bottom" : "right",
      labels: { colors: chartLabelColor },
      fontSize: isCompact ? "12px" : "13px",
      markers: { width: 11, height: 11, radius: 99 },
    },
    grid: {
      borderColor: chartGridColor,
      strokeDashArray: 0,
    },
    noData: {
      text: "No data",
      align: "center",
      verticalAlign: "middle",
      style: { color: chartTickColor },
    },
    responsive: [
      {
        breakpoint: 920,
        options: {
          legend: { position: "bottom" },
        },
      },
    ],
  };
}

function upsertChart(id, options) {
  const host = document.getElementById(id);
  if (!host) return;

  if (charts.has(id)) {
    charts.get(id).destroy();
  }

  const chart = new ApexCharts(host, options);
  chart.render();
  charts.set(id, chart);
}

fetchJSON("/api/cve/summary")
  .then((data) => {
    document.getElementById("total").textContent = formatNumber(data.total);
    document.getElementById("recent").textContent = formatNumber(data.recent_7d);
    document.getElementById("avg").textContent = Number(data.avg_score || 0).toFixed(2);
  })
  .catch((err) => console.error("summary fetch failed:", err));

fetchJSON("/api/cve/severity")
  .then((data) => {
    const filtered = cleanData(data, "severity");
    upsertChart("severityChart", {
      ...baseOptions("donut"),
      series: filtered.map((d) => toCount(d.count)),
      labels: filtered.map((d) => String(d.severity || "UNKNOWN").toUpperCase()),
      colors: ["#ff6a8f", "#ffa654", "#f8cf66", "#5fcea4", "#61d5ff"],
      stroke: { width: 0 },
      fill: {
        type: "gradient",
        gradient: {
          shade: "dark",
          type: "vertical",
          shadeIntensity: 0.35,
          opacityFrom: 0.98,
          opacityTo: 0.9,
          stops: [0, 100],
        },
      },
      plotOptions: {
        pie: {
          expandOnClick: false,
          customScale: 0.86,
          donut: { size: "34%" },
        },
      },
    });
  })
  .catch((err) => console.error("severity fetch failed:", err));

fetchJSON("/api/cve/scores")
  .then((data) => {
    const filtered = cleanData(data, "range_label");
    upsertChart("scoreChart", {
      ...baseOptions("bar"),
      series: [{ name: "Count", data: filtered.map((d) => toCount(d.count)) }],
      xaxis: {
        categories: filtered.map((d) => d.range_label),
        labels: { style: { colors: chartTickColor, fontSize: isCompact ? "11px" : "12px", fontWeight: 600 } },
      },
      yaxis: {
        labels: {
          style: { colors: chartTickColor, fontSize: isCompact ? "11px" : "12px", fontWeight: 600 },
          formatter: (val) => formatNumber(val),
        },
      },
      plotOptions: {
        bar: {
          borderRadius: 8,
          columnWidth: "52%",
        },
      },
      fill: {
        type: "gradient",
        gradient: {
          shade: "dark",
          type: "vertical",
          shadeIntensity: 0.3,
          opacityFrom: 0.95,
          opacityTo: 0.68,
          stops: [0, 100],
          gradientToColors: ["#4178f4"],
        },
      },
      colors: ["#57e3f5"],
      stroke: { width: 1.2, colors: ["rgba(182, 235, 255, 0.34)"] },
      legend: { show: false },
    });
  })
  .catch((err) => console.error("score fetch failed:", err));

fetchJSON("/api/cve/attack-vector")
  .then((data) => {
    const filtered = cleanData(data, "attack_vector");
    upsertChart("vectorChart", {
      ...baseOptions("donut"),
      series: filtered.map((d) => toCount(d.count)),
      labels: filtered.map((d) => String(d.attack_vector || "UNKNOWN").toUpperCase()),
      colors: ["#46d3ff", "#73e6bd", "#9774ff", "#ffa44f", "#ff648f"],
      stroke: { width: 0 },
      fill: {
        type: "gradient",
        gradient: {
          shade: "dark",
          type: "vertical",
          shadeIntensity: 0.3,
          opacityFrom: 0.98,
          opacityTo: 0.9,
          stops: [0, 100],
        },
      },
      plotOptions: {
        pie: {
          expandOnClick: false,
          customScale: 0.84,
          donut: { size: "44%" },
        },
      },
    });
  })
  .catch((err) => console.error("vector fetch failed:", err));

fetchJSON("/api/cve/tags")
  .then((data) => {
    const filtered = cleanData(data, "tag");
    upsertChart("tagsChart", {
      ...baseOptions("bar"),
      series: [{ name: "Count", data: filtered.map((d) => toCount(d.count)) }],
      xaxis: {
        categories: filtered.map((d) => shortLabel(d.tag, 30)),
        labels: {
          style: { colors: chartTickColor, fontSize: isCompact ? "11px" : "12px", fontWeight: 600 },
          formatter: (val) => formatNumber(val),
        },
      },
      yaxis: {
        labels: {
          style: { colors: chartTickColor, fontSize: isCompact ? "11px" : "12px", fontWeight: 600 },
        },
      },
      plotOptions: {
        bar: {
          horizontal: true,
          borderRadius: 8,
          barHeight: "40%",
        },
      },
      fill: {
        type: "gradient",
        gradient: {
          shade: "dark",
          type: "horizontal",
          shadeIntensity: 0.25,
          opacityFrom: 0.94,
          opacityTo: 0.66,
          stops: [0, 100],
          gradientToColors: ["#5bd8ff"],
        },
      },
      colors: ["#ad82ff"],
      stroke: { width: 1.2, colors: ["rgba(210, 232, 255, 0.36)"] },
      legend: { show: false },
    });
  })
  .catch((err) => console.error("tags fetch failed:", err));

fetchJSON("/api/cve/poc-stats")
  .then((data) => {
    const pocCount = toCount(data.poc_count);
    const noPocCount = toCount(data.no_poc_count);
    upsertChart("pocChart", {
      ...baseOptions("donut"),
      series: [pocCount, noPocCount],
      labels: ["With PoC", "Without PoC"],
      colors: ["#41d8ff", "#ff6694"],
      stroke: { width: 0 },
      fill: {
        type: "gradient",
        gradient: {
          shade: "dark",
          type: "vertical",
          shadeIntensity: 0.35,
          opacityFrom: 0.98,
          opacityTo: 0.9,
          stops: [0, 100],
        },
      },
      plotOptions: {
        pie: {
          expandOnClick: false,
          customScale: 0.84,
          donut: { size: "58%" },
        },
      },
    });
  })
  .catch((err) => console.error("poc stats fetch failed:", err));

const grid = document.getElementById("charts-grid");

function applySavedOrder() {
  const savedOrder = JSON.parse(localStorage.getItem("chartsOrder") || "[]");
  if (!savedOrder.length) return;
  savedOrder.forEach((id) => {
    const el = document.getElementById(id);
    if (el) grid.appendChild(el);
  });
}

new Sortable(grid, {
  animation: 160,
  ghostClass: "dragging",
  onEnd: () => {
    const order = [...grid.children].map((card) => card.id);
    localStorage.setItem("chartsOrder", JSON.stringify(order));
  },
});

applySavedOrder();

let resizeDebounce = null;
window.addEventListener("resize", () => {
  if (resizeDebounce) clearTimeout(resizeDebounce);
  resizeDebounce = setTimeout(() => {
    charts.forEach((chart) =>
      chart.updateOptions(
        {
          chart: { height: CHART_HEIGHT },
          legend: { position: window.matchMedia("(max-width: 920px)").matches ? "bottom" : "right" },
        },
        false,
        false
      )
    );
  }, 140);
});
