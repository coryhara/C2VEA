const chartGridColor = "rgba(104, 156, 228, 0.28)";
const chartTickColor = "#c4ddff";
const chartLabelColor = "#eaf4ff";
const isCompact = window.matchMedia("(max-width: 920px)").matches;
const CHART_HEIGHT = 360;

const charts = new Map();

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function formatCompactNumber(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n)) return "0";
  return new Intl.NumberFormat("en-US", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(n);
}

function formatPercent(part, total) {
  const pct = total > 0 ? (Number(part || 0) / Number(total)) * 100 : 0;
  const digits = pct >= 1 ? 2 : pct >= 0.1 ? 3 : 4;
  return `${pct.toFixed(digits)}%`;
}

function toCount(value) {
  const n =
    typeof value === "string"
      ? Number(value.replace(/,/g, ""))
      : Number(value);
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
  host.innerHTML = "";

  try {
    const chart = new ApexCharts(host, options);
    chart.render();
    charts.set(id, chart);
  } catch (e) {
    host.innerHTML = "<div style='padding:1rem;color:#c4ddff'>Chart render failed</div>";
    console.error(`${id} render failed:`, e);
  }
}

function renderSummary(data) {
  const summary = data || {};
  document.getElementById("total").textContent = formatNumber(summary.total);
  document.getElementById("recent").textContent = formatNumber(summary.recent_7d);
  document.getElementById("avg").textContent = Number(summary.avg_score || 0).toFixed(2);
}

function renderSeverity(data) {
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
}

function renderScores(data) {
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
}

function renderVector(data) {
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
}

function renderTags(data) {
  const filtered = cleanData(data, "tag");
  const tagPoints = filtered
    .map((d) => ({
      x: shortLabel(d.tag, 30),
      y: toCount(d.count),
    }))
    .filter((d) => d.y > 0)
    .slice(0, 10);
  upsertChart("tagsChart", {
    ...baseOptions("bar"),
    series: [{ name: "Count", data: tagPoints }],
    xaxis: {
      min: 0,
      axisBorder: { show: false },
      axisTicks: { show: false },
      labels: {
        show: false,
      },
    },
    yaxis: {
      labels: {
        trim: true,
        maxWidth: isCompact ? 140 : 200,
        style: { colors: chartTickColor, fontSize: isCompact ? "11px" : "12px", fontWeight: 600 },
      },
    },
    plotOptions: {
      bar: {
        horizontal: true,
        borderRadius: 8,
        barHeight: "42%",
      },
    },
    dataLabels: {
      enabled: true,
      formatter: (val) => formatNumber(val),
      offsetX: 10,
      style: { colors: ["#eaf4ff"], fontSize: "11px", fontWeight: 700 },
    },
    grid: {
      borderColor: chartGridColor,
      strokeDashArray: 0,
      xaxis: { lines: { show: false } },
      yaxis: { lines: { show: true } },
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
}

function renderPoc(data) {
  const poc = data || {};
  const pocCount = toCount(poc.poc_count);
  const noPocCount = toCount(poc.no_poc_count);
  const total = pocCount + noPocCount;
  const major = Math.max(pocCount, noPocCount);
  const minor = Math.min(pocCount, noPocCount);
  const imbalanceRatio = major > 0 ? minor / major : 1;
  const isExtremeImbalance = imbalanceRatio < 0.01;

  if (isExtremeImbalance) {
    upsertChart("pocChart", {
      ...baseOptions("bar"),
      series: [{ name: "Count", data: [pocCount, noPocCount] }],
      colors: ["#41d8ff"],
      fill: {
        type: "gradient",
        gradient: {
          shade: "dark",
          type: "vertical",
          shadeIntensity: 0.28,
          opacityFrom: 0.95,
          opacityTo: 0.72,
          stops: [0, 100],
          gradientToColors: ["#ff6694"],
        },
      },
      plotOptions: {
        bar: {
          borderRadius: 8,
          columnWidth: "48%",
          distributed: true,
          dataLabels: {
            position: "center",
          },
        },
      },
      xaxis: {
        categories: ["With PoC", "Without PoC"],
        labels: { style: { colors: chartTickColor, fontSize: isCompact ? "11px" : "12px", fontWeight: 600 } },
      },
      yaxis: {
        logarithmic: true,
        min: 1,
        tickAmount: 6,
        labels: {
          style: { colors: chartTickColor, fontSize: isCompact ? "11px" : "12px", fontWeight: 600 },
          formatter: (val) => formatCompactNumber(Math.max(1, Math.round(val))),
        },
      },
      dataLabels: {
        enabled: true,
        formatter: (val, opts) => {
          const i = opts.dataPointIndex;
          const count = i === 0 ? pocCount : noPocCount;
          return [formatNumber(count), formatPercent(count, total)];
        },
        style: { colors: ["#eaf4ff"], fontSize: "11px", fontWeight: 700 },
        offsetY: 0,
      },
      title: {
        text: `TOTAL ${formatNumber(total)} - LOG SCALE`,
        align: "center",
        style: { color: chartLabelColor, fontSize: "13px", fontWeight: 700 },
      },
      legend: { show: false },
      stroke: { width: 1.2, colors: ["rgba(8, 16, 31, 0.9)"] },
    });
    return;
  }

  upsertChart("pocChart", {
    ...baseOptions("donut"),
    series: [pocCount, noPocCount],
    labels: ["With PoC", "Without PoC"],
    colors: ["#41d8ff", "#ff6694"],
    stroke: { width: 1, colors: ["rgba(8, 16, 31, 0.88)"] },
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
        customScale: 0.92,
        donut: {
          size: "52%",
          labels: {
            show: true,
            name: { show: true, color: chartTickColor },
            value: {
              show: true,
              color: chartLabelColor,
              formatter: (val) => formatNumber(val),
            },
            total: {
              show: true,
              label: "TOTAL",
              color: chartTickColor,
              formatter: () => formatNumber(total),
            },
          },
        },
      },
    },
    dataLabels: {
      enabled: true,
      formatter: (val) => (val >= 1 ? `${val.toFixed(1)}%` : ""),
      style: { colors: ["#eaf4ff"], fontSize: "11px", fontWeight: 700 },
    },
    legend: {
      position: "bottom",
      labels: { colors: chartLabelColor },
      formatter: (seriesName, opts) => {
        const v = opts.w.globals.series[opts.seriesIndex] || 0;
        return `${seriesName}: ${formatNumber(v)}`;
      },
    },
  });
}

function applyDashboardSnapshot(payload) {
  const data = payload || {};
  renderSummary(data.summary || {});
  renderSeverity(Array.isArray(data.severity) ? data.severity : []);
  renderScores(Array.isArray(data.scores) ? data.scores : []);
  renderVector(Array.isArray(data.attack_vector) ? data.attack_vector : []);
  renderTags(Array.isArray(data.tags) ? data.tags : []);
  renderPoc(data.poc_stats || {});
}

function connectDashboardSocket() {
  const socket = io({
    path: "/socket.io/",
    transports: ["websocket", "polling"],
  });

  socket.on("connect", () => {
    socket.emit("subscribe_dashboard", { interval_ms: 5000 });
  });

  socket.on("dashboard_snapshot", (snapshot) => {
    applyDashboardSnapshot(snapshot);
  });

  socket.on("connect_error", (err) => {
    console.error("Dashboard socket connect error:", err?.message || err);
  });

  socket.on("disconnect", () => {
    console.warn("Dashboard socket disconnected");
  });

  window.addEventListener("beforeunload", () => {
    socket.emit("unsubscribe_dashboard");
    socket.close();
  });
}

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
connectDashboardSocket();

let resizeDebounce = null;
window.addEventListener("resize", () => {
  if (resizeDebounce) clearTimeout(resizeDebounce);
  resizeDebounce = setTimeout(() => {
    charts.forEach((chart) =>
      chart.updateOptions(
        {
          chart: { height: CHART_HEIGHT },
        },
        false,
        false
      )
    );
  }, 140);
});
