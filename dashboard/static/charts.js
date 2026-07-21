// =======================================
// Charts
// =======================================

let severityChart = null;
let ipChart = null;
let timelineChart = null;

async function loadCharts() {

    try {

        const response = await fetch("/api/stats");
        const data = await response.json();

        // ==========================
        // Severity Pie Chart
        // ==========================

        const severityCtx = document
            .getElementById("severityChart")
            .getContext("2d");

        if (severityChart) {
            severityChart.destroy();
        }

        severityChart = new Chart(severityCtx, {

            type: "pie",

            data: {

                labels: [
                    "High",
                    "Medium",
                    "Low"
                ],

                datasets: [{
                    data: [
                        data.severity.HIGH,
                        data.severity.MEDIUM,
                        data.severity.LOW
                    ],

                    backgroundColor: [
                        "#dc3545",
                        "#ffc107",
                        "#198754"
                    ]
                }]
            },

            options: {

                responsive: true,

                plugins: {

                    legend: {
                        labels: {
                            color: "white"
                        }
                    }

                }

            }

        });

        // ==========================
        // Top Attacking IPs
        // ==========================

        const ipLabels = data.top_ips.map(item => item.ip);
        const ipCounts = data.top_ips.map(item => item.count);

        const ipCtx = document
            .getElementById("ipChart")
            .getContext("2d");

        if (ipChart) {
            ipChart.destroy();
        }

        ipChart = new Chart(ipCtx, {

            type: "bar",

            data: {

                labels: ipLabels,

                datasets: [{

                    label: "Alerts",

                    data: ipCounts,

                    backgroundColor: "#0d6efd"

                }]

            },

            options: {

                responsive: true,

                plugins: {

                    legend: {

                        labels: {

                            color: "white"

                        }

                    }

                },

                scales: {

                    x: {

                        ticks: {

                            color: "white"

                        }

                    },

                    y: {

                        beginAtZero: true,

                        ticks: {

                            color: "white"

                        }

                    }

                }

            }

        });

        // ==========================
        // Alerts Over Time
        // ==========================

        const timelineCtx = document
            .getElementById("timelineChart")
            .getContext("2d");

        if (timelineChart) {
            timelineChart.destroy();
        }

        timelineChart = new Chart(timelineCtx, {
            type: "line",
            data: {
                labels: data.alerts_by_day.map(item => item.date),
                datasets: [{
                    label: "Alerts",
                    data: data.alerts_by_day.map(item => item.count),
                    borderColor: "#0dcaf0",
                    backgroundColor: "rgba(13, 202, 240, 0.2)",
                    fill: true,
                    tension: 0.25
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { labels: { color: "white" } }
                },
                scales: {
                    x: { ticks: { color: "white" } },
                    y: {
                        beginAtZero: true,
                        ticks: { color: "white", precision: 0 }
                    }
                }
            }
        });

    } catch (err) {

        console.error("Chart update failed:", err);

    }

}

// Load immediately
loadCharts();

// Refresh every 5 seconds
setInterval(loadCharts, 5000);
