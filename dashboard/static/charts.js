// =======================================
// Charts
// =======================================

let severityChart = null;
let ipChart = null;

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

    } catch (err) {

        console.error("Chart update failed:", err);

    }

}

// Load immediately
loadCharts();

// Refresh every 5 seconds
setInterval(loadCharts, 5000);
