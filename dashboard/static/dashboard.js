// ============================================
// Mini-SIEM Dashboard
// Live Dashboard Updates
// ============================================

async function loadAlerts() {

    try {

        const response = await fetch("/api/alerts");

        if (!response.ok) {
            throw new Error("Failed to load alerts");
        }

        const data = await response.json();

        // =====================================
        // Update Alert Counters
        // =====================================

        document.getElementById("high-count").textContent = data.high;
        document.getElementById("medium-count").textContent = data.medium;
        document.getElementById("low-count").textContent = data.low;
        document.getElementById("total-count").textContent = data.total;

        // =====================================
        // Update Alert Table
        // =====================================

        const table = document.getElementById("alerts-table");

        table.innerHTML = "";

        data.alerts.forEach(alert => {

            let badge = "bg-success";

            if (alert.severity === "HIGH") {
                badge = "bg-danger";
            }
            else if (alert.severity === "MEDIUM") {
                badge = "bg-warning text-dark";
            }

            table.innerHTML += `
                <tr>

                    <td>${alert.id}</td>

                    <td>${alert.timestamp}</td>

                    <td>${alert.source_ip}</td>

                    <td>${alert.country ?? "Unknown"}</td>

                    <td>${alert.city ?? "Unknown"}</td>

                    <td>${alert.isp ?? "Unknown"}</td>

                    <td>${alert.event_type}</td>

                    <td>
                        <span class="badge ${badge}">
                            ${alert.severity}
                        </span>
                    </td>

                    <td>${alert.description}</td>

                </tr>
            `;
        });

    }

    catch (error) {

        console.error("Dashboard update failed:", error);

    }

}

// ============================================
// Initial Load
// ============================================

loadAlerts();

// ============================================
// Refresh Every 5 Seconds
// ============================================

setInterval(() => {

    loadAlerts();

}, 5000);
