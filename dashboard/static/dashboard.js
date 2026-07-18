async function loadAlerts() {

    try {

        const response = await fetch("/api/alerts");

        const data = await response.json();

        // Update counters
        document.getElementById("high-count").textContent = data.high;
        document.getElementById("medium-count").textContent = data.medium;
        document.getElementById("low-count").textContent = data.low;
        document.getElementById("total-count").textContent = data.total;

        // Update alert table
        const table = document.getElementById("alerts-table");

        table.innerHTML = "";

        data.alerts.forEach(alert => {

            let badge = "bg-success";

            if (alert.severity === "HIGH") {
                badge = "bg-danger";
            } else if (alert.severity === "MEDIUM") {
                badge = "bg-warning text-dark";
            }

            table.innerHTML += `
                <tr>
                    <td>${alert.id}</td>
                    <td>${alert.timestamp}</td>
                    <td>${alert.source_ip}</td>
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

    } catch (err) {
        console.error("Dashboard update failed:", err);
    }

}

// Load immediately
loadAlerts();

// Refresh every 5 seconds
setInterval(loadAlerts, 5000);
