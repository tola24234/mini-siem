// ============================================
// Mini-SIEM Dashboard
// Live Dashboard Updates
// ============================================

let searchTimer = null;

function addCell(row, value) {
    const cell = document.createElement("td");
    cell.textContent = value ?? "Unknown";
    row.appendChild(cell);
}

function addSeverityCell(row, severity) {
    const cell = document.createElement("td");
    const badge = document.createElement("span");
    const value = severity ?? "LOW";

    badge.className = "badge bg-success";
    if (value === "HIGH") {
        badge.className = "badge bg-danger";
    } else if (value === "MEDIUM") {
        badge.className = "badge bg-warning text-dark";
    }

    badge.textContent = value;
    cell.appendChild(badge);
    row.appendChild(cell);
}

async function loadAlerts(query = "") {

    try {

        const params = new URLSearchParams();
        if (query) {
            params.set("q", query);
        }
        const response = await fetch(`/api/alerts?${params.toString()}`);

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
        const summary = document.getElementById("search-summary");

        table.replaceChildren();
        summary.textContent = data.query
            ? `${data.matching_total} matching alert${data.matching_total === 1 ? "" : "s"}`
            : "Showing the latest 100 alerts";

        data.alerts.forEach(alert => {
            const row = document.createElement("tr");
            addCell(row, alert.id);
            addCell(row, alert.timestamp);
            addCell(row, alert.source_ip);
            addCell(row, alert.country);
            addCell(row, alert.city);
            addCell(row, alert.isp);
            addCell(row, alert.event_type);
            addSeverityCell(row, alert.severity);
            addCell(row, alert.description);
            table.appendChild(row);
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

document.getElementById("alert-search").addEventListener("input", event => {
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(() => loadAlerts(event.target.value.trim()), 250);
});

// ============================================
// Refresh Every 5 Seconds
// ============================================

setInterval(() => {
    const search = document.getElementById("alert-search");
    loadAlerts(search.value.trim());
}, 5000);
