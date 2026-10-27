/**
 * TrustGuard AI — Dashboard Controller
 * Initializes Chart.js visualizations for personal threat metrics
 * and powers the scan history modal viewer.
 */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Initialize Chart.js Visualizations
    initDashboardCharts();

    // 2. Setup Scan History Details Modal
    initScanDetailsModal();
});

async function initDashboardCharts() {
    const riskCanvas = document.getElementById("riskDoughnutChart");
    const modalityCanvas = document.getElementById("modalityBarChart");

    if (!riskCanvas || !modalityCanvas) return;

    try {
        const response = await fetch("/api/dashboard/stats");
        if (!response.ok) return;

        const data = await response.json();
        if (!data.success) return;

        // --- Chart 1: Risk Level Distribution (Doughnut) ---
        const riskBreakdown = data.risk_breakdown || { "Low Risk": 0, "Suspicious": 0, "High Risk": 0 };
        const totalScans = (riskBreakdown["Low Risk"] || 0) + (riskBreakdown["Suspicious"] || 0) + (riskBreakdown["High Risk"] || 0);

        new Chart(riskCanvas, {
            type: "doughnut",
            data: {
                labels: ["Low Risk", "Suspicious", "High Risk"],
                datasets: [{
                    data: totalScans > 0 ? [
                        riskBreakdown["Low Risk"] || 0,
                        riskBreakdown["Suspicious"] || 0,
                        riskBreakdown["High Risk"] || 0
                    ] : [1, 0, 0], // Fallback preview if 0 scans
                    backgroundColor: [
                        "#059669", // Emerald Green
                        "#d97706", // Amber
                        "#dc2626"  // Crimson Red
                    ],
                    borderWidth: 2,
                    borderColor: "#ffffff",
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "70%",
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            font: { family: "'Plus Jakarta Sans', sans-serif", size: 12, weight: 600 },
                            padding: 16,
                            usePointStyle: true,
                            boxWidth: 8
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return ` ${context.label}: ${context.raw} scan(s)`;
                            }
                        }
                    }
                }
            }
        });

        // --- Chart 2: Modality Distribution (Bar) ---
        const modality = data.modality_breakdown || {};
        const labels = Object.keys(modality);
        const counts = Object.values(modality);

        new Chart(modalityCanvas, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    label: "Scans",
                    data: counts,
                    backgroundColor: "#3b82f6",
                    hoverBackgroundColor: "#1d4ed8",
                    borderRadius: 6,
                    maxBarThickness: 36
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1,
                            font: { family: "'Plus Jakarta Sans', sans-serif", size: 11 }
                        },
                        grid: {
                            color: "#f1f5f9"
                        }
                    },
                    x: {
                        grid: { display: false },
                        ticks: {
                            font: { family: "'Plus Jakarta Sans', sans-serif", size: 11 }
                        }
                    }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: (context) => ` ${context.raw} scan(s)`
                        }
                    }
                }
            }
        });

    } catch (err) {
        console.warn("Could not render dashboard charts:", err);
    }
}

function initScanDetailsModal() {
    const modal = document.getElementById("scanDetailModal");
    const modalCloseBtn = document.getElementById("modalCloseBtn");
    const modalDismissBtn = document.getElementById("modalDismissBtn");
    const modalBody = document.getElementById("modalBody");

    if (!modal) return;

    // Close handlers
    const closeModal = () => {
        modal.style.display = "none";
        document.body.classList.remove("modal-open");
    };
    if (modalCloseBtn) modalCloseBtn.addEventListener("click", closeModal);
    if (modalDismissBtn) modalDismissBtn.addEventListener("click", closeModal);
    modal.addEventListener("click", (e) => {
        if (e.target === modal) closeModal();
    });
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && modal.style.display === "flex") {
            closeModal();
        }
    });

    // View Details buttons in table
    document.querySelectorAll(".view-scan-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
            const scanId = btn.dataset.scanId;
            if (!scanId) return;

            modal.style.display = "flex";
            document.body.classList.add("modal-open");
            modalBody.innerHTML = `
                <div class="loading-spinner-center">
                    <i class="fa-solid fa-spinner fa-spin"></i> Loading scan #${scanId} details...
                </div>
            `;

            try {
                const res = await fetch(`/api/scan/${scanId}`);
                if (!res.ok) throw new Error("Failed to retrieve scan record.");
                const json = await res.json();
                if (!json.success) throw new Error(json.error || "Record not found.");

                renderModalContent(json.data);
            } catch (err) {
                modalBody.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="fa-solid fa-triangle-exclamation"></i>
                        <span>${err.message || 'Error loading scan details.'}</span>
                    </div>
                `;
            }
        });
    });

    function renderModalContent(scan) {
        let badgeClass = "badge-low";
        if (scan.risk_score >= 70) badgeClass = "badge-high";
        else if (scan.risk_score >= 30) badgeClass = "badge-suspicious";

        const flags = Array.isArray(scan.detected_flags) ? scan.detected_flags : [];
        const recs = Array.isArray(scan.recommendations) ? scan.recommendations : [];

        let flagsHtml = "";
        if (flags.length > 0) {
            flagsHtml = flags.map(f => `
                <div class="flag-card ${f.flag.includes('Credential') || f.flag.includes('Bare IP') ? 'flag-high' : ''}" style="margin-bottom: 8px;">
                    <div class="flag-icon"><i class="fa-solid fa-triangle-exclamation"></i></div>
                    <div class="flag-content">
                        <div class="flag-header">
                            <span class="flag-name">${escapeHtml(f.flag)}</span>
                            <span class="flag-cat">${escapeHtml(f.category || 'Indicator')}</span>
                        </div>
                        <div class="flag-desc">${escapeHtml(f.description)}</div>
                    </div>
                </div>
            `).join("");
        } else {
            flagsHtml = `
                <div class="no-flags-box" style="padding: 10px 14px;">
                    <i class="fa-solid fa-circle-check"></i>
                    <span>No heuristic warning triggers detected.</span>
                </div>
            `;
        }

        let recsHtml = recs.map(r => `
            <li class="rec-item" style="padding: 8px 12px; margin-bottom: 6px;">
                <i class="fa-solid fa-shield-check"></i> <span>${escapeHtml(r)}</span>
            </li>
        `).join("");

        modalBody.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;">
                <div>
                    <span class="badge badge-type">${scan.scan_type.toUpperCase()}</span>
                    <span style="font-size: 0.8rem; color: #64748b; margin-left: 8px;">Record #${scan.id}</span>
                </div>
                <div>
                    <span class="badge badge-risk ${badgeClass}">${scan.risk_level} (${scan.risk_score}/100)</span>
                </div>
            </div>

            <div class="snippet-box" style="margin-bottom: 18px;">
                <span class="snippet-label">Input Snippet:</span>
                <p class="snippet-content">${escapeHtml(scan.input_snippet)}</p>
            </div>

            <div style="margin-bottom: 18px;">
                <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 10px;">
                    <i class="fa-solid fa-triangle-exclamation"></i> Triggered Security Flags
                </h4>
                ${flagsHtml}
            </div>

            <div style="margin-bottom: 18px;">
                <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 10px;">
                    <i class="fa-solid fa-shield-check"></i> Safety Recommendations
                </h4>
                <ul class="recs-list" style="gap: 4px;">${recsHtml}</ul>
            </div>

            <div class="result-disclaimer-box" style="margin-bottom: 0;">
                <i class="fa-solid fa-circle-info"></i>
                <div class="disclaimer-text">
                    This risk assessment represents probabilistic pattern recognition and does not constitute a confirmed legal or cybersecurity guarantee.
                </div>
            </div>
        `;
    }

    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
}
