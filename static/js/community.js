/**
 * TrustGuard AI — Community Scam Reports Controller
 * Handles modal dialog interactions, client-side report validation,
 * and asynchronous submission to the moderation review queue.
 */

document.addEventListener("DOMContentLoaded", () => {
    const reportModal = document.getElementById("reportModal");
    const openBtn = document.getElementById("openReportModalBtn");
    const closeBtn = document.getElementById("closeReportModalBtn");
    const cancelBtn = document.getElementById("cancelReportModalBtn");
    const form = document.getElementById("communityReportForm");
    const errorBox = document.getElementById("reportModalError");
    const errorMsg = document.getElementById("reportModalErrorMsg");
    const submitBtn = document.getElementById("submitReportBtn");

    if (!reportModal) return;

    // Open Modal
    const openModal = () => {
        reportModal.style.display = "flex";
        document.body.classList.add("modal-open");
        if (errorBox) errorBox.style.display = "none";
        const catSelect = document.getElementById("reportCategory");
        if (catSelect) catSelect.focus();
    };

    // Close Modal
    const closeModal = () => {
        reportModal.style.display = "none";
        document.body.classList.remove("modal-open");
        if (form) form.reset();
        if (errorBox) errorBox.style.display = "none";
    };

    if (openBtn) openBtn.addEventListener("click", openModal);
    if (closeBtn) closeBtn.addEventListener("click", closeModal);
    if (cancelBtn) cancelBtn.addEventListener("click", closeModal);

    reportModal.addEventListener("click", (e) => {
        if (e.target === reportModal) closeModal();
    });

    // Close on Escape key
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && reportModal.style.display === "flex") {
            closeModal();
        }
    });

    // Form Submission
    if (form) {
        form.addEventListener("submit", async (e) => {
            e.preventDefault();

            if (errorBox) errorBox.style.display = "none";

            const category = document.getElementById("reportCategory").value.trim();
            const scamType = document.getElementById("reportScamType").value.trim();
            const evidence = document.getElementById("reportEvidence").value.trim();
            const description = document.getElementById("reportDescription").value.trim();

            // Client-side Validation
            if (!category) {
                showModalError("Please select a report category.");
                return;
            }
            if (!evidence || evidence.length < 5) {
                showModalError("Please provide the suspicious communication text or URL (at least 5 characters).");
                return;
            }
            if (!description || description.length < 10) {
                showModalError("Please explain what makes this communication suspicious (at least 10 characters).");
                return;
            }

            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Submitting...';

            try {
                const response = await fetch("/api/community/reports", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    body: JSON.stringify({
                        category: category,
                        scam_type: scamType,
                        evidence_snippet: evidence,
                        description: description
                    })
                });

                const data = await response.json();

                if (!response.ok || !data.success) {
                    showModalError(data.error || "An error occurred while submitting your report.");
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Submit Report for Moderation';
                    return;
                }

                // Success Feedback
                form.innerHTML = `
                    <div class="modal-body text-center py-4">
                        <div style="font-size: 3rem; color: #059669; margin-bottom: 12px;">
                            <i class="fa-solid fa-circle-check"></i>
                        </div>
                        <h3 style="font-size: 1.3rem; margin-bottom: 8px;">Report Submitted Successfully</h3>
                        <p class="text-muted text-sm" style="max-width: 440px; margin: 0 auto 16px;">
                            ${escapeHtml(data.message)}
                        </p>
                        <div class="badge badge-suspicious" style="font-size: 0.85rem; padding: 6px 14px;">
                            <i class="fa-solid fa-clock"></i> Status: Pending Safety Review
                        </div>
                    </div>
                    <div class="modal-footer text-center" style="justify-content: center;">
                        <button type="button" class="btn btn-primary" onclick="window.location.reload();">
                            Done
                        </button>
                    </div>
                `;

            } catch (err) {
                console.error("Submission error:", err);
                showModalError("Network error: Could not reach the TrustGuard community server.");
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Submit Report for Moderation';
            }
        });
    }

    function showModalError(msg) {
        if (errorBox && errorMsg) {
            errorMsg.textContent = msg;
            errorBox.style.display = "flex";
        } else {
            alert(msg);
        }
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
});
