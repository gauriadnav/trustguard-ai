/**
 * TrustGuard AI — Scanner Frontend Interactions
 * Handles modality tabs (Text, URL, Job Offer, Screenshot Upload),
 * drag-and-drop screenshot uploads, sample scenarios, asynchronous threat evaluation,
 * and dynamic SVG score gauge animation.
 */

document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements - Navigation & Inputs
    const scannerTabs = document.getElementById("scannerTabs");
    const scanTypeInput = document.getElementById("scanType");
    const textInputGroup = document.getElementById("textInputGroup");
    const screenshotInputGroup = document.getElementById("screenshotInputGroup");
    const demoSamples = document.getElementById("demoSamples");
    const scanInput = document.getElementById("scanInput");
    const inputLabel = document.getElementById("inputLabel");
    const scanBtn = document.getElementById("scanBtn");
    const clearBtn = document.getElementById("clearBtn");
    const scanLoading = document.getElementById("scanLoading");
    const loadingSubtitle = document.getElementById("loadingSubtitle");
    const scanError = document.getElementById("scanError");
    const scanErrorMsg = document.getElementById("scanErrorMsg");
    const resultCard = document.getElementById("resultCard");
    const scanAnotherBtn = document.getElementById("scanAnotherBtn");

    // Screenshot Dropzone Elements
    const uploadDropzone = document.getElementById("uploadDropzone");
    const screenshotFile = document.getElementById("screenshotFile");
    const dropzonePrompt = document.getElementById("dropzonePrompt");
    const filePreviewCard = document.getElementById("filePreviewCard");
    const previewThumbnail = document.getElementById("previewThumbnail");
    const previewFilename = document.getElementById("previewFilename");
    const previewFilesize = document.getElementById("previewFilesize");
    const removeFileBtn = document.getElementById("removeFileBtn");

    // Result Card Elements
    const resBadgeType = document.getElementById("resBadgeType");
    const resTimestamp = document.getElementById("resTimestamp");
    const resAuthStatus = document.getElementById("resAuthStatus");
    const resSnippet = document.getElementById("resSnippet");
    const resOcrSection = document.getElementById("resOcrSection");
    const resOcrText = document.getElementById("resOcrText");
    const resOcrCharCount = document.getElementById("resOcrCharCount");
    const resScore = document.getElementById("resScore");
    const resRiskBadge = document.getElementById("resRiskBadge");
    const gaugeCircle = document.getElementById("gaugeCircle");
    const resMlProb = document.getElementById("resMlProb");
    const resMlBar = document.getElementById("resMlBar");
    const resConfidence = document.getElementById("resConfidence");
    const resConfBar = document.getElementById("resConfBar");
    const resVerdictText = document.getElementById("resVerdictText");
    const resFlagsList = document.getElementById("resFlagsList");
    const resRecsList = document.getElementById("resRecsList");
    const resDisclaimer = document.getElementById("resDisclaimer");

    // Language Intelligence Elements
    const languageSelect = document.getElementById("languageSelect");
    const resLanguageNotice = document.getElementById("resLanguageNotice");
    const resLangBadge = document.getElementById("resLangBadge");
    const resLangMode = document.getElementById("resLangMode");
    const resLangNote = document.getElementById("resLangNote");

    // Preset Sample Scenarios for Testing / Viva Demonstration
    const sampleScenarios = {
        phishing: {
            type: "email",
            lang: "en",
            text: "URGENT SECURITY ALERT: Your Chase online banking account has been temporarily restricted due to suspicious login attempts. Verify your password, SSN, and 6-digit PIN immediately within 24 hours at http://192.168.1.105/chase-verify to restore access."
        },
        job_scam: {
            type: "job_offer",
            lang: "en",
            text: "Congratulations! You have been selected for our Remote Executive Software Intern role. Earn $1,200 per day with no previous experience required. To finalize your onboarding paperwork and receive company equipment, please submit a $150 registration fee via Steam gift card or Bitcoin."
        },
        spoofed_url: {
            type: "url",
            lang: "en",
            text: "http://paypal.com.verify-security-account.xyz/login"
        },
        spanish_phishing: {
            type: "text",
            lang: "es",
            text: "ALERTA URGENTE: Su cuenta de banco ha sido suspendida. Ingrese su contraseña y verifique su PIN inmediatamente dentro de 24 horas en http://banco-seguro-verificar.xyz para restaurar acceso."
        },
        french_phishing: {
            type: "email",
            lang: "fr",
            text: "URGENT: Votre compte bancaire est suspendu suite à une activité suspecte. Entrez votre mot de passe et confirmez vos identifiants immédiatement dans les 24 heures."
        },
        safe_message: {
            type: "text",
            lang: "en",
            text: "Hi Alex, please remember to bring your laptop and review chapter 4 before our group project discussion tomorrow at 2:00 PM in the library."
        }
    };

    // Tab Configurations for Text Inputs
    const tabConfigs = {
        text: {
            label: "Paste suspicious communication or message text:",
            placeholder: "Paste SMS messages, WhatsApp messages, or direct messages here..."
        },
        url: {
            label: "Enter the suspicious website URL or link:",
            placeholder: "e.g., http://paypal.com.verify-billing-account.xyz/login"
        },
        job_offer: {
            label: "Paste the job or internship offer message or compensation details:",
            placeholder: "Paste the recruitment email, WhatsApp job offer, or stipend details here..."
        }
    };

    // 1. Modality Tab Switching
    if (scannerTabs) {
        scannerTabs.addEventListener("click", (e) => {
            const btn = e.target.closest(".tab-btn");
            if (!btn) return;

            const selectedType = btn.dataset.type;
            if (!selectedType) return;

            // Update active button
            scannerTabs.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            scanTypeInput.value = selectedType;

            // Reset result and error
            resultCard.style.display = "none";
            scanError.style.display = "none";

            // Modality View Switching: Screenshot vs Text Inputs
            if (selectedType === "screenshot") {
                textInputGroup.style.display = "none";
                screenshotInputGroup.style.display = "block";
                if (loadingSubtitle) {
                    loadingSubtitle.textContent = "Processing image, running Tesseract OCR text extraction, and evaluating threat signals...";
                }
            } else {
                textInputGroup.style.display = "block";
                screenshotInputGroup.style.display = "none";
                if (tabConfigs[selectedType]) {
                    inputLabel.textContent = tabConfigs[selectedType].label;
                    scanInput.placeholder = tabConfigs[selectedType].placeholder;
                }
                if (loadingSubtitle) {
                    loadingSubtitle.textContent = "Running TF-IDF classifier inference, extracting heuristic urgency triggers, and inspecting structural URL patterns.";
                }
            }
        });
    }

    // 2. Screenshot File Upload & Drag-and-Drop Handlers
    if (uploadDropzone && screenshotFile) {
        // Click to open file dialog
        uploadDropzone.addEventListener("click", (e) => {
            if (e.target.closest("#removeFileBtn")) return;
            screenshotFile.click();
        });

        // Drag & Drop visual highlights
        ["dragenter", "dragover"].forEach(eventName => {
            uploadDropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                uploadDropzone.classList.add("drag-over");
            }, false);
        });

        ["dragleave", "drop"].forEach(eventName => {
            uploadDropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                uploadDropzone.classList.remove("drag-over");
            }, false);
        });

        uploadDropzone.addEventListener("drop", (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files && files.length > 0) {
                handleSelectedFile(files[0]);
            }
        });

        screenshotFile.addEventListener("change", (e) => {
            if (e.target.files && e.target.files.length > 0) {
                handleSelectedFile(e.target.files[0]);
            }
        });
    }

    function handleSelectedFile(file) {
        const allowedExtensions = [".png", ".jpg", ".jpeg", ".webp"];
        const fileExt = "." + file.name.split(".").pop().toLowerCase();

        if (!allowedExtensions.includes(fileExt)) {
            showError(`Invalid file format '${fileExt}'. Please select a PNG, JPG, JPEG, or WEBP image.`);
            resetFileInput();
            return;
        }

        if (file.size > 5 * 1024 * 1024) {
            showError(`Selected file is too large (${(file.size / (1024 * 1024)).toFixed(1)}MB). Maximum allowed size is 5MB.`);
            resetFileInput();
            return;
        }

        scanError.style.display = "none";
        previewFilename.textContent = file.name;
        previewFilesize.textContent = formatBytes(file.size);

        // Render image thumbnail
        const reader = new FileReader();
        reader.onload = (e) => {
            previewThumbnail.src = e.target.result;
            dropzonePrompt.style.display = "none";
            filePreviewCard.style.display = "flex";
        };
        reader.readAsDataURL(file);
    }

    if (removeFileBtn) {
        removeFileBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            resetFileInput();
        });
    }

    function resetFileInput() {
        if (screenshotFile) screenshotFile.value = "";
        if (previewThumbnail) previewThumbnail.src = "";
        if (dropzonePrompt) dropzonePrompt.style.display = "block";
        if (filePreviewCard) filePreviewCard.style.display = "none";
    }

    function formatBytes(bytes) {
        if (bytes === 0) return "0 Bytes";
        const k = 1024;
        const sizes = ["Bytes", "KB", "MB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
    }

    // 3. Demo Sample Fill Buttons
    document.querySelectorAll(".sample-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const sampleKey = btn.dataset.sample;
            const scenario = sampleScenarios[sampleKey];
            if (!scenario) return;

            // Switch to corresponding text tab
            const targetTab = scannerTabs.querySelector(`.tab-btn[data-type="${scenario.type}"]`) ||
                              scannerTabs.querySelector('.tab-btn[data-type="text"]');
            if (targetTab) targetTab.click();

            if (scenario.lang && languageSelect) {
                languageSelect.value = scenario.lang;
            }

            // Populate text
            scanInput.value = scenario.text;
            scanInput.focus();

            resultCard.style.display = "none";
            scanError.style.display = "none";
        });
    });

    // 4. Clear Button
    if (clearBtn) {
        clearBtn.addEventListener("click", () => {
            scanInput.value = "";
            resetFileInput();
            resultCard.style.display = "none";
            scanError.style.display = "none";
            scanInput.focus();
        });
    }

    // 5. Scan Another Button
    if (scanAnotherBtn) {
        scanAnotherBtn.addEventListener("click", () => {
            if (scanTypeInput.value === "screenshot") {
                uploadDropzone.scrollIntoView({ behavior: "smooth", block: "center" });
            } else {
                scanInput.focus();
                scanInput.select();
                window.scrollTo({ top: scanInput.offsetTop - 120, behavior: "smooth" });
            }
        });
    }

    // 6. Submit Scan Execution
    if (scanBtn) {
        scanBtn.addEventListener("click", executeScan);
    }

    // Allow Ctrl+Enter to trigger scan
    if (scanInput) {
        scanInput.addEventListener("keydown", (e) => {
            if (e.ctrlKey && e.key === "Enter") {
                executeScan();
            }
        });
    }

    async function executeScan() {
        const scanType = scanTypeInput.value;
        const selectedLang = languageSelect ? languageSelect.value : "auto";

        // Reset UI states
        scanError.style.display = "none";
        resultCard.style.display = "none";

        let fetchOptions = {};

        if (scanType === "screenshot") {
            if (!screenshotFile.files || screenshotFile.files.length === 0) {
                showError("Please select or drop a screenshot image file to analyze.");
                return;
            }

            const file = screenshotFile.files[0];
            const formData = new FormData();
            formData.append("screenshot", file);
            formData.append("scan_type", "screenshot");
            formData.append("language", selectedLang);

            fetchOptions = {
                method: "POST",
                body: formData
                // Note: Content-Type header must NOT be manually set for FormData (browser sets boundary)
            };
        } else {
            const content = scanInput.value.trim();
            if (!content) {
                showError("Please enter or paste content before running the analysis.");
                scanInput.focus();
                return;
            }

            fetchOptions = {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    content: content,
                    scan_type: scanType,
                    language: selectedLang
                })
            };
        }

        scanLoading.style.display = "block";
        scanBtn.disabled = true;

        try {
            const response = await fetch("/api/scan", fetchOptions);
            const resData = await response.json();

            if (!response.ok || !resData.success) {
                throw new Error(resData.error || "An error occurred during threat analysis.");
            }

            // Render successful scan report
            renderScanResult(resData.data);

        } catch (err) {
            console.error("Scan error:", err);
            showError(err.message || "Failed to reach the threat detection engine.");
        } finally {
            scanLoading.style.display = "none";
            scanBtn.disabled = false;
        }
    }

    function showError(message) {
        scanErrorMsg.textContent = message;
        scanError.style.display = "flex";
        scanLoading.style.display = "none";
        scanError.scrollIntoView({ behavior: "smooth", block: "center" });
    }

    function renderScanResult(data) {
        // 1. Header Information
        const typeLabels = {
            text: "Text / SMS Analysis",
            email: "Email Analysis",
            url: "URL Pattern Forensics",
            job_offer: "Recruitment Pattern Analysis",
            screenshot: "OCR Screenshot Analysis"
        };
        resBadgeType.textContent = typeLabels[data.scan_type] || "Threat Analysis";
        resTimestamp.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        // Authenticated vs Guest indicator
        if (data.is_authenticated) {
            resAuthStatus.className = "auth-pill saved";
            resAuthStatus.innerHTML = '<i class="fa-solid fa-cloud-arrow-up"></i> Saved to Account History';
        } else {
            resAuthStatus.className = "auth-pill guest";
            resAuthStatus.innerHTML = '<i class="fa-solid fa-user-ninja"></i> Guest Scan (Not Saved to Profile)';
        }

        // Snippet Preview
        resSnippet.textContent = data.input_snippet || "(No content preview)";

        // Language Notice Banner
        if (data.language_info && resLanguageNotice) {
            resLanguageNotice.style.display = "flex";
            if (resLangBadge) resLangBadge.innerHTML = `<i class="fa-solid fa-language"></i> ${escapeHtml(data.language_info.name)}`;
            if (resLangMode) resLangMode.textContent = data.language_info.mode;
            if (resLangNote) resLangNote.textContent = data.language_info.note;
        } else if (resLanguageNotice) {
            resLanguageNotice.style.display = "none";
        }

        // Extracted OCR Text Box (Visible for screenshots)
        if (data.extracted_text) {
            resOcrSection.style.display = "block";
            resOcrText.textContent = data.extracted_text;
            resOcrCharCount.textContent = `${data.extracted_text.length} characters extracted via OCR`;
        } else {
            resOcrSection.style.display = "none";
        }

        // 2. Score Gauge & Risk Categorization
        const score = Math.max(0, Math.min(100, data.risk_score || 0));
        animateScore(score);

        // Update Gauge & Badge Colors
        let strokeColor = "#059669"; // Green
        let riskClass = "badge-low";
        let verdict = "No prominent threat indicators detected. Standard digital vigilance is still recommended.";

        if (score >= 70) {
            strokeColor = "#dc2626"; // Red
            riskClass = "badge-high";
            verdict = "Multiple high-risk scam characteristics detected. Interaction, payment, or credential sharing is strongly discouraged.";
        } else if (score >= 30) {
            strokeColor = "#d97706"; // Amber
            riskClass = "badge-suspicious";
            verdict = "Elevated suspicion: questionable patterns or pressure indicators detected. Verify through independent channels.";
        }

        gaugeCircle.style.stroke = strokeColor;
        resRiskBadge.className = `badge badge-risk ${riskClass}`;
        resRiskBadge.textContent = data.risk_level;
        resVerdictText.textContent = verdict;

        // SVG stroke offset (circumference = 2 * PI * 50 = 314.159)
        const circumference = 314.159;
        const offset = circumference * (1 - (score / 100));
        gaugeCircle.style.strokeDashoffset = offset;

        // 3. Metrics Bars
        if (data.ml_applied) {
            const mlPercentage = (data.ml_probability * 100).toFixed(1);
            resMlProb.textContent = `${mlPercentage}%`;
            resMlBar.style.width = `${Math.min(100, mlPercentage)}%`;
            resMlBar.style.backgroundColor = strokeColor;
        } else {
            resMlProb.textContent = "N/A (Bypassed)";
            resMlBar.style.width = "0%";
        }

        const confPercentage = Math.round((data.confidence_score || 0.5) * 100);
        resConfidence.textContent = `${confPercentage}%`;
        resConfBar.style.width = `${confPercentage}%`;

        // 4. Detected Flags List
        resFlagsList.innerHTML = "";
        const flags = data.detected_flags || [];

        if (flags.length > 0) {
            flags.forEach(flag => {
                const flagCard = document.createElement("div");
                const isHigh = flag.flag.includes("Credential") || flag.flag.includes("Untraceable") || flag.flag.includes("Bare IP");
                flagCard.className = `flag-card ${isHigh ? 'flag-high' : ''}`;

                flagCard.innerHTML = `
                    <div class="flag-icon">
                        <i class="fa-solid fa-triangle-exclamation"></i>
                    </div>
                    <div class="flag-content">
                        <div class="flag-header">
                            <span class="flag-name">${escapeHtml(flag.flag)}</span>
                            <span class="flag-cat">${escapeHtml(flag.category || 'Indicator')}</span>
                        </div>
                        <div class="flag-desc">${escapeHtml(flag.description)}</div>
                    </div>
                `;
                resFlagsList.appendChild(flagCard);
            });
        } else {
            resFlagsList.innerHTML = `
                <div class="no-flags-box">
                    <i class="fa-solid fa-circle-check"></i>
                    <span>No heuristic warning triggers or deceptive domain patterns were detected.</span>
                </div>
            `;
        }

        // 5. Recommendations List
        resRecsList.innerHTML = "";
        const recs = data.recommendations || [];
        recs.forEach(rec => {
            const li = document.createElement("li");
            li.className = "rec-item";
            li.innerHTML = `<i class="fa-solid fa-shield-check"></i> <span>${escapeHtml(rec)}</span>`;
            resRecsList.appendChild(li);
        });

        // 6. Disclaimer
        resDisclaimer.textContent = data.disclaimer || "TrustGuard AI provides probabilistic risk indicators.";

        // Reveal result card with smooth scroll
        resultCard.style.display = "block";
        resultCard.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function animateScore(targetScore) {
        let current = 0;
        const duration = 600; // ms
        const steps = 30;
        const stepTime = duration / steps;
        const increment = targetScore / steps;

        const timer = setInterval(() => {
            current += increment;
            if (current >= targetScore) {
                resScore.textContent = targetScore;
                clearInterval(timer);
            } else {
                resScore.textContent = Math.round(current);
            }
        }, stepTime);
    }

    function escapeHtml(str) {
        if (!str) return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
