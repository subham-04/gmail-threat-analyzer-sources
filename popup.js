// popup.js
document.addEventListener('DOMContentLoaded', () => {
    const analyzeBtn = document.getElementById('analyzeBtn');
    const reanalyzeBtn = document.getElementById('reanalyzeBtn');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const analyzeText = document.getElementById('analyzeText');
    const resultsContainer = document.getElementById('resultsContainer');
    const overallScore = document.getElementById('overallScore');
    const severityText = document.getElementById('severityText');

    // Sender element references
    const senderUsername = document.getElementById('senderUsername');
    const senderDomainName = document.getElementById('senderDomainName');
    const senderDomainDisplay = document.getElementById('senderDomainDisplay');
    const domainScoreDisplay = document.getElementById('domainScoreDisplay');
    const domainOverallScore = document.getElementById('domainOverallScore');
    const urlCount = document.getElementById('urlCount');
    const urlOverallScore = document.getElementById('urlOverallScore');
    const attachmentCount = document.getElementById('attachmentCount');
    const filehashOverallScore = document.getElementById('filehashOverallScore'); // This will always be 0 or N/A

    // Email content elements
    const emailSubject = document.getElementById('emailSubject');
    const emailBody = document.getElementById('emailBody');

    const apiKeyInput = document.getElementById('apiKeyInput');
    const apiKeyStatus = document.getElementById('apiKeyStatus');
    const rememberApiKeyCheckbox = document.getElementById('rememberApiKey');
    const rememberApiKeyLabel = document.getElementById('rememberApiKeyLabel'); // Reference to the label for styling disabled state

    // Function to update API key status and checkbox state
    function updateApiKeyStatus(message, isSuccess, shouldSave, apiKey) {
        apiKeyStatus.textContent = message;
        if (isSuccess) {
            apiKeyStatus.classList.remove('has-text-danger');
            apiKeyStatus.classList.add('has-text-success');
        } else {
            apiKeyStatus.classList.remove('has-text-success');
            apiKeyStatus.classList.add('has-text-danger');
        }

        if (shouldSave) {
            chrome.storage.sync.set({ virustotalApiKey: apiKey });
        } else {
            chrome.storage.sync.remove('virustotalApiKey');
        }
    }

    // Load API Key from storage and set checkbox state on load
    chrome.storage.sync.get('virustotalApiKey', (data) => {
        if (data.virustotalApiKey) {
            apiKeyInput.value = data.virustotalApiKey;
            rememberApiKeyCheckbox.checked = true;
            updateApiKeyStatus('API Key loaded.', true, true, data.virustotalApiKey);
        } else {
            apiKeyInput.value = '';
            rememberApiKeyCheckbox.checked = false;
            updateApiKeyStatus('No API Key saved. Please enter one.', false, false, '');
        }
        // Initially disable/enable checkbox based on input field content
        rememberApiKeyCheckbox.disabled = !apiKeyInput.value.trim();
        if (rememberApiKeyCheckbox.disabled) {
            rememberApiKeyLabel.classList.add('checkbox[disabled]');
        } else {
            rememberApiKeyLabel.classList.remove('checkbox[disabled]');
        }
    });

    // Event listener for API Key input field to enable/disable checkbox
    apiKeyInput.addEventListener('input', () => {
        const currentApiKey = apiKeyInput.value.trim();
        if (currentApiKey) {
            rememberApiKeyCheckbox.disabled = false;
            rememberApiKeyLabel.classList.remove('checkbox[disabled]');
            // If user types something, but checkbox was unchecked, update status
            if (!rememberApiKeyCheckbox.checked && apiKeyStatus.textContent === 'No API Key saved. Please enter one.') {
                 updateApiKeyStatus('API Key entered. Check "Remember" to save.', true, false, '');
            }
        } else {
            rememberApiKeyCheckbox.disabled = true;
            rememberApiKeyLabel.classList.add('checkbox[disabled]');
            // If input becomes empty, uncheck the box and remove key from storage
            if (rememberApiKeyCheckbox.checked) {
                rememberApiKeyCheckbox.checked = false;
                updateApiKeyStatus('API Key removed. Not saved for future sessions.', false, false, '');
            } else {
                updateApiKeyStatus('API Key cannot be empty. Removed from storage.', false, false, '');
            }
        }
    });

    // Event listener for "Remember API Key" checkbox
    rememberApiKeyCheckbox.addEventListener('change', () => {
        const apiKey = apiKeyInput.value.trim();
        if (rememberApiKeyCheckbox.checked) {
            if (apiKey) {
                updateApiKeyStatus('API Key saved and checked successfully!', true, true, apiKey);
            } else {
                // This case should ideally not happen if checkbox is disabled when input is empty
                rememberApiKeyCheckbox.checked = false; // Prevent checking if input is empty
                updateApiKeyStatus('API Key cannot be empty to save.', false, false, '');
            }
        } else {
            updateApiKeyStatus('API Key not saved for future sessions.', true, false, '');
        }
    });


    // Function to handle analysis
    const performAnalysis = () => {
        const apiKey = apiKeyInput.value.trim();
        if (!apiKey) {
            updateApiKeyStatus('Please enter your VirusTotal API Key first!', false, false, '');
            resetButtons();
            return;
        }

        analyzeText.textContent = 'Analyzing...';
        loadingSpinner.classList.remove('is-hidden');
        analyzeBtn.disabled = true;
        reanalyzeBtn.disabled = true;
        resultsContainer.classList.add('is-hidden'); // Hide previous results

        // Send a message to the content script to extract email data
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0] && tabs[0].url.includes('mail.google.com')) {
                chrome.scripting.executeScript({
                    target: { tabId: tabs[0].id },
                    files: ['content.js']
                }, () => {
                    chrome.tabs.sendMessage(tabs[0].id, { action: 'extractEmailData' }, (response) => {
                        if (chrome.runtime.lastError) {
                            console.error("Error sending message:", chrome.runtime.lastError.message);
                            displayError("Failed to communicate with Gmail page. Please ensure you are on an email page.");
                            resetButtons();
                            return;
                        }

                        if (response && response.success) {
                            console.log("Email data extracted:", response.data);
                            // Send extracted data to background script for VT analysis
                            chrome.runtime.sendMessage({ action: 'analyzeWithVirusTotal', data: response.data, apiKey: apiKey }, (vtResponse) => {
                                if (chrome.runtime.lastError) {
                                    console.error("Error sending message to background:", chrome.runtime.lastError.message);
                                    displayError("Failed to send data for analysis. Check background script.");
                                    resetButtons();
                                    return;
                                }

                                if (vtResponse && vtResponse.success) {
                                    console.log("VirusTotal analysis complete:", vtResponse.results);
                                    displayResults(vtResponse.results);
                                } else {
                                    displayError(vtResponse.error || "VirusTotal analysis failed.");
                                }
                                resetButtons();
                            });
                        } else {
                            displayError(response ? response.error : "Failed to extract email data. Are you viewing an email?");
                            resetButtons();
                        }
                    });
                });
            } else {
                displayError("Please navigate to an email in Gmail to use this extension.");
                resetButtons();
            }
        });
    };

    analyzeBtn.addEventListener('click', performAnalysis);
    reanalyzeBtn.addEventListener('click', performAnalysis);

    function resetButtons() {
        analyzeText.textContent = 'Analyze Email';
        loadingSpinner.classList.add('is-hidden');
        analyzeBtn.disabled = false;
        reanalyzeBtn.disabled = false;
        reanalyzeBtn.classList.remove('is-hidden'); // Show reanalyze button after first analysis
    }

    function displayError(message) {
        resultsContainer.classList.remove('is-hidden');
        overallScore.className = 'notification is-danger has-text-centered is-size-5 has-text-weight-bold p-4';
        overallScore.textContent = 'Error';
        severityText.textContent = message;

        senderUsername.textContent = 'N/A';
        senderDomainName.textContent = '';
        senderDomainDisplay.textContent = 'N/A';
        domainScoreDisplay.textContent = 'N/A';
        domainOverallScore.textContent = 'N/A';
        domainOverallScore.classList.add('score-red');
        urlCount.textContent = 'N/A';
        urlOverallScore.textContent = 'N/A';
        urlOverallScore.classList.add('score-red');
        attachmentCount.textContent = 'N/A';
        filehashOverallScore.textContent = 'N/A';
        filehashOverallScore.classList.add('score-red');
    }

    // Function to copy text to clipboard - Make it globally accessible
    async function copyToClipboard(text) {
        try {
            // Try modern Clipboard API first
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(text);
                console.log('Text copied to clipboard using Clipboard API');
                return true;
            } else {
                // Fallback to deprecated method
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);
                textarea.focus();
                textarea.select();
                try {
                    const result = document.execCommand('copy');
                    console.log('Text copied to clipboard using execCommand');
                    document.body.removeChild(textarea);
                    return result;
                } catch (err) {
                    console.error('Unable to copy to clipboard', err);
                    document.body.removeChild(textarea);
                    throw err;
                }
            }
        } catch (err) {
            console.error('Failed to copy text to clipboard:', err);
            // Show user feedback that copy failed
            alert('Failed to copy to clipboard. Please copy manually.');
            return false;
        }
    }

    // Wrapper function for inline onclick handlers
    function copyToClipboardSync(text, buttonElement) {
        console.log('copyToClipboardSync called with:', text);
        copyToClipboard(text).then(success => {
            console.log('Copy result:', success);
            if (success !== false && buttonElement) {
                const originalText = buttonElement.textContent;
                buttonElement.textContent = 'Copied!';
                setTimeout(() => {
                    buttonElement.textContent = originalText;
                }, 1500);
            }
        }).catch(err => {
            console.error('Copy failed:', err);
            if (buttonElement) {
                const originalText = buttonElement.textContent;
                buttonElement.textContent = 'Failed!';
                setTimeout(() => {
                    buttonElement.textContent = originalText;
                }, 1500);
            }
        });
    }

    // Simple test function
    function testCopy(text) {
        console.log('Testing copy with:', text);
        copyToClipboard(text);
    }

    // Make copyToClipboard function globally accessible
    window.copyToClipboard = copyToClipboard;
    window.copyToClipboardSync = copyToClipboardSync;
    window.testCopy = testCopy;

    function displayResults(results) {
        resultsContainer.classList.remove('is-hidden');

        let totalMaliciousIOCs = 0;
        let totalIOCsAnalyzed = 0;

        // Sender Info
        senderUsername.textContent = results.senderUsername || '[not found]';
        senderDomainName.textContent = results.domain ? results.domain.id : '[not found]';
        
        // New sender domain display - fixed logic
        senderDomainDisplay.textContent = results.domain ? results.domain.id : 'N/A';
        
        // Calculate total properly from available stats
        if (results.domain) {
            const domainTotal = (results.domain.harmless || 0) + (results.domain.malicious || 0) + 
                              (results.domain.suspicious || 0) + (results.domain.undetected || 0) + 
                              (results.domain.timeout || 0);
            domainScoreDisplay.textContent = `${results.domain.malicious || 0}/${domainTotal}`;
        } else {
            domainScoreDisplay.textContent = 'N/A';
        }

        // Domain Score
        let domainMalicious = 0;
        if (results.domain) {
            domainMalicious = results.domain.malicious || 0;
            totalMaliciousIOCs += domainMalicious;
            totalIOCsAnalyzed += (results.domain.harmless || 0) + domainMalicious + (results.domain.suspicious || 0) + (results.domain.undetected || 0) + (results.domain.timeout || 0);
            domainOverallScore.textContent = `${domainMalicious}`;
            if (domainMalicious > 0) {
                domainOverallScore.classList.add('score-red');
            } else {
                domainOverallScore.classList.remove('score-red');
            }
        } else {
            domainOverallScore.textContent = 'N/A'; // Changed from '0' to 'N/A'
            domainOverallScore.classList.remove('score-red');
        }

        // URL Score
        let urlMalicious = 0;
        if (results.urls && results.urls.length > 0) {
            urlMalicious = results.urls.reduce((sum, urlRes) => sum + (urlRes.malicious || 0), 0);
            totalMaliciousIOCs += urlMalicious;
            totalIOCsAnalyzed += results.urls.length; // Each URL is an IOC
            urlCount.textContent = results.urls.length;
            urlOverallScore.textContent = `${urlMalicious}`;
            if (urlMalicious > 0) {
                urlOverallScore.classList.add('score-red');
            } else {
                urlOverallScore.classList.remove('score-red');
            }
        } else {
            urlCount.textContent = '0';
            urlOverallScore.textContent = '0';
            urlOverallScore.classList.remove('score-red');
        }

        // Attachment/Filehash Score with Security Analysis
        let attachmentSecurityScore = 0;
        let criticalAttachments = 0;
        let highRiskAttachments = 0;
        
        if (results.attachments && results.attachments.length > 0) {
            // Calculate security scores based on risk levels
            results.attachments.forEach(attachment => {
                if (attachment.riskLevel === 'CRITICAL') {
                    criticalAttachments++;
                    attachmentSecurityScore += 10; // High score for critical files
                } else if (attachment.riskLevel === 'HIGH') {
                    highRiskAttachments++;
                    attachmentSecurityScore += 5; // Medium score for high risk
                } else if (attachment.riskLevel === 'MEDIUM') {
                    attachmentSecurityScore += 2; // Low score for medium risk
                }
            });
        }
        
        attachmentCount.textContent = results.attachments ? results.attachments.length : '0';
        
        // Display security-based score instead of hash-based score
        if (criticalAttachments > 0 || highRiskAttachments > 0) {
            filehashOverallScore.textContent = `${criticalAttachments + highRiskAttachments} risky`;
            filehashOverallScore.classList.add('score-red');
        } else {
            filehashOverallScore.textContent = '0';
            filehashOverallScore.classList.remove('score-red');
        }


        // Overall Score and Severity (including attachment security analysis)
        let severity = 'Clean';
        let scoreClass = 'severity-clean'; // Custom class for background color

        // Factor in attachment security risks
        if (criticalAttachments > 0) {
            severity = 'High';
            scoreClass = 'severity-high';
        } else if (totalMaliciousIOCs > 0 || highRiskAttachments > 0) {
            if (domainMalicious > 5 || urlMalicious > 5 || highRiskAttachments > 2) {
                severity = 'High';
                scoreClass = 'severity-high';
            } else if (domainMalicious > 0 || urlMalicious > 0 || highRiskAttachments > 0) {
                severity = 'Medium';
                scoreClass = 'severity-medium';
            }
        } else if (totalIOCsAnalyzed > 0 || attachmentSecurityScore > 0) {
            severity = 'Clean';
            scoreClass = 'severity-clean';
        } else {
            severity = 'No indicators found or analyzed.';
            scoreClass = 'notification is-light'; // Bulma neutral for no data
        }

        overallScore.className = `notification has-text-centered is-size-5 has-text-weight-bold p-4 ${scoreClass}`;
        overallScore.textContent = `Total Malicious IOCs: ${totalMaliciousIOCs}`;
        severityText.textContent = severity;
        
        // Populate email content
        if (results.emailData) {
            emailSubject.textContent = results.emailData.subject || 'No subject available';
            emailBody.textContent = results.emailData.bodyText || 'No email body available';
        } else {
            emailSubject.textContent = 'No subject available';
            emailBody.textContent = 'No email body available';
        }
        
        // Store results globally for side panel access
        window.lastAnalysisResults = results;
    }

    // Side Panel Functionality
    const sidePanel = document.getElementById('sidePanel');
    const sidePanelOverlay = document.getElementById('sidePanelOverlay');
    const closeSidePanel = document.getElementById('closeSidePanel');
    const sidePanelTitle = document.getElementById('sidePanelTitle');
    const sidePanelBody = document.getElementById('sidePanelBody');

    // View All button references
    const viewAllDomains = document.getElementById('viewAllDomains');
    const viewAllUrls = document.getElementById('viewAllUrls');
    const viewAllAttachments = document.getElementById('viewAllAttachments');

    // Function to open side panel
    function openSidePanel() {
        sidePanel.classList.add('show');
        sidePanelOverlay.classList.add('show');
        document.body.style.overflow = 'hidden';
    }

    // Function to close side panel
    function closeSidePanelFunc() {
        sidePanel.classList.remove('show');
        sidePanelOverlay.classList.remove('show');
        document.body.style.overflow = 'auto';
    }

    // Safe HTML function to prevent XSS - using DOMParser for security
    function safeSetHTML(element, htmlString) {
        // Clear existing content
        element.replaceChildren();
        
        try {
            // Use DOMParser for safer HTML parsing
            const parser = new DOMParser();
            const doc = parser.parseFromString(htmlString, 'text/html');
            
            // Move all child nodes from the parsed document body to the target element
            const bodyContent = doc.body;
            while (bodyContent.firstChild) {
                element.appendChild(bodyContent.firstChild);
            }
        } catch (error) {
            console.error('Error parsing HTML:', error);
            // Fallback to text content only
            element.textContent = htmlString.replace(/<[^>]*>/g, '');
        }
    }

    // Function to reset side panel content
    function resetSidePanel() {
        console.log('Resetting side panel content');
        sidePanelTitle.textContent = '';
        sidePanelBody.replaceChildren();
    }

    // Function to get severity color based on malicious score
    function getSeverityColor(malicious, total) {
        if (malicious === 0) return 'severity-clean';
        const ratio = malicious / total;
        if (ratio <= 0.1) return 'severity-low';
        if (ratio <= 0.3) return 'severity-medium';
        return 'severity-high';
    }

    // Function to show all domains in side panel
    function showAllDomains() {
        if (!window.lastAnalysisResults || !window.lastAnalysisResults.domain) {
            sidePanelBody.replaceChildren();
            const noDataParagraph = document.createElement('p');
            noDataParagraph.className = 'has-text-light';
            noDataParagraph.textContent = 'No domain data available.';
            sidePanelBody.appendChild(noDataParagraph);
            return;
        }

        const domain = window.lastAnalysisResults.domain;
        const total = (domain.harmless || 0) + (domain.malicious || 0) + (domain.suspicious || 0) + (domain.undetected || 0) + (domain.timeout || 0);
        const severityClass = getSeverityColor(domain.malicious || 0, total);
        const isMalicious = (domain.malicious || 0) > 0;
        const isSuspicious = (domain.suspicious || 0) > 0;

        // Determine domain status and color
        let statusIcon = '🌐';
        let statusText = 'Clean';
        let statusColor = 'var(--color-success)';
        
        if (domain.error) {
            statusIcon = '❌';
            statusText = 'Analysis Error';
            statusColor = 'var(--color-light)';
        } else if (isMalicious) {
            statusIcon = '🚨';
            statusText = 'Malicious';
            statusColor = 'var(--color-danger)';
        } else if (isSuspicious) {
            statusIcon = '⚠️';
            statusText = 'Suspicious';
            statusColor = 'var(--color-warning)';
        } else if (total > 0) {
            statusIcon = '✅';
            statusText = 'Clean';
            statusColor = 'var(--color-success)';
        } else {
            statusIcon = '❓';
            statusText = 'Unknown';
            statusColor = 'var(--color-light)';
        }

        sidePanelTitle.textContent = 'Domain Analysis Details';
        console.log('Setting side panel title to: Domain Analysis Details');
        
        // Add domain security summary at the top
        let summaryHtml = '<div class="side-panel-item" style="margin-bottom: 1.5rem; background: var(--color-bg-variant); border: 2px solid var(--color-primary);">';
        summaryHtml += '<div class="side-panel-item-header"><span class="side-panel-item-title">🌐 Domain Security Analysis Summary</span></div>';
        summaryHtml += '<div class="side-panel-item-details" style="font-size: 0.85rem;">';
        if (isMalicious) {
            summaryHtml += `<p style="color: var(--color-danger); font-weight: bold;">🔴 MALICIOUS: Domain flagged by ${domain.malicious} security engines</p>`;
        }
        if (isSuspicious) {
            summaryHtml += `<p style="color: var(--color-warning); font-weight: bold;">🟡 SUSPICIOUS: Domain flagged by ${domain.suspicious} security engines</p>`;
        }
        if (!isMalicious && !isSuspicious && total > 0) {
            summaryHtml += `<p style="color: var(--color-success);">🟢 CLEAN: Domain verified by ${total} security engines</p>`;
        }
        if (domain.error) {
            summaryHtml += `<p style="color: var(--color-light);">❌ ERROR: ${domain.error}</p>`;
        }
        summaryHtml += '</div></div>';

        const domainDetails = `
            <div class="side-panel-item ${isMalicious ? 'malicious' : ''}">
                <div class="side-panel-item-header">
                    <span class="side-panel-item-title" style="color: ${statusColor};">${statusIcon} ${domain.id}</span>
                    <span class="side-panel-item-score ${severityClass}">${domain.malicious || 0}/${total}</span>
                </div>
                <div class="side-panel-url-container">
                    <div class="side-panel-url-display has-text-light" style="max-height: 4.5rem; overflow-y: auto; padding: 0.75rem; background: var(--bulma-black-bis); border: 1px solid ${statusColor}; border-radius: 6px; font-size: 0.8rem; line-height: 1.4; word-break: break-all; position: relative; padding-right: 3rem;">
                        ${domain.id}
                        <button class="button side-panel-copy-btn" data-copy-text="${domain.id}" style="position: absolute; top: 0.5rem; right: 0.5rem; z-index: 10; min-width: 1.5rem; height: 1.2rem; padding: 0.2rem; font-size: 0.6rem; background: rgba(122, 122, 122, 0.3); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); border: 1px solid rgba(255, 255, 255, 0.1); color: rgba(255, 255, 255, 0.9);">
                            ⧉
                        </button>
                    </div>
                </div>
                <div class="side-panel-item-details mt-3">
                    <p><strong style="color: ${statusColor};">Status:</strong> ${statusText}</p>
                    <p><strong>Domain:</strong> ${domain.id}</p>
                    ${domain.error ? 
                        `<p style="color: var(--color-danger);"><strong>Error:</strong> ${domain.error}</p>` : 
                        `<div class="mt-2">
                            <p><strong>Security Engine Results:</strong></p>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin-top: 0.5rem; font-size: 0.8rem;">
                                <div style="background: rgba(35, 209, 96, 0.2); padding: 0.3rem; border-radius: 4px;">
                                    <strong style="color: var(--color-success);">✅ Harmless:</strong> ${domain.harmless || 0}
                                </div>
                                <div style="background: rgba(255, 56, 96, 0.2); padding: 0.3rem; border-radius: 4px;">
                                    <strong style="color: var(--color-danger);">🚨 Malicious:</strong> ${domain.malicious || 0}
                                </div>
                                <div style="background: rgba(255, 221, 87, 0.2); padding: 0.3rem; border-radius: 4px;">
                                    <strong style="color: var(--color-warning);">⚠️ Suspicious:</strong> ${domain.suspicious || 0}
                                </div>
                                <div style="background: rgba(122, 122, 122, 0.2); padding: 0.3rem; border-radius: 4px;">
                                    <strong style="color: var(--color-light);">❓ Undetected:</strong> ${domain.undetected || 0}
                                </div>
                            </div>
                            ${(domain.timeout || 0) > 0 ? `<p style="color: var(--color-light); margin-top: 0.5rem;"><strong>⏱️ Timeout:</strong> ${domain.timeout}</p>` : ''}
                            <div class="mt-3">
                                <p><strong>Domain Risk Assessment:</strong></p>
                                <div style="background: rgba(72, 95, 199, 0.1); padding: 0.5rem; border-radius: 6px; margin-top: 0.5rem;">
                                    ${isMalicious ? 
                                        `<p style="color: var(--color-danger); font-weight: bold;">⚠️ HIGH RISK: This domain has been flagged as malicious by ${domain.malicious} security engines. Emails from this domain may contain phishing attempts, malware, or other threats.</p>` :
                                        isSuspicious ?
                                        `<p style="color: var(--color-warning); font-weight: bold;">⚠️ MEDIUM RISK: This domain has been flagged as suspicious by ${domain.suspicious} security engines. Exercise caution with emails from this sender.</p>` :
                                        total > 0 ?
                                        `<p style="color: var(--color-success);">✅ LOW RISK: This domain has been analyzed by ${total} security engines with no malicious or suspicious findings.</p>` :
                                        `<p style="color: var(--color-light);">❓ UNKNOWN: Limited analysis data available for this domain.</p>`
                                    }
                                </div>
                            </div>
                            <div class="mt-3">
                                <p><strong>Reputation Details:</strong></p>
                                <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                    <p>• <strong>Total Engines:</strong> ${total} security engines analyzed this domain</p>
                                    <p>• <strong>Detection Rate:</strong> ${total > 0 ? Math.round(((domain.malicious || 0) + (domain.suspicious || 0)) / total * 100) : 0}% flagged as threat</p>
                                    <p>• <strong>Confidence Level:</strong> ${total >= 50 ? 'High' : total >= 20 ? 'Medium' : 'Low'} (${total} engines)</p>
                                    ${domain.reputation !== null ? `<p>• <strong>VirusTotal Reputation:</strong> ${domain.reputation}</p>` : ''}
                                </div>
                            </div>
                            
                            ${domain.creation_date || domain.registrar || domain.country ? `
                            <div class="mt-3">
                                <p><strong>Domain Registration:</strong></p>
                                <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                    ${domain.creation_date ? `<p>• <strong>Created:</strong> ${new Date(domain.creation_date * 1000).toLocaleDateString()}</p>` : ''}
                                    ${domain.expiration_date ? `<p>• <strong>Expires:</strong> ${new Date(domain.expiration_date * 1000).toLocaleDateString()}</p>` : ''}
                                    ${domain.last_update_date ? `<p>• <strong>Last Updated:</strong> ${new Date(domain.last_update_date * 1000).toLocaleDateString()}</p>` : ''}
                                    ${domain.registrar ? `<p>• <strong>Registrar:</strong> ${domain.registrar}</p>` : ''}
                                    ${domain.country ? `<p>• <strong>Country:</strong> ${domain.country.toUpperCase()}</p>` : ''}
                                    ${domain.creation_date ? `<p>• <strong>Domain Age:</strong> ${Math.floor((Date.now() - domain.creation_date * 1000) / (1000 * 60 * 60 * 24))} days</p>` : ''}
                                </div>
                            </div>
                            ` : ''}
                            
                            ${domain.categories && Object.keys(domain.categories).length > 0 ? `
                            <div class="mt-3">
                                <p><strong>Content Categories:</strong></p>
                                <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                    ${Object.entries(domain.categories).map(([provider, category]) => 
                                        `<span style="background: rgba(72, 95, 199, 0.2); padding: 0.2rem 0.4rem; border-radius: 4px; margin: 0.1rem; display: inline-block; font-size: 0.7rem;">${category}</span>`
                                    ).join('')}
                                </div>
                            </div>
                            ` : ''}
                            
                            ${domain.tags && domain.tags.length > 0 ? `
                            <div class="mt-3">
                                <p><strong>Security Tags:</strong></p>
                                <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                    ${domain.tags.map(tag => 
                                        `<span style="background: rgba(255, 56, 96, 0.2); padding: 0.2rem 0.4rem; border-radius: 4px; margin: 0.1rem; display: inline-block; font-size: 0.7rem; color: var(--color-danger);">${tag}</span>`
                                    ).join('')}
                                </div>
                            </div>
                            ` : ''}
                            
                            ${domain.asn || domain.as_owner || domain.network ? `
                            <div class="mt-3">
                                <p><strong>Network Information:</strong></p>
                                <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                    ${domain.asn ? `<p>• <strong>ASN:</strong> AS${domain.asn}</p>` : ''}
                                    ${domain.as_owner ? `<p>• <strong>AS Owner:</strong> ${domain.as_owner}</p>` : ''}
                                    ${domain.network ? `<p>• <strong>Network:</strong> ${domain.network}</p>` : ''}
                                </div>
                            </div>
                            ` : ''}
                            
                            ${domain.subdomains && domain.subdomains.length > 0 ? `
                            <div class="mt-3">
                                <p><strong>Known Subdomains (${domain.subdomains.length}):</strong></p>
                                <div style="font-size: 0.8rem; margin-top: 0.5rem; max-height: 80px; overflow-y: auto; background: rgba(122, 122, 122, 0.1); padding: 0.3rem; border-radius: 4px;">
                                    ${domain.subdomains.slice(0, 10).map(subdomain => 
                                        `<p style="margin: 0.1rem 0;">• ${subdomain}</p>`
                                    ).join('')}
                                    ${domain.subdomains.length > 10 ? `<p style="margin: 0.1rem 0; font-style: italic;">... and ${domain.subdomains.length - 10} more</p>` : ''}
                                </div>
                            </div>
                            ` : ''}
                            
                            ${domain.siblings && domain.siblings.length > 0 ? `
                            <div class="mt-3">
                                <p><strong>Related Domains (${domain.siblings.length}):</strong></p>
                                <div style="font-size: 0.8rem; margin-top: 0.5rem; max-height: 60px; overflow-y: auto; background: rgba(122, 122, 122, 0.1); padding: 0.3rem; border-radius: 4px;">
                                    ${domain.siblings.slice(0, 5).map(sibling => 
                                        `<p style="margin: 0.1rem 0;">• ${sibling}</p>`
                                    ).join('')}
                                    ${domain.siblings.length > 5 ? `<p style="margin: 0.1rem 0; font-style: italic;">... and ${domain.siblings.length - 5} more</p>` : ''}
                                </div>
                            </div>
                            ` : ''}
                            
                            ${domain.whois && domain.whois.length > 0 ? `
                            <div class="mt-3">
                                <p><strong>WHOIS Information:</strong></p>
                                <div style="font-size: 0.7rem; margin-top: 0.5rem; max-height: 100px; overflow-y: auto; background: rgba(122, 122, 122, 0.1); padding: 0.5rem; border-radius: 4px; white-space: pre-wrap; font-family: monospace;">
                                    ${domain.whois.substring(0, 500)}${domain.whois.length > 500 ? '...' : ''}
                                </div>
                                ${domain.whois_date ? `<p style="font-size: 0.7rem; margin-top: 0.3rem; color: var(--color-light);">WHOIS updated: ${new Date(domain.whois_date * 1000).toLocaleDateString()}</p>` : ''}
                            </div>
                            ` : ''}
                            
                            ${domain.last_analysis_date ? `
                            <div class="mt-3">
                                <p><strong>Analysis Timeline:</strong></p>
                                <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                    <p>• <strong>Last Analyzed:</strong> ${new Date(domain.last_analysis_date * 1000).toLocaleString()}</p>
                                    ${domain.last_modification_date ? `<p>• <strong>Last Modified:</strong> ${new Date(domain.last_modification_date * 1000).toLocaleString()}</p>` : ''}
                                </div>
                            </div>
                            ` : ''}
                            
                            ${domain.total_votes && (domain.total_votes.harmless || domain.total_votes.malicious) ? `
                            <div class="mt-3">
                                <p><strong>Community Votes:</strong></p>
                                <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                    <p>• <strong>Harmless:</strong> ${domain.total_votes.harmless || 0} votes</p>
                                    <p>• <strong>Malicious:</strong> ${domain.total_votes.malicious || 0} votes</p>
                                </div>
                            </div>
                            ` : ''}
                            
                            ${domain.popularity_ranks && Object.keys(domain.popularity_ranks).length > 0 ? `
                            <div class="mt-3">
                                <p><strong>Popularity Rankings:</strong></p>
                                <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                    ${Object.entries(domain.popularity_ranks).map(([provider, rank]) => 
                                        `<p>• <strong>${provider}:</strong> #${typeof rank === 'object' ? rank.rank : rank}</p>`
                                    ).join('')}
                                </div>
                            </div>
                            ` : ''}
                        </div>`
                    }
                </div>
            </div>
        `;
        
        safeSetHTML(sidePanelBody, summaryHtml + domainDetails);
    }

    // Function to show all URLs in side panel
    function showAllUrls() {
        if (!window.lastAnalysisResults || !window.lastAnalysisResults.urls || window.lastAnalysisResults.urls.length === 0) {
            sidePanelBody.replaceChildren();
            const noUrlsParagraph = document.createElement('p');
            noUrlsParagraph.className = 'has-text-light';
            noUrlsParagraph.textContent = 'No URLs found in the email.';
            sidePanelBody.appendChild(noUrlsParagraph);
            return;
        }

        // Calculate URL security summary
        const urlSummary = {
            malicious: window.lastAnalysisResults.urls.filter(url => (url.malicious || 0) > 0).length,
            suspicious: window.lastAnalysisResults.urls.filter(url => (url.suspicious || 0) > 0 && (url.malicious || 0) === 0).length,
            clean: window.lastAnalysisResults.urls.filter(url => (url.malicious || 0) === 0 && (url.suspicious || 0) === 0).length,
            errors: window.lastAnalysisResults.urls.filter(url => url.error).length
        };

        sidePanelTitle.textContent = `All URLs (${window.lastAnalysisResults.urls.length})`;
        console.log(`Setting side panel title to: All URLs (${window.lastAnalysisResults.urls.length})`);
        
        // Add URL security summary at the top
        let summaryHtml = '<div class="side-panel-item" style="margin-bottom: 1.5rem; background: var(--color-bg-variant); border: 2px solid var(--color-primary);">';
        summaryHtml += '<div class="side-panel-item-header"><span class="side-panel-item-title">🔗 URL Security Analysis Summary</span></div>';
        summaryHtml += '<div class="side-panel-item-details" style="font-size: 0.85rem;">';
        if (urlSummary.malicious > 0) {
            summaryHtml += `<p style="color: var(--color-danger); font-weight: bold;">🔴 MALICIOUS: ${urlSummary.malicious} URLs</p>`;
        }
        if (urlSummary.suspicious > 0) {
            summaryHtml += `<p style="color: var(--color-warning); font-weight: bold;">🟡 SUSPICIOUS: ${urlSummary.suspicious} URLs</p>`;
        }
        if (urlSummary.clean > 0) {
            summaryHtml += `<p style="color: var(--color-success);">🟢 CLEAN: ${urlSummary.clean} URLs</p>`;
        }
        if (urlSummary.errors > 0) {
            summaryHtml += `<p style="color: var(--color-light);">❌ ERRORS: ${urlSummary.errors} URLs (analysis failed)</p>`;
        }
        summaryHtml += '</div></div>';

        const urlItems = window.lastAnalysisResults.urls.map((urlRes, index) => {
            const total = (urlRes.harmless || 0) + (urlRes.malicious || 0) + (urlRes.suspicious || 0) + (urlRes.undetected || 0) + (urlRes.timeout || 0);
            const severityClass = getSeverityColor(urlRes.malicious || 0, total);
            const isMalicious = (urlRes.malicious || 0) > 0;
            const isSuspicious = (urlRes.suspicious || 0) > 0;
            
            // Extract domain from URL for easier reading
            let urlDomain = 'Unknown domain';
            try {
                const urlObj = new URL(urlRes.id);
                urlDomain = urlObj.hostname;
            } catch (e) {
                urlDomain = urlRes.id.substring(0, 50) + '...';
            }
            
            // Determine URL status and color
            let statusIcon = '🔗';
            let statusText = 'Clean';
            let statusColor = 'var(--color-success)';
            
            if (urlRes.error) {
                statusIcon = '❌';
                statusText = 'Analysis Error';
                statusColor = 'var(--color-light)';
            } else if (isMalicious) {
                statusIcon = '🚨';
                statusText = 'Malicious';
                statusColor = 'var(--color-danger)';
            } else if (isSuspicious) {
                statusIcon = '⚠️';
                statusText = 'Suspicious';
                statusColor = 'var(--color-warning)';
            } else if (total > 0) {
                statusIcon = '✅';
                statusText = 'Clean';
                statusColor = 'var(--color-success)';
            } else {
                statusIcon = '❓';
                statusText = 'Unknown';
                statusColor = 'var(--color-light)';
            }
            
            return `
                <div class="side-panel-item ${isMalicious ? 'malicious' : ''}">
                    <div class="side-panel-item-header">
                        <span class="side-panel-item-title" style="color: ${statusColor};">${statusIcon} ${urlDomain}</span>
                        <span class="side-panel-item-score ${severityClass}">${urlRes.malicious || 0}/${total}</span>
                    </div>
                    <div class="side-panel-url-container">
                        <div class="side-panel-url-display has-text-light" style="max-height: 4.5rem; overflow-y: auto; padding: 0.75rem; background: var(--bulma-black-bis); border: 1px solid ${statusColor}; border-radius: 6px; font-size: 0.8rem; line-height: 1.4; word-break: break-all; position: relative; padding-right: 3rem;">
                            ${urlRes.id}
                            <button class="button side-panel-copy-btn" data-copy-text="${urlRes.id}" style="position: absolute; top: 0.5rem; right: 0.5rem; z-index: 10; min-width: 1.5rem; height: 1.2rem; padding: 0.2rem; font-size: 0.6rem; background: rgba(122, 122, 122, 0.3); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); border: 1px solid rgba(255, 255, 255, 0.1); color: rgba(255, 255, 255, 0.9);">
                                ⧉
                            </button>
                        </div>
                    </div>
                    <div class="side-panel-item-details mt-3">
                        <p><strong style="color: ${statusColor};">Status:</strong> ${statusText}</p>
                        <p><strong>Domain:</strong> ${urlDomain}</p>
                        ${urlRes.error ? 
                            `<p style="color: var(--color-danger);"><strong>Error:</strong> ${urlRes.error}</p>` : 
                            `<div class="mt-2">
                                <p><strong>Detection Results:</strong></p>
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin-top: 0.5rem; font-size: 0.8rem;">
                                    <div style="background: rgba(35, 209, 96, 0.2); padding: 0.3rem; border-radius: 4px;">
                                        <strong style="color: var(--color-success);">✅ Harmless:</strong> ${urlRes.harmless || 0}
                                    </div>
                                    <div style="background: rgba(255, 56, 96, 0.2); padding: 0.3rem; border-radius: 4px;">
                                        <strong style="color: var(--color-danger);">🚨 Malicious:</strong> ${urlRes.malicious || 0}
                                    </div>
                                    <div style="background: rgba(255, 221, 87, 0.2); padding: 0.3rem; border-radius: 4px;">
                                        <strong style="color: var(--color-warning);">⚠️ Suspicious:</strong> ${urlRes.suspicious || 0}
                                    </div>
                                    <div style="background: rgba(122, 122, 122, 0.2); padding: 0.3rem; border-radius: 4px;">
                                        <strong style="color: var(--color-light);">❓ Undetected:</strong> ${urlRes.undetected || 0}
                                    </div>
                                </div>
                                ${(urlRes.timeout || 0) > 0 ? `<p style="color: var(--color-light); margin-top: 0.5rem;"><strong>⏱️ Timeout:</strong> ${urlRes.timeout}</p>` : ''}
                                
                                <div class="mt-3">
                                    <p><strong>URL Risk Assessment:</strong></p>
                                    <div style="background: rgba(72, 95, 199, 0.1); padding: 0.5rem; border-radius: 6px; margin-top: 0.5rem;">
                                        ${isMalicious ? 
                                            `<p style="color: var(--color-danger); font-weight: bold;">⚠️ HIGH RISK: This URL has been flagged as malicious by ${urlRes.malicious} security engines. Clicking this link may lead to phishing sites, malware downloads, or other threats.</p>` :
                                            isSuspicious ?
                                            `<p style="color: var(--color-warning); font-weight: bold;">⚠️ MEDIUM RISK: This URL has been flagged as suspicious by ${urlRes.suspicious} security engines. Exercise caution before clicking this link.</p>` :
                                            total > 0 ?
                                            `<p style="color: var(--color-success);">✅ LOW RISK: This URL has been analyzed by ${total} security engines with no malicious or suspicious findings.</p>` :
                                            `<p style="color: var(--color-light);">❓ UNKNOWN: Limited analysis data available for this URL.</p>`
                                        }
                                    </div>
                                </div>
                                
                                <div class="mt-3">
                                    <p><strong>Detection Details:</strong></p>
                                    <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                        <p>• <strong>Total Engines:</strong> ${total} security engines analyzed this URL</p>
                                        <p>• <strong>Detection Rate:</strong> ${total > 0 ? Math.round(((urlRes.malicious || 0) + (urlRes.suspicious || 0)) / total * 100) : 0}% flagged as threat</p>
                                        <p>• <strong>Confidence Level:</strong> ${total >= 50 ? 'High' : total >= 20 ? 'Medium' : 'Low'} (${total} engines)</p>
                                        ${urlRes.reputation !== null ? `<p>• <strong>VirusTotal Reputation:</strong> ${urlRes.reputation}</p>` : ''}
                                    </div>
                                </div>
                                
                                ${urlRes.categories && Object.keys(urlRes.categories).length > 0 ? `
                                <div class="mt-3">
                                    <p><strong>Content Categories:</strong></p>
                                    <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                        ${Object.entries(urlRes.categories).map(([provider, category]) => 
                                            `<span style="background: rgba(72, 95, 199, 0.2); padding: 0.2rem 0.4rem; border-radius: 4px; margin: 0.1rem; display: inline-block; font-size: 0.7rem;">${category}</span>`
                                        ).join('')}
                                    </div>
                                </div>
                                ` : ''}
                                
                                ${urlRes.tags && urlRes.tags.length > 0 ? `
                                <div class="mt-3">
                                    <p><strong>Security Tags:</strong></p>
                                    <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                        ${urlRes.tags.map(tag => 
                                            `<span style="background: rgba(255, 56, 96, 0.2); padding: 0.2rem 0.4rem; border-radius: 4px; margin: 0.1rem; display: inline-block; font-size: 0.7rem; color: var(--color-danger);">${tag}</span>`
                                        ).join('')}
                                    </div>
                                </div>
                                ` : ''}
                                
                                ${urlRes.first_submission_date || urlRes.last_analysis_date ? `
                                <div class="mt-3">
                                    <p><strong>Analysis Timeline:</strong></p>
                                    <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                        ${urlRes.first_submission_date ? `<p>• <strong>First Submission:</strong> ${new Date(urlRes.first_submission_date * 1000).toLocaleString()}</p>` : ''}
                                        ${urlRes.last_analysis_date ? `<p>• <strong>Last Analyzed:</strong> ${new Date(urlRes.last_analysis_date * 1000).toLocaleString()}</p>` : ''}
                                        ${urlRes.last_modification_date ? `<p>• <strong>Last Modified:</strong> ${new Date(urlRes.last_modification_date * 1000).toLocaleString()}</p>` : ''}
                                    </div>
                                </div>
                                ` : ''}
                                
                                ${urlRes.total_votes && (urlRes.total_votes.harmless || urlRes.total_votes.malicious) ? `
                                <div class="mt-3">
                                    <p><strong>Community Votes:</strong></p>
                                    <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                        <p>• <strong>Harmless:</strong> ${urlRes.total_votes.harmless || 0} votes</p>
                                        <p>• <strong>Malicious:</strong> ${urlRes.total_votes.malicious || 0} votes</p>
                                    </div>
                                </div>
                                ` : ''}
                                
                                ${urlRes.threat_names && urlRes.threat_names.length > 0 ? `
                                <div class="mt-3">
                                    <p><strong>Threat Names:</strong></p>
                                    <div style="font-size: 0.8rem; margin-top: 0.5rem; max-height: 60px; overflow-y: auto; background: rgba(255, 56, 96, 0.1); padding: 0.3rem; border-radius: 4px;">
                                        ${urlRes.threat_names.slice(0, 5).map(threat => 
                                            `<p style="margin: 0.1rem 0; color: var(--color-danger);">• ${threat}</p>`
                                        ).join('')}
                                        ${urlRes.threat_names.length > 5 ? `<p style="margin: 0.1rem 0; font-style: italic;">... and ${urlRes.threat_names.length - 5} more</p>` : ''}
                                    </div>
                                </div>
                                ` : ''}
                            </div>`
                        }
                    </div>
                </div>
            `;
        }).join('');
        
        safeSetHTML(sidePanelBody, summaryHtml + urlItems);
    }

    // Function to show all attachments in side panel with security analysis
    function showAllAttachments() {
        if (!window.lastAnalysisResults || !window.lastAnalysisResults.attachments || window.lastAnalysisResults.attachments.length === 0) {
            sidePanelBody.replaceChildren();
            const noAttachmentsParagraph = document.createElement('p');
            noAttachmentsParagraph.className = 'has-text-light';
            noAttachmentsParagraph.textContent = 'No attachments found in the email.';
            sidePanelBody.appendChild(noAttachmentsParagraph);
            return;
        }

        // Calculate security summary
        const securitySummary = {
            critical: window.lastAnalysisResults.attachments.filter(att => att.riskLevel === 'CRITICAL').length,
            high: window.lastAnalysisResults.attachments.filter(att => att.riskLevel === 'HIGH').length,
            medium: window.lastAnalysisResults.attachments.filter(att => att.riskLevel === 'MEDIUM').length,
            low: window.lastAnalysisResults.attachments.filter(att => att.riskLevel === 'LOW').length
        };

        sidePanelTitle.textContent = `All Attachments (${window.lastAnalysisResults.attachments.length})`;
        console.log(`Setting side panel title to: All Attachments (${window.lastAnalysisResults.attachments.length})`);
        
        // Add security summary at the top
        let summaryHtml = '<div class="side-panel-item" style="margin-bottom: 1.5rem; background: var(--color-bg-variant); border: 2px solid var(--color-primary);">';
        summaryHtml += '<div class="side-panel-item-header"><span class="side-panel-item-title">🛡️ Security Analysis Summary</span></div>';
        summaryHtml += '<div class="side-panel-item-details" style="font-size: 0.85rem;">';
        if (securitySummary.critical > 0) {
            summaryHtml += `<p style="color: var(--color-danger); font-weight: bold;">🔴 CRITICAL: ${securitySummary.critical} files (Executables/Scripts)</p>`;
        }
        if (securitySummary.high > 0) {
            summaryHtml += `<p style="color: #ff8c42; font-weight: bold;">🟠 HIGH: ${securitySummary.high} files (Macro-capable documents)</p>`;
        }
        if (securitySummary.medium > 0) {
            summaryHtml += `<p style="color: var(--color-warning); font-weight: bold;">🟡 MEDIUM: ${securitySummary.medium} files (Archives/PDFs)</p>`;
        }
        if (securitySummary.low > 0) {
            summaryHtml += `<p style="color: var(--color-success);">🟢 LOW: ${securitySummary.low} files (Safe types)</p>`;
        }
        summaryHtml += '</div></div>';
        
        const attachmentItems = window.lastAnalysisResults.attachments.map((attachment, index) => {
            // Determine risk color and icon
            let riskColor, riskIcon, riskBg;
            switch(attachment.riskLevel) {
                case 'CRITICAL':
                    riskColor = 'var(--color-danger)';
                    riskIcon = '🚨';
                    riskBg = 'rgba(255, 56, 96, 0.1)';
                    break;
                case 'HIGH':
                    riskColor = '#ff8c42';
                    riskIcon = '⚠️';
                    riskBg = 'rgba(255, 140, 66, 0.1)';
                    break;
                case 'MEDIUM':
                    riskColor = 'var(--color-warning)';
                    riskIcon = '⚡';
                    riskBg = 'rgba(255, 221, 87, 0.1)';
                    break;
                case 'LOW':
                    riskColor = 'var(--color-success)';
                    riskIcon = '✅';
                    riskBg = 'rgba(35, 209, 96, 0.1)';
                    break;
                default:
                    riskColor = 'var(--color-light)';
                    riskIcon = '❓';
                    riskBg = 'rgba(122, 122, 122, 0.1)';
            }
            
            const isCritical = attachment.riskLevel === 'CRITICAL';
            
            return `
                <div class="side-panel-item ${isCritical ? 'malicious' : ''}" style="background: ${riskBg}; border-color: ${riskColor};">
                    <div class="side-panel-item-header">
                        <span class="side-panel-item-title" style="color: ${riskColor};">${riskIcon} ${attachment.filename}</span>
                        <span class="side-panel-item-score" style="background: ${riskColor}; color: var(--bulma-black-bis); font-weight: bold;">${attachment.riskLevel}</span>
                    </div>
                    <div class="side-panel-url-container">
                        <div class="side-panel-url-display has-text-light" style="max-height: 4.5rem; overflow-y: auto; padding: 0.75rem; background: var(--bulma-black-bis); border: 1px solid ${riskColor}; border-radius: 6px; font-size: 0.8rem; line-height: 1.4; word-break: break-all; position: relative; padding-right: 3rem;">
                            📄 ${attachment.filename}
                            <button class="button side-panel-copy-btn" data-copy-text="${attachment.filename}" style="position: absolute; top: 0.5rem; right: 0.5rem; z-index: 10; min-width: 1.5rem; height: 1.2rem; padding: 0.2rem; font-size: 0.6rem; background: rgba(122, 122, 122, 0.3); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); border: 1px solid rgba(255, 255, 255, 0.1); color: rgba(255, 255, 255, 0.9);">
                                ⧉
                            </button>
                        </div>
                    </div>
                    <div class="side-panel-item-details mt-3">
                        <p><strong style="color: ${riskColor};">Risk Category:</strong> ${attachment.riskCategory || 'Unknown'}</p>
                        <p><strong>Description:</strong> ${attachment.riskDescription || 'No description available'}</p>
                        <p><strong>Download URL:</strong> ${attachment.downloadURL ? 'Available' : 'Not detected'}</p>
                        ${attachment.fileSize ? `<p><strong>File Size:</strong> ${attachment.fileSize}</p>` : ''}
                        ${attachment.attachmentId ? `<p><strong>Attachment ID:</strong> ${attachment.attachmentId}</p>` : ''}
                        
                        ${attachment.fileHashes && (attachment.fileHashes.md5 || attachment.fileHashes.sha1 || attachment.fileHashes.sha256) ? `
                        <div class="mt-3">
                            <p><strong>File Hashes:</strong></p>
                            <div style="font-size: 0.7rem; margin-top: 0.5rem; background: rgba(122, 122, 122, 0.1); padding: 0.5rem; border-radius: 4px; font-family: monospace;">
                                ${attachment.fileHashes.md5 ? `<p><strong>MD5:</strong> ${attachment.fileHashes.md5}</p>` : ''}
                                ${attachment.fileHashes.sha1 ? `<p><strong>SHA1:</strong> ${attachment.fileHashes.sha1}</p>` : ''}
                                ${attachment.fileHashes.sha256 ? `<p><strong>SHA256:</strong> ${attachment.fileHashes.sha256}</p>` : ''}
                            </div>
                        </div>
                        ` : ''}
                        
                        ${attachment.vtHashAnalysis ? `
                        <div class="mt-3">
                            <p><strong>VirusTotal Hash Analysis:</strong></p>
                            <div style="font-size: 0.8rem; margin-top: 0.5rem;">
                                <p><strong>Hash Type:</strong> ${attachment.vtHashAnalysis.hashType}</p>
                                <p><strong>Database Status:</strong> ${attachment.vtHashAnalysis.found ? 'Found in VirusTotal' : 'Not found in database'}</p>
                                
                                ${attachment.vtHashAnalysis.found ? `
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin-top: 0.5rem; font-size: 0.75rem;">
                                    <div style="background: rgba(35, 209, 96, 0.2); padding: 0.3rem; border-radius: 4px;">
                                        <strong style="color: var(--color-success);">✅ Harmless:</strong> ${attachment.vtHashAnalysis.harmless || 0}
                                    </div>
                                    <div style="background: rgba(255, 56, 96, 0.2); padding: 0.3rem; border-radius: 4px;">
                                        <strong style="color: var(--color-danger);">🚨 Malicious:</strong> ${attachment.vtHashAnalysis.malicious || 0}
                                    </div>
                                    <div style="background: rgba(255, 221, 87, 0.2); padding: 0.3rem; border-radius: 4px;">
                                        <strong style="color: var(--color-warning);">⚠️ Suspicious:</strong> ${attachment.vtHashAnalysis.suspicious || 0}
                                    </div>
                                    <div style="background: rgba(122, 122, 122, 0.2); padding: 0.3rem; border-radius: 4px;">
                                        <strong style="color: var(--color-light);">❓ Undetected:</strong> ${attachment.vtHashAnalysis.undetected || 0}
                                    </div>
                                </div>
                                
                                ${attachment.vtHashAnalysis.fileType ? `<p style="margin-top: 0.5rem;"><strong>File Type:</strong> ${attachment.vtHashAnalysis.fileType}</p>` : ''}
                                ${attachment.vtHashAnalysis.fileSize ? `<p><strong>VT File Size:</strong> ${attachment.vtHashAnalysis.fileSize} bytes</p>` : ''}
                                ${attachment.vtHashAnalysis.firstSeen ? `<p><strong>First Seen:</strong> ${new Date(attachment.vtHashAnalysis.firstSeen * 1000).toLocaleDateString()}</p>` : ''}
                                ${attachment.vtHashAnalysis.lastSeen ? `<p><strong>Last Analyzed:</strong> ${new Date(attachment.vtHashAnalysis.lastSeen * 1000).toLocaleDateString()}</p>` : ''}
                                ${attachment.vtHashAnalysis.reputation ? `<p><strong>Reputation:</strong> ${attachment.vtHashAnalysis.reputation}</p>` : ''}
                                
                                ${attachment.vtHashAnalysis.tags && attachment.vtHashAnalysis.tags.length > 0 ? `
                                <div style="margin-top: 0.5rem;">
                                    <p><strong>Tags:</strong></p>
                                    <div style="margin-top: 0.3rem;">
                                        ${attachment.vtHashAnalysis.tags.slice(0, 5).map(tag => 
                                            `<span style="background: rgba(255, 56, 96, 0.2); padding: 0.2rem 0.3rem; border-radius: 3px; margin: 0.1rem; display: inline-block; font-size: 0.65rem; color: var(--color-danger);">${tag}</span>`
                                        ).join('')}
                                        ${attachment.vtHashAnalysis.tags.length > 5 ? `<span style="font-size: 0.65rem; color: var(--color-light);">... +${attachment.vtHashAnalysis.tags.length - 5} more</span>` : ''}
                                    </div>
                                </div>
                                ` : ''}
                                
                                ${attachment.vtHashAnalysis.names && attachment.vtHashAnalysis.names.length > 0 ? `
                                <div style="margin-top: 0.5rem;">
                                    <p><strong>Known Names:</strong></p>
                                    <div style="font-size: 0.65rem; margin-top: 0.3rem; max-height: 60px; overflow-y: auto; background: rgba(122, 122, 122, 0.1); padding: 0.3rem; border-radius: 4px;">
                                        ${attachment.vtHashAnalysis.names.slice(0, 8).map(name => 
                                            `<p style="margin: 0.1rem 0;">• ${name}</p>`
                                        ).join('')}
                                        ${attachment.vtHashAnalysis.names.length > 8 ? `<p style="margin: 0.1rem 0; font-style: italic;">... and ${attachment.vtHashAnalysis.names.length - 8} more</p>` : ''}
                                    </div>
                                </div>
                                ` : ''}
                                ` : attachment.vtHashAnalysis.error ? `
                                <p style="color: var(--color-danger); margin-top: 0.5rem;"><strong>Error:</strong> ${attachment.vtHashAnalysis.error}</p>
                                ` : `
                                <p style="color: var(--color-light); margin-top: 0.5rem;">This file has not been analyzed by VirusTotal yet.</p>
                                `}
                            </div>
                        </div>
                        ` : ''}
                        
                        ${isCritical ? '<p style="color: var(--color-danger); font-weight: bold; margin-top: 0.5rem;">⚠️ WARNING: This file can execute code on your system!</p>' : ''}
                    </div>
                </div>
            `;
        }).join('');
        
        safeSetHTML(sidePanelBody, summaryHtml + attachmentItems);
    }

    // Event listeners for View All buttons
    viewAllDomains.addEventListener('click', () => {
        // Reset panel content first to ensure fresh state
        resetSidePanel();
        showAllDomains();
        openSidePanel();
    });

    viewAllUrls.addEventListener('click', () => {
        // Reset panel content first to ensure fresh state
        resetSidePanel();
        showAllUrls();
        openSidePanel();
    });

    viewAllAttachments.addEventListener('click', () => {
        // Reset panel content first to ensure fresh state
        resetSidePanel();
        showAllAttachments();
        openSidePanel();
    });

    // Event listeners for closing side panel
    closeSidePanel.addEventListener('click', closeSidePanelFunc);
    sidePanelOverlay.addEventListener('click', closeSidePanelFunc);

    // Close side panel with Escape key
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && sidePanel.classList.contains('show')) {
            closeSidePanelFunc();
        }
    });

    // Add event listeners for copy buttons in main view
    function setupCopyButtons() {
        // Copy sender email button
        const copySenderBtn = document.querySelector('.copy-sender-btn');
        if (copySenderBtn) {
            copySenderBtn.addEventListener('click', function() {
                const username = document.getElementById('senderUsername').textContent;
                const domain = document.getElementById('senderDomainName').textContent;
                const fullEmail = username + '@' + domain;
                copyToClipboardSync(fullEmail, this);
            });
        }

        // Copy domain button
        const copyDomainBtn = document.querySelector('.copy-domain-main-btn');
        if (copyDomainBtn) {
            copyDomainBtn.addEventListener('click', function() {
                const domain = document.getElementById('senderDomainDisplay').textContent;
                copyToClipboardSync(domain, this);
            });
        }

        // Copy subject button
        const copySubjectBtn = document.querySelector('.copy-subject-btn');
        if (copySubjectBtn) {
            copySubjectBtn.addEventListener('click', function() {
                const subject = document.getElementById('emailSubject').textContent;
                copyToClipboardSync(subject, this);
            });
        }
    }

    // Call setupCopyButtons after DOM is ready
    setupCopyButtons();

    // Add event delegation for side panel copy buttons
    sidePanelBody.addEventListener('click', function(event) {
        if (event.target.classList.contains('side-panel-copy-btn')) {
            const textToCopy = event.target.getAttribute('data-copy-text');
            if (textToCopy) {
                copyToClipboardSync(textToCopy, event.target);
            }
        }
    });
});