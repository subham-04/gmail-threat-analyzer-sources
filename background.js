// background.js
// This is the service worker script. It runs in the background and handles API calls.

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'analyzeWithVirusTotal') {
        const { data, apiKey } = request;
        const results = {
            domain: null,
            urls: [],
            attachments: data.attachments, // Pass attachment objects directly
            senderUsername: null, // Add username extraction
            emailData: {
                subject: data.subject,
                bodyText: data.bodyText,
                bodyHTML: data.bodyHTML
            }
        };

        // Extract username from sender email
        if (data.sender) {
            const usernameMatch = data.sender.match(/^([^@]+)@/);
            if (usernameMatch) {
                results.senderUsername = usernameMatch[1];
            }
        }

        if (!apiKey) {
            console.error("VirusTotal API Key is missing.");
            sendResponse({ success: false, error: 'VirusTotal API Key is missing.' });
            return true; // Indicate that sendResponse will be called asynchronously
        }

        const headers = {
            'x-apikey': apiKey,
            'accept': 'application/json'
        };

        const analysisPromises = [];

        // 1. Analyze Sender Domain
        if (data.senderDomain) {
            const domainUrl = `https://www.virustotal.com/api/v3/domains/${data.senderDomain}`;
            console.log(`[Background] Analyzing domain: ${data.senderDomain}`);
            analysisPromises.push(
                fetch(domainUrl, { headers })
                    .then(response => {
                        console.log(`[Background] Domain API Response Status for ${data.senderDomain}: ${response.status} ${response.statusText}`);
                        if (!response.ok) {
                            return response.json().then(errorData => Promise.reject(new Error(errorData.error ? errorData.error.message : `HTTP error! status: ${response.status}`)));
                        }
                        return response.json();
                    })
                    .then(vtData => {
                        console.log(`[Background] Domain API Data for ${data.senderDomain}:`, vtData);
                        if (vtData.data && vtData.data.attributes) {
                            const attrs = vtData.data.attributes;
                            const stats = attrs.last_analysis_stats || {};
                            
                            results.domain = {
                                id: data.senderDomain,
                                // Basic analysis stats
                                harmless: stats.harmless || 0,
                                malicious: stats.malicious || 0,
                                suspicious: stats.suspicious || 0,
                                undetected: stats.undetected || 0,
                                timeout: stats.timeout || 0,
                                
                                // Enhanced domain information
                                creation_date: attrs.creation_date || null,
                                last_update_date: attrs.last_update_date || null,
                                expiration_date: attrs.expiration_date || null,
                                registrar: attrs.registrar || null,
                                whois: attrs.whois || null,
                                whois_date: attrs.whois_date || null,
                                reputation: attrs.reputation || null,
                                categories: attrs.categories || {},
                                last_analysis_date: attrs.last_analysis_date || null,
                                last_modification_date: attrs.last_modification_date || null,
                                
                                // Network and infrastructure
                                network: attrs.network || null,
                                asn: attrs.asn || null,
                                as_owner: attrs.as_owner || null,
                                country: attrs.country || null,
                                
                                // Security intelligence
                                subdomains: attrs.subdomains || [],
                                siblings: attrs.siblings || [],
                                tags: attrs.tags || [],
                                last_analysis_results: attrs.last_analysis_results || {},
                                
                                // Additional metadata
                                total_votes: attrs.total_votes || {},
                                popularity_ranks: attrs.popularity_ranks || {}
                            };
                        } else if (vtData.error) {
                            console.error(`[Background] VirusTotal Domain Error for ${data.senderDomain}:`, vtData.error.message);
                            results.domain = { id: data.senderDomain, error: vtData.error.message };
                        } else {
                            results.domain = { id: data.senderDomain, message: 'No analysis data available.' };
                        }
                    })
                    .catch(error => {
                        console.error(`[Background] Error analyzing domain ${data.senderDomain}:`, error);
                        results.domain = { id: data.senderDomain, error: error.message };
                    })
            );
        }

        // 2. Analyze URLs
        if (data.links && data.links.length > 0) { // Use data.links from the new structure
            data.links.forEach(url => {
                console.log(`[Background] Analyzing URL: ${url}`);
                const urlAnalysisUrl = `https://www.virustotal.com/api/v3/urls`;

                analysisPromises.push(
                    fetch(urlAnalysisUrl, {
                        method: 'POST',
                        headers: {
                            'x-apikey': apiKey,
                            'accept': 'application/json',
                            'content-type': 'application/x-www-form-urlencoded'
                        },
                        body: `url=${url}`
                    })
                    .then(response => {
                        console.log(`[Background] URL Submission API Response Status for ${url}: ${response.status} ${response.statusText}`);
                        if (!response.ok) {
                            return response.json().then(errorData => Promise.reject(new Error(errorData.error ? errorData.error.message : `HTTP error! status: ${response.status}`)));
                        }
                        return response.json();
                    })
                    .then(submissionData => {
                        console.log(`[Background] URL Submission API Data for ${url}:`, submissionData);
                        if (submissionData.data && submissionData.data.id) {
                            const analysisId = submissionData.data.id;
                            // Now fetch the analysis report
                            console.log(`[Background] Fetching URL analysis report for ID: ${analysisId}`);
                            return fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers });
                        } else if (submissionData.error) {
                             console.error(`[Background] VirusTotal URL Submission Error for ${url}:`, submissionData.error.message);
                             return Promise.reject(new Error(submissionData.error.message));
                        } else {
                            return Promise.reject(new Error('Failed to submit URL for analysis.'));
                        }
                    })
                    .then(response => {
                        console.log(`[Background] URL Report API Response Status for analysis ID: ${response.status} ${response.statusText}`);
                        if (!response.ok) {
                            return response.json().then(errorData => Promise.reject(new Error(errorData.error ? errorData.error.message : `HTTP error! status: ${response.status}`)));
                        }
                        return response.json();
                    })
                    .then(vtData => {
                        console.log(`[Background] URL Report API Data for ${url}:`, vtData);
                        // CORRECTED: Use vtData.data.attributes.stats for URL analysis summary
                        if (vtData.data && vtData.data.attributes && vtData.data.attributes.stats) {
                            const stats = vtData.data.attributes.stats;
                            const attributes = vtData.data.attributes;
                            results.urls.push({
                                id: url,
                                vtId: vtData.data.id, // ID for VT GUI link
                                harmless: stats.harmless || 0,
                                malicious: stats.malicious || 0,
                                suspicious: stats.suspicious || 0,
                                undetected: stats.undetected || 0,
                                timeout: stats.timeout || 0,
                                // Additional URL intelligence fields
                                reputation: attributes.reputation || null,
                                categories: attributes.categories || {},
                                tags: attributes.tags || [],
                                first_submission_date: attributes.first_submission_date || null,
                                last_analysis_date: attributes.last_analysis_date || null,
                                last_modification_date: attributes.last_modification_date || null,
                                total_votes: attributes.total_votes || {},
                                threat_names: attributes.threat_names || []
                            });
                        } else if (vtData.error) {
                            console.error(`[Background] VirusTotal URL Analysis Error for ${url}:`, vtData.error.message);
                            results.urls.push({ id: url, error: vtData.error.message });
                        } else {
                            results.urls.push({ id: url, message: 'No analysis data available.' });
                        }
                    })
                    .catch(error => {
                        console.error(`[Background] Error analyzing URL ${url}:`, error);
                        results.urls.push({ id: url, error: error.message });
                    })
                );
            });
        }

        // 3. Analyze File Hashes (if available)
        if (data.attachments && data.attachments.length > 0) {
            data.attachments.forEach(attachment => {
                // Check if we have any hash for this attachment
                const fileHashes = attachment.fileHashes;
                const availableHash = fileHashes?.sha256 || fileHashes?.sha1 || fileHashes?.md5;
                
                if (availableHash) {
                    console.log(`[Background] Analyzing file hash for ${attachment.filename}: ${availableHash}`);
                    const hashAnalysisUrl = `https://www.virustotal.com/api/v3/files/${availableHash}`;
                    
                    analysisPromises.push(
                        fetch(hashAnalysisUrl, { headers })
                            .then(response => {
                                console.log(`[Background] File Hash API Response Status for ${attachment.filename}: ${response.status} ${response.statusText}`);
                                if (!response.ok) {
                                    if (response.status === 404) {
                                        console.log(`[Background] File hash not found in VirusTotal database: ${availableHash}`);
                                        return { notFound: true };
                                    }
                                    return response.json().then(errorData => Promise.reject(new Error(errorData.error ? errorData.error.message : `HTTP error! status: ${response.status}`)));
                                }
                                return response.json();
                            })
                            .then(hashData => {
                                console.log(`[Background] File Hash API Data for ${attachment.filename}:`, hashData);
                                
                                if (hashData.notFound) {
                                    // Add hash info to attachment even if not found in VT
                                    const attachmentIndex = results.attachments.findIndex(att => att.filename === attachment.filename);
                                    if (attachmentIndex !== -1) {
                                        results.attachments[attachmentIndex].vtHashAnalysis = {
                                            hash: availableHash,
                                            hashType: fileHashes?.sha256 ? 'SHA256' : fileHashes?.sha1 ? 'SHA1' : 'MD5',
                                            found: false,
                                            message: 'Hash not found in VirusTotal database'
                                        };
                                    }
                                } else if (hashData.data && hashData.data.attributes) {
                                    const stats = hashData.data.attributes.last_analysis_stats;
                                    const attributes = hashData.data.attributes;
                                    
                                    // Add comprehensive hash analysis to attachment
                                    const attachmentIndex = results.attachments.findIndex(att => att.filename === attachment.filename);
                                    if (attachmentIndex !== -1) {
                                        results.attachments[attachmentIndex].vtHashAnalysis = {
                                            hash: availableHash,
                                            hashType: fileHashes?.sha256 ? 'SHA256' : fileHashes?.sha1 ? 'SHA1' : 'MD5',
                                            found: true,
                                            harmless: stats?.harmless || 0,
                                            malicious: stats?.malicious || 0,
                                            suspicious: stats?.suspicious || 0,
                                            undetected: stats?.undetected || 0,
                                            timeout: stats?.timeout || 0,
                                            // Additional file intelligence
                                            fileType: attributes.type_description || null,
                                            fileSize: attributes.size || null,
                                            firstSeen: attributes.first_submission_date || null,
                                            lastSeen: attributes.last_analysis_date || null,
                                            reputation: attributes.reputation || null,
                                            tags: attributes.tags || [],
                                            names: attributes.names || []
                                        };
                                    }
                                }
                            })
                            .catch(error => {
                                console.error(`[Background] Error analyzing file hash for ${attachment.filename}:`, error);
                                // Add error info to attachment
                                const attachmentIndex = results.attachments.findIndex(att => att.filename === attachment.filename);
                                if (attachmentIndex !== -1) {
                                    results.attachments[attachmentIndex].vtHashAnalysis = {
                                        hash: availableHash,
                                        hashType: fileHashes?.sha256 ? 'SHA256' : fileHashes?.sha1 ? 'SHA1' : 'MD5',
                                        found: false,
                                        error: error.message
                                    };
                                }
                            })
                    );
                }
            });
        }

        // Wait for all analysis promises to resolve
        Promise.allSettled(analysisPromises)
            .then(() => {
                console.log("[Background] All VirusTotal analysis promises settled. Sending response to popup.");
                sendResponse({ success: true, results: results });
            })
            .catch(error => {
                console.error("[Background] Overall analysis failed:", error);
                sendResponse({ success: false, error: `Overall analysis failed: ${error.message}` });
            });

        return true; // Indicate that sendResponse will be called asynchronously
    }
});