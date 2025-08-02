// content.js
// This script runs in the context of the Gmail page.

// Add Bulma font family styling
const bulmaFontStyle = document.createElement('style');
bulmaFontStyle.textContent = `
    .is-family-sans-serif {
        font-family: BlinkMacSystemFont, -apple-system, "Segoe UI", "Roboto", "Oxygen", "Ubuntu", "Cantarell", "Fira Sans", "Droid Sans", "Helvetica Neue", "Helvetica", "Arial", sans-serif !important;
    }
`;
document.head.appendChild(bulmaFontStyle);

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'extractEmailData') {
        try {
            const emailDetails = {
                sender: null,
                senderDomain: null,
                subject: null,
                bodyText: null,
                bodyHTML: null,
                links: [],
                attachments: [] // Will store objects { filename, downloadURL }
            };

            // 1. Extract Sender and Sender Domain
            const senderElement = document.querySelector('.gD'); // Simplified selector like your console script
            if (senderElement) {
                emailDetails.sender = senderElement.getAttribute('email') || senderElement.innerText;
                if (emailDetails.sender) {
                    const domainMatch = emailDetails.sender.match(/@(.+)$/);
                    if (domainMatch) {
                        emailDetails.senderDomain = domainMatch[1];
                    }
                }
            }

            // Fallback: Extract from header table like your console script
            if (!emailDetails.sender || !emailDetails.senderDomain) {
                const headerTable = document.querySelector('table.cf.hb');
                if (headerTable) {
                    const rows = headerTable.querySelectorAll('tr');
                    rows.forEach(row => {
                        const label = row.querySelector('td:first-child')?.innerText?.trim().toLowerCase();
                        const value = row.querySelector('td:last-child')?.innerText?.trim();
                        
                        if (label && label.startsWith('from:') && value) {
                            emailDetails.sender = value;
                            const domainMatch = value.match(/@(.+)$/);
                            if (domainMatch) {
                                emailDetails.senderDomain = domainMatch[1];
                            }
                        }
                    });
                }
            }
            // Fallback if the above doesn't work (e.g., for different Gmail layouts)
            if (!emailDetails.sender || !emailDetails.senderDomain) {
                const emailHeader = document.querySelector('.nH.hX .gF.gK');
                if (emailHeader) {
                    const emailAddress = emailHeader.querySelector('.gD');
                    if (emailAddress) {
                        const senderText = emailAddress.getAttribute('email') || emailAddress.textContent.trim();
                        const emailMatch = senderText.match(/\S+@\S+\.\S+/);
                        if (emailMatch) {
                            emailDetails.sender = emailMatch[0];
                            const domainMatch = emailDetails.sender.match(/@([^>]+)/);
                            if (domainMatch && domainMatch[1]) {
                                emailDetails.senderDomain = domainMatch[1];
                            }
                        }
                    }
                }
            }


            // 2. Extract Subject
            const subjectElement = document.querySelector('.hP');
            if (subjectElement) {
                emailDetails.subject = subjectElement.innerText;
            }

            // 3. Extract Body HTML and Text, and Links
            const emailBodyContent = document.querySelector('.a3s.aiL') || document.querySelector('.nH.hx .a3s'); // Common body content selectors
            if (emailBodyContent) {
                emailDetails.bodyHTML = emailBodyContent.innerHTML;
                emailDetails.bodyText = emailBodyContent.innerText;

                const links = emailBodyContent.querySelectorAll('a[href]');
                links.forEach(link => {
                    const href = link.href;
                    if (href && (href.startsWith('http://') || href.startsWith('https://')) && !href.includes('mail.google.com')) {
                        emailDetails.links.push(href);
                    }
                });
            }

            // 4. Extract Attachments - Enhanced Multiple Strategy Detection with Security Analysis
            // console.log("🔎 Starting attachment detection with security analysis...");
            
            // Define file extension categories for security analysis
            const fileExtensions = {
                // Highly Dangerous - Executable Files
                executable: ['exe', 'com', 'scr', 'bat', 'cmd', 'pif', 'msi', 'app', 'deb', 'rpm', 'run'],
                
                // Highly Dangerous - Script Files
                scripts: ['js', 'vbs', 'vbe', 'jse', 'ws', 'wsf', 'wsh', 'ps1', 'psm1', 'psd1', 'jar', 'py', 'pl', 'rb', 'sh', 'bash', 'zsh', 'fish'],
                
                // Dangerous - Office Macros & Documents with potential macro capability
                macroCapable: ['doc', 'docm', 'xls', 'xlsm', 'ppt', 'pptm', 'xlam', 'docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp'],
                
                // Suspicious - Archives & Compressed files
                archives: ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'cab', 'iso', 'img', 'dmg', 'ace', 'arj'],
                
                // Medium Risk - Documents and potentially dangerous files
                mediumRisk: ['pdf', 'rtf', 'svg', 'swf', 'html', 'htm', 'hta', 'chm', 'txt', 'log', 'cfg', 'conf', 'ini'],
                
                // Business Safe - Common business document/media files (non-executable)
                businessSafe: ['pages', 'numbers', 'key', 'wpd', 'pub', 'csv', 'json', 'xml'],
                
                // Media Safe - Images, audio, video files
                mediaSafe: ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp', 'mp3', 'mp4', 'wav', 'avi', 'mov', 'flv', 'wmv', 'mkv']
            };
            
            // Function to categorize file by extension and assign risk level
            function analyzeFileRisk(filename) {
                // Clean the filename and extract extension properly
                const cleanFilename = filename.trim().replace(/\s+/g, ' ');
                const allParts = cleanFilename.toLowerCase().split('.');
                const extension = allParts[allParts.length - 1]; // Last extension
                
                // console.log(`  🔍 Analyzing file: "${cleanFilename}" | Extension: "${extension}"`);
                
                // Check for suspicious double extensions (e.g., file.exe.png, document.scr.jpg)
                if (allParts.length > 2) {
                    const penultimateExtension = allParts[allParts.length - 2]; // Second to last extension
                    
                    // Check if the second-to-last extension is dangerous while final extension appears safe
                    const isDangerousHidden = [
                        ...fileExtensions.executable,
                        ...fileExtensions.scripts
                    ].includes(penultimateExtension);
                    
                    const appearsHarmless = [
                        ...fileExtensions.mediaSafe,
                        ...fileExtensions.businessSafe,
                        'txt', 'pdf', 'doc', 'docx'
                    ].includes(extension);
                    
                    if (isDangerousHidden && appearsHarmless) {
                        // console.log(`  🚨 SUSPICIOUS: Double extension detected! Hidden: ${penultimateExtension}, Visible: ${extension}`);
                        return { 
                            category: 'disguised', 
                            risk: 'CRITICAL', 
                            description: `⚠️ DISGUISED EXECUTABLE - Hidden .${penultimateExtension} file masquerading as .${extension}! This is a common malware technique.` 
                        };
                    }
                    
                    // Check for other suspicious patterns like multiple extensions
                    if (allParts.length > 3) {
                        // console.log(`  🚨 SUSPICIOUS: Multiple extensions detected: ${allParts.slice(1).join('.')}`);
                        return { 
                            category: 'multi-extension', 
                            risk: 'HIGH', 
                            description: `Multiple file extensions (.${allParts.slice(1).join('.')}) - Potentially suspicious naming pattern` 
                        };
                    }
                }
                
                // Regular single extension analysis
                if (fileExtensions.executable.includes(extension)) {
                    return { category: 'executable', risk: 'CRITICAL', description: 'Executable file - Can run code on your system' };
                } else if (fileExtensions.scripts.includes(extension)) {
                    return { category: 'script', risk: 'CRITICAL', description: 'Script file - Can execute malicious code' };
                } else if (fileExtensions.macroCapable.includes(extension)) {
                    return { category: 'macro', risk: 'HIGH', description: 'Office document - May contain dangerous macros' };
                } else if (fileExtensions.archives.includes(extension)) {
                    return { category: 'archive', risk: 'MEDIUM', description: 'Archive file - May contain hidden malicious files' };
                } else if (fileExtensions.mediumRisk.includes(extension)) {
                    return { category: 'medium', risk: 'MEDIUM', description: 'Document/config file - May contain sensitive data or embedded content' };
                } else if (fileExtensions.businessSafe.includes(extension)) {
                    return { category: 'business', risk: 'LOW', description: 'Business document - Generally safe but verify sender' };
                } else if (fileExtensions.mediaSafe.includes(extension)) {
                    return { category: 'media', risk: 'LOW', description: 'Media file - Generally safe content' };
                } else {
                    return { category: 'unknown', risk: 'MEDIUM', description: `Unknown file type (.${extension}) - Exercise caution and verify with sender` };
                }
            }
            
            // Note: File hash calculation is not currently possible due to browser security restrictions.
            // Gmail attachment URLs require authentication and don't contain hash parameters.
            // Future enhancement could include manual hash input or server-side proxy for hash calculation.
            
            // Create comprehensive file extension pattern for detection
            const allExtensions = [
                ...fileExtensions.executable,
                ...fileExtensions.scripts,
                ...fileExtensions.macroCapable,
                ...fileExtensions.archives,
                ...fileExtensions.mediumRisk,
                ...fileExtensions.businessSafe,
                ...fileExtensions.mediaSafe
            ].join('|');
            
            // Strategy 1: Modern Gmail attachment selectors (2024-2025)
            let attachmentElements = document.querySelectorAll('span[role="link"] .aQy, .aV3 .aQy');
            // console.log(`Strategy 1 (Modern): Found ${attachmentElements.length} elements`);
            
            // Strategy 2: Alternative selectors for different Gmail versions
            if (attachmentElements.length === 0) {
                attachmentElements = document.querySelectorAll('.aKp .aQy, .aQJ .aQy, .aKu .aQy');
                // console.log(`Strategy 2 (Alternative): Found ${attachmentElements.length} elements`);
            }
            
            // Strategy 3: Look for any element with attachment-like attributes
            if (attachmentElements.length === 0) {
                attachmentElements = document.querySelectorAll('[aria-label*="attachment"], [title*="attachment"], .aQy');
                // console.log(`Strategy 3 (Attributes): Found ${attachmentElements.length} elements`);
            }
            
            // Strategy 4: Search by download links and extract filenames with enhanced URL capture
            if (attachmentElements.length === 0) {
                // console.log("Strategy 4: Searching download links...");
                const downloadLinks = document.querySelectorAll('a[href*="&attid="], a[href*="attachment"], a[href*="download"], a[href*="disp=safe"], a[href*="disp=attd"]');
                // console.log(`Found ${downloadLinks.length} download links`);
                
                downloadLinks.forEach((link, index) => {
                    // console.log(`  Link ${index + 1}: [URL HIDDEN]`);
                    // Try to find filename in nearby text or aria-label
                    let filename = link.getAttribute('aria-label') || 
                                   link.getAttribute('title') || 
                                   link.textContent.trim() ||
                                   link.querySelector('.aQy')?.textContent.trim() ||
                                   link.parentElement?.textContent.trim();
                    
                    // Also try to extract filename from the URL if available
                    if (!filename || filename.length < 3) {
                        const urlParams = new URLSearchParams(link.href.split('?')[1] || '');
                        filename = urlParams.get('filename') || urlParams.get('fn') || '';
                    }
                    
                    // Clean filename - remove duplicates and extra whitespace
                    if (filename) {
                        filename = filename.trim().replace(/\s+/g, ' ');
                        // Remove duplicate filename if it appears twice (common Gmail issue)
                        const words = filename.split(' ');
                        if (words.length > 1) {
                            const firstHalf = words.slice(0, Math.floor(words.length / 2)).join(' ');
                            const secondHalf = words.slice(Math.floor(words.length / 2)).join(' ');
                            if (firstHalf === secondHalf) {
                                filename = firstHalf;
                            }
                        }
                        // Remove file size info (e.g., "29 KB")
                        filename = filename.replace(/\d+(\.\d+)?\s?(KB|MB|GB|bytes?)\s*$/i, '').trim();
                    }
                    
                    // console.log(`  Cleaned filename: "${filename}"`);
                    
                    if (filename && filename.length > 0 && filename !== 'Download' && filename.length < 200) {
                        const riskAnalysis = analyzeFileRisk(filename);
                        
                        // Extract additional metadata from Gmail download URL
                        const urlParams = new URLSearchParams(link.href.split('?')[1] || '');
                        const attachmentId = urlParams.get('attid');
                        const fileSize = link.parentElement?.querySelector('[title*="KB"], [title*="MB"], [title*="GB"]')?.textContent?.match(/[\d.]+\s*[KMGT]?B/i)?.[0];
                        
                        emailDetails.attachments.push({
                            filename: filename,
                            downloadURL: link.href,
                            attachmentId: attachmentId,
                            fileSize: fileSize,
                            riskLevel: riskAnalysis.risk,
                            riskCategory: riskAnalysis.category,
                            riskDescription: riskAnalysis.description
                        });
                        // console.log(`  ✅ Added attachment: ${filename} [${riskAnalysis.risk} RISK - ${riskAnalysis.category}]`);
                    }
                });
            } else {
                // Process found attachment elements
                // console.log(`Processing ${attachmentElements.length} attachment elements...`);
                attachmentElements.forEach((attElement, index) => {
                    let filename = attElement.textContent.trim();
                    // console.log(`  Element ${index + 1}: "${filename}"`);
                    
                    // Clean filename - remove duplicates and extra whitespace
                    if (filename) {
                        filename = filename.trim().replace(/\s+/g, ' ');
                        // Remove duplicate filename if it appears twice
                        const words = filename.split(' ');
                        if (words.length > 1) {
                            const firstHalf = words.slice(0, Math.floor(words.length / 2)).join(' ');
                            const secondHalf = words.slice(Math.floor(words.length / 2)).join(' ');
                            if (firstHalf === secondHalf) {
                                filename = firstHalf;
                            }
                        }
                        // Remove file size info
                        filename = filename.replace(/\d+(\.\d+)?\s?(KB|MB|GB|bytes?)\s*$/i, '').trim();
                    }
                    
                    // console.log(`  Cleaned filename: "${filename}"`);
                    
                    const downloadLinkElement = attElement.closest('a') || 
                                              attElement.parentElement?.querySelector('a') ||
                                              attElement.querySelector('a');
                    const downloadURL = downloadLinkElement ? downloadLinkElement.href : null;
                    
                    // console.log(`  Download URL: ${downloadURL ? '[FOUND]' : '[NOT FOUND]'}`);

                    if (filename && filename.length > 0 && filename.length < 200) {
                        const riskAnalysis = analyzeFileRisk(filename);
                        
                        // Extract additional metadata
                        const fileSize = attElement.querySelector('[title*="KB"], [title*="MB"], [title*="GB"]')?.textContent?.match(/[\d.]+\s*[KMGT]?B/i)?.[0] ||
                                        attElement.parentElement?.textContent?.match(/[\d.]+\s*[KMGT]?B/i)?.[0];
                        
                        // Extract attachment ID from download URL if available
                        let attachmentId = null;
                        
                        if (downloadURL) {
                            const urlParams = new URLSearchParams(downloadURL.split('?')[1] || '');
                            attachmentId = urlParams.get('attid');
                        }
                        
                        emailDetails.attachments.push({
                            filename: filename,
                            downloadURL: downloadURL,
                            attachmentId: attachmentId,
                            fileSize: fileSize,
                            riskLevel: riskAnalysis.risk,
                            riskCategory: riskAnalysis.category,
                            riskDescription: riskAnalysis.description
                        });
                        // console.log(`  ✅ Added attachment: ${filename} [${riskAnalysis.risk} RISK - ${riskAnalysis.category}]`);
                    }
                });
            }
            
            // Strategy 5: Enhanced file extension pattern matching with security analysis
            if (emailDetails.attachments.length === 0) {
                // console.log("Strategy 5: File extension pattern matching with security analysis...");
                const emailContainer = document.querySelector('.nH.hx') || document.querySelector('.ii.gt') || document.body;
                const containerText = emailContainer.innerText;
                
                // Enhanced pattern matching including dangerous extensions and suspicious patterns
                // Pattern 1: Regular files with known extensions
                const filePattern = new RegExp(`(?:^|\\s)([^\\s\\/\\\\:*?"<>|]{1,100}\\.(${allExtensions}))(?:\\s|$)`, 'gi');
                let matches = containerText.match(filePattern) || [];
                
                // Pattern 2: Suspicious double extensions (e.g., file.exe.png, doc.scr.jpg)
                const doubleExtPattern = new RegExp(`(?:^|\\s)([^\\s\\/\\\\:*?"<>|]{1,100}\\.(exe|com|scr|bat|cmd|pif|msi|vbs|js|jar|py|sh)\\.(${allExtensions}))(?:\\s|$)`, 'gi');
                const doubleExtMatches = containerText.match(doubleExtPattern) || [];
                
                // Pattern 3: Multiple extensions (more than 2 dots)
                const multiExtPattern = new RegExp(`(?:^|\\s)([^\\s\\/\\\\:*?"<>|]{1,100}(?:\\.[a-zA-Z0-9]{1,10}){3,})(?:\\s|$)`, 'gi');
                const multiExtMatches = containerText.match(multiExtPattern) || [];
                
                // Combine all matches
                matches = [...matches, ...doubleExtMatches, ...multiExtMatches];
                
                if (matches.length > 0) {
                    // console.log(`Found ${matches.length} potential filenames in text (including suspicious patterns)`);
                    matches.forEach((match, index) => {
                        const filename = match.trim();
                        // console.log(`  Potential file ${index + 1}: "${filename}"`);
                        
                        // Only add if it looks like a reasonable filename
                        if (filename.length < 100 && filename.length > 5 && 
                            !emailDetails.attachments.some(att => att.filename === filename)) {
                            const riskAnalysis = analyzeFileRisk(filename);
                            emailDetails.attachments.push({
                                filename: filename,
                                downloadURL: null,
                                riskLevel: riskAnalysis.risk,
                                riskCategory: riskAnalysis.category,
                                riskDescription: riskAnalysis.description
                            });
                            // console.log(`  ✅ Added from text: ${filename} [${riskAnalysis.risk} RISK - ${riskAnalysis.category}]`);
                        }
                    });
                } else {
                    // console.log("  No file patterns found in text");
                }
            }
            
            // Strategy 6: Look for Gmail-specific attachment containers with security analysis
            if (emailDetails.attachments.length === 0) {
                // console.log("Strategy 6: Gmail attachment containers with security analysis...");
                const attachmentContainers = document.querySelectorAll('.aKu, .aKp, .aKr, [data-tooltip*="Download"], [aria-label*="Download"]');
                // console.log(`Found ${attachmentContainers.length} potential attachment containers`);
                
                attachmentContainers.forEach((container, index) => {
                    // console.log(`  Container ${index + 1}:`, container.className, '[TEXT CONTENT HIDDEN]');
                    
                    // Look for filenames within the container
                    const textContent = container.textContent.trim();
                    
                    // Pattern 1: Regular extensions
                    const filePattern = new RegExp(`[^\\s\\/\\\\:*?"<>|]{1,100}\\.(${allExtensions})`, 'gi');
                    let fileMatches = textContent.match(filePattern) || [];
                    
                    // Pattern 2: Suspicious double extensions
                    const doubleExtPattern = new RegExp(`[^\\s\\/\\\\:*?"<>|]{1,100}\\.(exe|com|scr|bat|cmd|pif|msi|vbs|js|jar|py|sh)\\.(${allExtensions})`, 'gi');
                    const doubleExtMatches = textContent.match(doubleExtPattern) || [];
                    
                    // Pattern 3: Multiple extensions
                    const multiExtPattern = new RegExp(`[^\\s\\/\\\\:*?"<>|]{1,100}(?:\\.[a-zA-Z0-9]{1,10}){3,}`, 'gi');
                    const multiExtMatches = textContent.match(multiExtPattern) || [];
                    
                    // Combine all matches
                    fileMatches = [...fileMatches, ...doubleExtMatches, ...multiExtMatches];
                    
                    if (fileMatches.length > 0) {
                        fileMatches.forEach(filename => {
                            if (!emailDetails.attachments.some(att => att.filename === filename)) {
                                const riskAnalysis = analyzeFileRisk(filename);
                                emailDetails.attachments.push({
                                    filename: filename,
                                    downloadURL: null,
                                    riskLevel: riskAnalysis.risk,
                                    riskCategory: riskAnalysis.category,
                                    riskDescription: riskAnalysis.description
                                });
                                // console.log(`  ✅ Added from container: ${filename} [${riskAnalysis.risk} RISK - ${riskAnalysis.category}]`);
                            }
                        });
                    }
                });
            }
            
            // Security Summary
            if (emailDetails.attachments.length > 0) {
                const riskSummary = {
                    critical: emailDetails.attachments.filter(att => att.riskLevel === 'CRITICAL').length,
                    high: emailDetails.attachments.filter(att => att.riskLevel === 'HIGH').length,
                    medium: emailDetails.attachments.filter(att => att.riskLevel === 'MEDIUM').length,
                    low: emailDetails.attachments.filter(att => att.riskLevel === 'LOW').length,
                    disguised: emailDetails.attachments.filter(att => att.riskCategory === 'disguised').length,
                    multiExtension: emailDetails.attachments.filter(att => att.riskCategory === 'multi-extension').length
                };
                
                // console.log(`🛡️ Security Analysis Summary:`);
                // console.log(`  🔴 CRITICAL Risk: ${riskSummary.critical} files`);
                // console.log(`  🟠 HIGH Risk: ${riskSummary.high} files`);
                // console.log(`  🟡 MEDIUM Risk: ${riskSummary.medium} files`);
                // console.log(`  🟢 LOW Risk: ${riskSummary.low} files`);
                
                if (riskSummary.disguised > 0) {
                    // console.log(`🚨 ALERT: ${riskSummary.disguised} DISGUISED EXECUTABLE(S) detected! These files are hiding malicious extensions behind safe-looking ones.`);
                }
                
                if (riskSummary.multiExtension > 0) {
                    // console.log(`⚠️ WARNING: ${riskSummary.multiExtension} file(s) with suspicious multiple extensions detected.`);
                }
                
                if (riskSummary.critical > 0) {
                    // console.log(`⚠️ WARNING: CRITICAL risk files detected! These can execute code on your system.`);
                }
            }
            
            // console.log(`📎 Final attachment count: ${emailDetails.attachments.length}`);

            // console.log("Email data extraction completed successfully");
            sendResponse({ success: true, data: emailDetails });

        } catch (error) {
            console.error("Error extracting email data:", error);
            sendResponse({ success: false, error: `Error extracting email data: ${error.message}` });
        }
    }
});