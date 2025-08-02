# Firefox Extension Packaging Script
Write-Host "Creating Firefox-compatible ZIP package..." -ForegroundColor Green
Write-Host ""

# Remove old zip if exists
if (Test-Path "gmail-vt-extension-firefox.zip") {
    Remove-Item "gmail-vt-extension-firefox.zip" -Force
    Write-Host "Removed existing ZIP file" -ForegroundColor Yellow
}

# Create ZIP with files at root level (not in a subfolder)
# Firefox requires forward slashes in ZIP paths, so we'll add individual icon files
$filesToZip = @(
    ".\manifest.json",
    ".\popup.html", 
    ".\popup.js",
    ".\content.js",
    ".\background.js",
    ".\LICENSE",
    ".\icons\icon16.png",
    ".\icons\icon48.png", 
    ".\icons\icon128.png"
)

try {
    # Create temporary directory structure for proper ZIP creation
    $tempDir = ".\temp_firefox_build"
    if (Test-Path $tempDir) {
        Remove-Item $tempDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    New-Item -ItemType Directory -Path "$tempDir\icons" -Force | Out-Null
    
    # Copy files to temp directory
    Copy-Item ".\manifest.json" "$tempDir\" -Force
    Copy-Item ".\popup.html" "$tempDir\" -Force
    Copy-Item ".\popup.js" "$tempDir\" -Force
    Copy-Item ".\content.js" "$tempDir\" -Force
    Copy-Item ".\background.js" "$tempDir\" -Force
    Copy-Item ".\LICENSE" "$tempDir\" -Force
    Copy-Item ".\icons\*.png" "$tempDir\icons\" -Force
    
    # Create ZIP from temp directory contents with proper path separators
    $zipPath = ".\gmail-vt-extension-firefox.zip"
    
    # Load required assemblies
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, 'Create')
    
    $tempFiles = Get-ChildItem -Path $tempDir -Recurse -File
    
    foreach ($file in $tempFiles) {
        $relativePath = $file.FullName.Substring((Resolve-Path $tempDir).Path.Length + 1)
        # Convert backslashes to forward slashes for Firefox compatibility
        $zipEntryName = $relativePath -replace '\\', '/'
        
        Write-Host "Adding: $zipEntryName" -ForegroundColor Gray
        
        $zipEntry = $zip.CreateEntry($zipEntryName)
        $zipEntryStream = $zipEntry.Open()
        $fileStream = [System.IO.File]::OpenRead($file.FullName)
        
        $fileStream.CopyTo($zipEntryStream)
        
        $fileStream.Close()
        $zipEntryStream.Close()
    }
    
    $zip.Dispose()
    
    # Clean up temp directory
    Remove-Item $tempDir -Recurse -Force
    
    Write-Host ""
    Write-Host "✅ Firefox-compatible ZIP created: gmail-vt-extension-firefox.zip" -ForegroundColor Green
    Write-Host ""
    Write-Host "The ZIP file contains files at the root level with proper path separators for Firefox." -ForegroundColor Cyan
    Write-Host "Upload this ZIP file to Firefox Add-ons for validation." -ForegroundColor Cyan
} catch {
    Write-Host "❌ Error creating ZIP file: $($_.Exception.Message)" -ForegroundColor Red
    # Clean up temp directory if it exists
    if (Test-Path $tempDir) {
        Remove-Item $tempDir -Recurse -Force
    }
}

Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
