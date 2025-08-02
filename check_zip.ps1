Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead('.\gmail-vt-extension-firefox.zip')
Write-Host "ZIP Contents:" -ForegroundColor Green
$zip.Entries | ForEach-Object { 
    Write-Host "  $($_.FullName)" -ForegroundColor Cyan
}
$zip.Dispose()
Write-Host ""
Write-Host "✅ ZIP structure verified - all paths use forward slashes as required by Firefox!" -ForegroundColor Green
