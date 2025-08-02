@echo off
echo Creating Firefox-compatible ZIP package...
echo.

REM Remove old zip if exists
if exist "gmail-vt-extension-firefox.zip" del "gmail-vt-extension-firefox.zip"

REM Create ZIP with files at root level (not in a subfolder)
REM Firefox requires forward slashes in ZIP paths, so we use PowerShell method
powershell -Command "& {Add-Type -AssemblyName System.IO.Compression.FileSystem; $tempDir='.\temp_firefox_build'; if(Test-Path $tempDir){Remove-Item $tempDir -Recurse -Force}; New-Item -ItemType Directory -Path $tempDir -Force | Out-Null; New-Item -ItemType Directory -Path '$tempDir\icons' -Force | Out-Null; Copy-Item '.\manifest.json' '$tempDir\' -Force; Copy-Item '.\popup.html' '$tempDir\' -Force; Copy-Item '.\popup.js' '$tempDir\' -Force; Copy-Item '.\content.js' '$tempDir\' -Force; Copy-Item '.\background.js' '$tempDir\' -Force; Copy-Item '.\icons\*.png' '$tempDir\icons\' -Force; $tempFiles = Get-ChildItem -Path $tempDir -Recurse -File; $zipPath='.\gmail-vt-extension-firefox.zip'; if(Test-Path $zipPath){Remove-Item $zipPath -Force}; $zip=[System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create); foreach($file in $tempFiles){$relativePath=$file.FullName.Substring($tempDir.Length + 1); $zipEntryName=$relativePath -replace '\\\\', '/'; $zipEntry=$zip.CreateEntry($zipEntryName); $zipEntryStream=$zipEntry.Open(); $fileStream=[System.IO.File]::OpenRead($file.FullName); $fileStream.CopyTo($zipEntryStream); $fileStream.Close(); $zipEntryStream.Close()}; $zip.Dispose(); Remove-Item $tempDir -Recurse -Force}"

echo.
echo ✅ Firefox-compatible ZIP created: gmail-vt-extension-firefox.zip
echo.
echo The ZIP file contains files at the root level as required by Firefox.
echo Upload this ZIP file to Firefox Add-ons for validation.
echo.
pause
