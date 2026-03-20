# Cyber Triage Universal Launcher
# Use this to safely launch the full suite using the correct Python installation.

$pythonDir = "C:\Users\ASUS\AppData\Local\Programs\Python"
$pyBin = Get-ChildItem -Path $pythonDir -Filter "python.exe" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName

if ($pyBin) {
    Write-Host "-> Found Python at: $pyBin"
    Write-Host "-> Starting Cyber Triage OS Suite..."
    & $pyBin run_all.py
} else {
    Write-Host "[ERROR] Could not locate your Python installation."
    Write-Host "Try running: python run_all.py manually."
}
