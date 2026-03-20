# Cyber Triage Test Runner
# Use this script to verify the system logic.

Write-Host "Checking for Python..."
if (Get-Command python -ErrorAction SilentlyContinue) {
    Write-Host "Running Cyber Triage Unit Tests..."
    python tests/test_all.py
} else {
    Write-Host "Error: Python not found in PATH."
    Write-Host "Please install Python and run: python tests/test_all.py"
}
