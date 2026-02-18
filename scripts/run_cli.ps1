param(
  [string]$PythonExe = "python"
)

$ErrorActionPreference = "Stop"
$env:PYTHONUNBUFFERED = "1"
& $PythonExe "oneseam.py"
