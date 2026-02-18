param(
  [string]$BaseUrl = "http://127.0.0.1:8000"
)

$ErrorActionPreference = "Stop"

Write-Host "Checking $BaseUrl/ready ..."
$response = Invoke-RestMethod -Method Get -Uri "$BaseUrl/ready"
$response | ConvertTo-Json -Depth 10
