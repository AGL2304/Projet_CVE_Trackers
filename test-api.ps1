$baseURL = "http://localhost:3000"

Write-Host "`n=== Test API CVE Tracker ===" -ForegroundColor Cyan

# 1. Verifier le serveur
try {
    $stats = Invoke-RestMethod -Uri "$baseURL/api/dashboard/stats" -Method GET
    Write-Host "`nOK Serveur en ligne" -ForegroundColor Green
    Write-Host "   Actifs: $($stats.totalAssets)" -ForegroundColor White
    Write-Host "   Vulnerabilites: $($stats.totalVulnerabilities)" -ForegroundColor White
} catch {
    Write-Host "`nERREUR: Le serveur n'est pas demarre" -ForegroundColor Red
    Write-Host "   Lancez: bun run dev" -ForegroundColor Yellow
    exit
}

# 2. Charger les donnees factices
Write-Host "`nChargement des donnees factices..." -ForegroundColor Yellow
$seed = Invoke-RestMethod -Uri "$baseURL/api/seed" -Method POST
Write-Host "OK Donnees chargees" -ForegroundColor Green
Write-Host "   Actifs: $($seed.assetsCreated)" -ForegroundColor White
Write-Host "   Vulnerabilites: $($seed.vulnerabilitiesCreated)" -ForegroundColor White

# 3. Creer un actif de test
Write-Host "`nCreation d'un actif de test..." -ForegroundColor Yellow
$newAsset = @{
    name = "Test PowerShell Actif"
    type = "server"
    ip = "10.0.0.1"
    hostname = "test-powershell"
    criticality = "medium"
    status = "active"
} | ConvertTo-Json

$createdAsset = Invoke-RestMethod -Uri "$baseURL/api/assets" -Method POST -Body $newAsset -ContentType "application/json"
Write-Host "OK Actif cree" -ForegroundColor Green
Write-Host "   ID: $($createdAsset.id)" -ForegroundColor White
Write-Host "   Nom: $($createdAsset.name)" -ForegroundColor White

Write-Host "`nTous les tests reussis !" -ForegroundColor Green
