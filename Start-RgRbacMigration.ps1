<#
.SYNOPSIS
    Migração direta de RBAC entre Resource Groups (recursivo) com renomeação de recursos.
.DESCRIPTION
    Orquestra exportação e importação de assignments RBAC de um RG origem para um RG destino,
    aplicando dois arquivos de mapping (RG e Recursos). Suporta WhatIf e preservação opcional
    da hierarquia de recursos.
.PARAMETER SourceSubscriptionId
    Subscription de origem.
.PARAMETER SourceResourceGroup
    Resource Group de origem.
.PARAMETER TargetSubscriptionId
    Subscription de destino.
.PARAMETER TargetResourceGroup
    Resource Group de destino.
.PARAMETER RgMappingFile
    CSV com: SourceSubscriptionId,SourceResourceGroup,TargetSubscriptionId,TargetResourceGroup
.PARAMETER ResourceMappingFile
    CSV com: SourceScopeRelative,TargetScopeRelative,PrincipalRemap,RoleRemap
.PARAMETER PreserveHierarchy
    Mantém a hierarquia de scopes dos recursos origem (se omitido, faz flatten no RG destino).
.PARAMETER WhatIf
    Simula a importação sem criar assignments.
.PARAMETER ExportFile
    Caminho opcional para salvar export intermediário (default: output/rg-rbac-export.json).
.PARAMETER ReportFile
    Caminho para relatório final (default: output/rg-rbac-import-report.json).
.EXAMPLE
    .\Start-RgRbacMigration.ps1 -SourceSubscriptionId subA -SourceResourceGroup rgA -TargetSubscriptionId subB -TargetResourceGroup rgB -RgMappingFile config/rg-mapping.csv -ResourceMappingFile config/resource-mapping.csv -PreserveHierarchy -WhatIf
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory)] [string]$SourceSubscriptionId,
    [Parameter(Mandatory)] [string]$SourceResourceGroup,
    [Parameter(Mandatory)] [string]$TargetSubscriptionId,
    [Parameter(Mandatory)] [string]$TargetResourceGroup,
    [Parameter(Mandatory)] [string]$RgMappingFile,
    [string]$ResourceMappingFile = 'config/resource-mapping.csv',
    [switch]$PreserveHierarchy,
    [switch]$DryRun, # evita conflito com ShouldProcess -WhatIf
    [string]$ExportFile = 'output/rg-rbac-export.json',
    [string]$ReportFile = 'output/rg-rbac-import-report.json'
)

$ErrorActionPreference = 'Stop'

Write-Host '=== Migração RBAC RG->RG Iniciada ===' -ForegroundColor Cyan
Write-Host "Origem: $SourceSubscriptionId / $SourceResourceGroup" -ForegroundColor Gray
Write-Host "Destino: $TargetSubscriptionId / $TargetResourceGroup" -ForegroundColor Gray

# Carrega módulos locais
Import-Module (Join-Path $PSScriptRoot 'src/AzureAuthenticator.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src/AzureRbacManager.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src/Logger.psm1') -Force

# Config / Service Principal (opcionalmente reutiliza config.json se existir)
$spTenant = $env:AZ_TENANT_ID
$spClientId = $env:AZ_CLIENT_ID
$spClientSecret = $env:AZ_CLIENT_SECRET
if (-not $spTenant -or -not $spClientId -or -not $spClientSecret) {
    $configPath = Join-Path $PSScriptRoot 'config/config.json'
    if (Test-Path $configPath) {
        $cfg = Get-Content -Path $configPath -Raw | ConvertFrom-Json
        $spTenant = $cfg.ServicePrincipal.TenantId
        $spClientId = $cfg.ServicePrincipal.ClientId
        $spClientSecret = $cfg.ServicePrincipal.ClientSecret
    } else {
        throw 'Credenciais do Service Principal não encontradas em variáveis de ambiente nem em config.json'
    }
}

$logger = New-Logger -LogDirectory (Join-Path $PSScriptRoot 'logs') -MinLogLevel Information
$secureSecret = if ($spClientSecret -is [System.Security.SecureString]) { $spClientSecret } else { ConvertTo-SecureString -String $spClientSecret -AsPlainText -Force }
$auth = New-AzureAuthenticator -TenantId $spTenant -ClientId $spClientId -ClientSecret $secureSecret
$rbac = New-AzureRbacManager -Authenticator $auth

# Export
Write-Host 'Exportando RBAC recursivo...' -ForegroundColor Cyan
$exportCount = Export-RgRbacAssignments -RbacManager $rbac -SourceSubscriptionId $SourceSubscriptionId -SourceResourceGroup $SourceResourceGroup -OutputFile $ExportFile -Verbose:$VerbosePreference
Write-Host "Assignments exportados: $exportCount" -ForegroundColor Green

# Prepara arquivo de mapping RG se não existir (auto-gerar opcional)
if (-not (Test-Path $RgMappingFile)) {
    Write-Warning "RgMappingFile não encontrado. Gerando modelo em $RgMappingFile";
    $dir = Split-Path -Path $RgMappingFile -Parent; if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    @"
SourceSubscriptionId,SourceResourceGroup,TargetSubscriptionId,TargetResourceGroup
$SourceSubscriptionId,$SourceResourceGroup,$TargetSubscriptionId,$TargetResourceGroup
"@ | Out-File -FilePath $RgMappingFile -Encoding UTF8 -Force
}

if (-not (Test-Path $ResourceMappingFile)) {
    Write-Warning "ResourceMappingFile não encontrado. Gerando modelo em $ResourceMappingFile";
    $dir2 = Split-Path -Path $ResourceMappingFile -Parent; if ($dir2 -and -not (Test-Path $dir2)) { New-Item -ItemType Directory -Path $dir2 -Force | Out-Null }
    @"
SourceScopeRelative,TargetScopeRelative,PrincipalRemap,RoleRemap
/,,,
"@ | Out-File -FilePath $ResourceMappingFile -Encoding UTF8 -Force
}

# Import
Write-Host 'Importando RBAC no destino...' -ForegroundColor Cyan
$importParams = @{ RbacManager = $rbac; InputFile = $ExportFile; RgMappingFile = $RgMappingFile; ResourceMappingFile = $ResourceMappingFile; ReportFile = $ReportFile }
if ($PreserveHierarchy) { $importParams.PreserveHierarchy = $true }
if ($DryRun) { $importParams.WhatIfMode = $true }
Import-RgRbacAssignments @importParams -Verbose:$VerbosePreference

Write-Host '=== Migração RBAC RG->RG Finalizada ===' -ForegroundColor Cyan
