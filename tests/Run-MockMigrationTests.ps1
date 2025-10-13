using module ..\src\AzureRbacManager.psm1

<#
 Script de testes mock para validar fluxo Export/Import RG RBAC sem chamadas reais ao Azure.
 Gera assignments sintéticos e verifica relatório.
#>
param(
    [string]$OutputDir = 'output/tests'
)

$ErrorActionPreference = 'Stop'
Write-Host '== Iniciando testes mock de migração RG RBAC ==' -ForegroundColor Cyan

# (AzureRbacManager carregado em tempo de parse via 'using module')

class MockAuthenticator {
    [hashtable] GetAuthHeaders() { return @{ Authorization = 'Bearer MOCK' } }
}

class MockAzureRbacManager : AzureRbacManager {
    [string]$TestSourceSub
    [string]$TestTargetSub
    [string]$TestSourceRg
    [string]$TestTargetRg
    [string]$ExistingResourceRelative
    [System.Collections.Generic.HashSet[string]]$CreatedAssignments

    MockAzureRbacManager([object]$auth) : base($auth) {
        $this.TestSourceSub = '11111111-1111-1111-1111-111111111111'
        $this.TestTargetSub = '22222222-2222-2222-2222-222222222222'
        $this.TestSourceRg = 'rg-source'
        $this.TestTargetRg = 'rg-target'
        $this.ExistingResourceRelative = '/providers/Microsoft.Storage/storageAccounts/st1'
        $this.CreatedAssignments = [System.Collections.Generic.HashSet[string]]::new()
    }

    [RbacAssignment[]] GetRbacAssignmentsForResourceGroupRecursive([string]$subscriptionId, [string]$resourceGroupName) {
        # Três assignments: nível RG, recurso existente, recurso que será mapeado para recurso inexistente
        $list = @()
        $baseScope = "/subscriptions/$($this.TestSourceSub)/resourceGroups/$($this.TestSourceRg)"
        $rgAssign = [RbacAssignment]::new(); $rgAssign.Id = "$baseScope/providers/Microsoft.Authorization/roleAssignments/rgRole"; $rgAssign.Scope = $baseScope; $rgAssign.PrincipalId = '00000000-0000-0000-0000-000000000001'; $rgAssign.PrincipalType='User'; $rgAssign.RoleDefinitionId="/subscriptions/$($this.TestSourceSub)/providers/Microsoft.Authorization/roleDefinitions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"; $rgAssign.RoleName='Owner'; $list += $rgAssign
        $res1Scope = "$baseScope$($this.ExistingResourceRelative)"; $res1 = [RbacAssignment]::new(); $res1.Id = "$res1Scope/providers/Microsoft.Authorization/roleAssignments/res1"; $res1.Scope=$res1Scope; $res1.PrincipalId='00000000-0000-0000-0000-000000000002'; $res1.PrincipalType='ServicePrincipal'; $res1.RoleDefinitionId="/subscriptions/$($this.TestSourceSub)/providers/Microsoft.Authorization/roleDefinitions/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"; $res1.RoleName='Reader'; $list += $res1
        $res2Scope = "$baseScope/providers/Microsoft.ServiceBus/namespaces/ns1"; $res2 = [RbacAssignment]::new(); $res2.Id="$res2Scope/providers/Microsoft.Authorization/roleAssignments/res2"; $res2.Scope=$res2Scope; $res2.PrincipalId='00000000-0000-0000-0000-000000000003'; $res2.PrincipalType='Group'; $res2.RoleDefinitionId="/subscriptions/$($this.TestSourceSub)/providers/Microsoft.Authorization/roleDefinitions/cccccccc-cccc-cccc-cccc-cccccccccccc"; $res2.RoleName='CustomAppRole'; $list += $res2
        return $list
    }

    [bool] RoleDefinitionExists([string]$roleDefinitionId) {
        # Considera inexistente GUID cccccccc...
        if ($roleDefinitionId -match 'cccccccc-cccc-cccc-cccc-cccccccccccc') { return $false }
        return $true
    }

    [bool] RbacAssignmentExists([string]$scope, [string]$principalId, [string]$roleDefinitionId) {
        # Marca duplicado para res1 assignment (GUID bbbbbbbb, principal 0002)
        if ($scope -match 'storageAccounts/st1' -and $principalId -eq '00000000-0000-0000-0000-000000000002') { return $true }
        return $false
    }

    [bool] CreateRbacAssignment([string]$scope, [hashtable]$payload) {
        $key = "$($payload.properties.principalId)|$($payload.properties.roleDefinitionId)|$scope"
        $this.CreatedAssignments.Add($key) | Out-Null
        Write-Host "[MOCK] Create assignment => $key" -ForegroundColor Green
        return $true
    }

    [PSCustomObject] InvokeAzureRestApi([string]$uri, [string]$method, [string]$body = $null) {
        # Simula existência apenas do RG e do resource relativo ExistingResourceRelative
        if ($method -eq 'GET') {
            if ($uri -match '/resourceGroups/rg-target($|\?)') { return [pscustomobject]@{ id='rg-target'} }
            if ($uri -match '/resourceGroups/rg-target/providers/Microsoft\.Storage/storageAccounts/st1') { return [pscustomobject]@{ id='storageAccounts/st1'} }
            if ($uri -match 'storageAccounts/st1') { return [pscustomobject]@{ id='storageAccounts/st1-alt'} }
            if ($uri -match [regex]::Escape($this.ExistingResourceRelative)) { return [pscustomobject]@{ id='existingResource'} }
            throw [System.Exception]::new('NotFound')
        }
        return [pscustomobject]@{}
    }
}

# Instancia mocks
$auth = [MockAuthenticator]::new()
$mockMgr = [MockAzureRbacManager]::new($auth)

# Garante diretórios
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$exportFile = Join-Path $OutputDir 'export.json'
$rgMapFile = Join-Path $OutputDir 'rg-mapping.csv'
$resMapFile = Join-Path $OutputDir 'resource-mapping.csv'
$reportFile = Join-Path $OutputDir 'report.json'

# Cria CSVs
@"
SourceSubscriptionId,SourceResourceGroup,TargetSubscriptionId,TargetResourceGroup
$($mockMgr.TestSourceSub),$($mockMgr.TestSourceRg),$($mockMgr.TestTargetSub),$($mockMgr.TestTargetRg)
"@ | Out-File -FilePath $rgMapFile -Encoding UTF8 -Force

@"
SourceScopeRelative,TargetScopeRelative,PrincipalRemap,RoleRemap
/providers/Microsoft.Storage/storageAccounts/st1,/providers/Microsoft.Storage/storageAccounts/st1,,
/providers/Microsoft.ServiceBus/namespaces/ns1,/providers/Microsoft.ServiceBus/namespaces/nsX,,
/,,,
"@ | Out-File -FilePath $resMapFile -Encoding UTF8 -Force

Write-Host '>> Executando Export-RgRbacAssignments (mock)' -ForegroundColor Yellow
$count = Export-RgRbacAssignments -RbacManager $mockMgr -SourceSubscriptionId $mockMgr.TestSourceSub -SourceResourceGroup $mockMgr.TestSourceRg -OutputFile $exportFile -Verbose:$false
Write-Host "Assignments exportados: $count" -ForegroundColor Gray

Write-Host '>> Executando Import-RgRbacAssignments (WhatIf)' -ForegroundColor Yellow
Import-RgRbacAssignments -RbacManager $mockMgr -InputFile $exportFile -RgMappingFile $rgMapFile -ResourceMappingFile $resMapFile -ReportFile $reportFile -PreserveHierarchy -WhatIfMode -Verbose:$false

$report = Get-Content -Path $reportFile -Raw | ConvertFrom-Json
Write-Host 'Relatório (resumo):' -ForegroundColor Cyan
Write-Host ("Processados: {0} Criados(WhatIf): {1} Skipped: {2} Errors: {3}" -f $report.totals.processed,$report.totals.created,$report.totals.skipped,$report.totals.errors) -ForegroundColor Gray
Write-Host 'Level Stats:' -ForegroundColor Cyan
Write-Host ($report.levelStats | ConvertTo-Json -Depth 3) -ForegroundColor DarkGray
Write-Host 'Missing resources:' -ForegroundColor Cyan
Write-Host ($report.missingResources -join '; ') -ForegroundColor DarkYellow

if ($report.totals.processed -ne 3) { throw 'Esperado 3 assignments processados' }
if ($report.totals.created -lt 1) { throw 'Esperado pelo menos 1 criação simulada' }
if (-not ($report.items | Where-Object { $_.action -eq 'SkipRoleNotFound' })) { throw 'Esperado SkipRoleNotFound para custom role inexistente' }
if (-not ($report.items | Where-Object { $_.action -eq 'SkipDuplicate' })) { throw 'Esperado SkipDuplicate para recurso duplicado' }

Write-Host '== Testes mock concluídos com sucesso ==' -ForegroundColor Green
