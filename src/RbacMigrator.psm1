# =============================================================================
# Azure RBAC Import Automation - RBAC Migrator Module
# =============================================================================
# Este módulo implementa a migração direta de permissões RBAC usando transformação
# baseada em CSV simples (Source → Target), verificação de existência e importação
# seletiva apenas das permissões que não existem no destino.
# =============================================================================

using module ".\Logger.psm1"
using module ".\AzureAuthenticator.psm1"
using module ".\AzureRbacManager.psm1"

class MappingRule {
    [string]$Source
    [string]$Target
    [string]$Type
    
    MappingRule([string]$source, [string]$target, [string]$type = "General") {
        $this.Source = $source
        $this.Target = $target
        $this.Type = $type
    }
    
    [string] ApplyTransformation([string]$value) {
        # Evita transformações desnecessárias
        if ([string]::IsNullOrEmpty($value) -or [string]::IsNullOrEmpty($this.Source)) {
            return $value
        }
        
        if ($value.Contains($this.Source)) {
            $newValue = $value.Replace($this.Source, $this.Target)
            # Só retorna se houve mudança real
            if ($newValue -ne $value) {
                return $newValue
            }
        }
        return $value
    }
    
    [string] ToString() {
        return "$($this.Source) → $($this.Target) [$($this.Type)]"
    }
}

class RbacPermission {
    [hashtable]$Properties
    [string]$Id
    [string]$Type
    [string]$Name
    [string]$RoleDefinitionName
    [bool]$IsTransformed = $false
    [System.Collections.ArrayList]$AppliedTransformations
    
    # Construtor padrão
    RbacPermission() {
        $this.Properties = @{}
        $this.AppliedTransformations = [System.Collections.ArrayList]::new()
    }
    
    RbacPermission([PSCustomObject]$rbacObject) {
        $this.Properties = @{}
        foreach ($prop in $rbacObject.properties.PSObject.Properties) {
            $this.Properties[$prop.Name] = $prop.Value
        }
        
        $this.Id = $rbacObject.id
        $this.Type = $rbacObject.type
        $this.Name = $rbacObject.name
        $this.RoleDefinitionName = $rbacObject.roleDefinitionName
        $this.AppliedTransformations = [System.Collections.ArrayList]::new()
    }
    
    [void] ApplyTransformation([MappingRule]$rule) {
        $transformationApplied = $false
        
        # Cria uma nova hashtable com todas as transformações aplicadas
        $newProperties = @{}
        
        # Cria um array das chaves primeiro para evitar modificação durante iteração
        $allKeys = @($this.Properties.Keys)
        
        foreach ($key in $allKeys) {
            $originalValue = $this.Properties[$key]
            $newValue = $rule.ApplyTransformation($originalValue)
            $newProperties[$key] = $newValue
            
            # Só loga se houve mudança real e não é vazio/null
            if ($originalValue -ne $newValue -and 
                -not ([string]::IsNullOrEmpty($originalValue) -and [string]::IsNullOrEmpty($newValue))) {
                Write-Host "  ⚡ Transformação: $key ($($rule.Type))" -ForegroundColor Cyan
                Write-Host "      De: $originalValue" -ForegroundColor Gray
                Write-Host "      Para: $newValue" -ForegroundColor Green
                $transformationApplied = $true
            }
        }
        
        # Substitui completamente o hashtable
        $this.Properties = $newProperties
        
        # Aplica transformação no ID
        if ($this.Id -and $this.Id.Contains($rule.Source)) {
            $originalId = $this.Id
            $this.Id = $this.Id.Replace($rule.Source, $rule.Target)
            Write-Host "  ⚡ Transformação: id" -ForegroundColor Cyan
            Write-Host "      De: $originalId" -ForegroundColor Gray
            Write-Host "      Para: $($this.Id)" -ForegroundColor Green
            $this.AppliedTransformations.Add("id: $originalId → $($this.Id)") | Out-Null
            $transformationApplied = $true
        }
        
        if ($transformationApplied) {
            $this.IsTransformed = $true
        }
    }
    
    [hashtable] GetComparisonHash() {
        # Retorna hash para comparação ignorando campos temporais
        $compareHash = @{}
        
        foreach ($key in $this.Properties.Keys) {
            if ($key -notin @('createdOn', 'updatedOn', 'createdBy', 'updatedBy')) {
                $compareHash[$key] = $this.Properties[$key]
            }
        }
        
        $compareHash['type'] = $this.Type
        $compareHash['roleDefinitionName'] = $this.RoleDefinitionName
        
        return $compareHash
    }
    
    [hashtable] GetCreatePayload() {
        return @{
            properties = @{
                principalId = $this.Properties.principalId
                roleDefinitionId = $this.Properties.roleDefinitionId
                principalType = $this.Properties.principalType
            }
        }
    }
    
    [string] GetTargetScope() {
        return $this.Properties.scope
    }
    
    [string] ToString() {
        return "[$($this.RoleDefinitionName)] $($this.Properties.principalType):$($this.Properties.principalId) → $($this.Properties.scope)"
    }
}

class RbacMigrator {
    [object]$Logger
    [object]$Authenticator
    [object]$RbacManager
    [MappingRule[]]$MappingRules = @()
    [RbacPermission[]]$SourcePermissions = @()
    [RbacPermission[]]$TransformedPermissions = @()
    [RbacPermission[]]$PermissionsToImport = @()
    [RbacPermission[]]$DuplicateAssignments = @()
    [hashtable]$Statistics = @{}
    
    RbacMigrator([object]$logger, [object]$authenticator, [object]$rbacManager) {
        $this.Logger = $logger
        $this.Authenticator = $authenticator
        $this.RbacManager = $rbacManager
        $this.InitializeStatistics()
    }
    
    [void] InitializeStatistics() {
        $this.Statistics = @{
            SourcePermissionsLoaded = 0
            MappingRulesLoaded = 0
            TransformationsApplied = 0
            PermissionsTransformed = 0
            ExistingPermissionsFound = 0
            PermissionsToImport = 0
            ImportedSuccessfully = 0
            ImportErrors = 0
            StartTime = Get-Date
            EndTime = $null
        }
    }
    
    [bool] LoadMappingRules([string]$csvFilePath) {
        try {
            $this.Logger.LogInfo([LogCategory]::CsvProcessing, "Carregando regras de mapeamento", $csvFilePath, @{})
            
            if (-not (Test-Path -Path $csvFilePath)) {
                throw "Arquivo CSV não encontrado: $csvFilePath"
            }
            
            $csvData = Import-Csv -Path $csvFilePath -Encoding UTF8
            $this.MappingRules = @()
            
            foreach ($row in $csvData) {
                if (-not [string]::IsNullOrWhiteSpace($row.Source) -and -not [string]::IsNullOrWhiteSpace($row.Target)) {
                    $type = if ($row.PSObject.Properties.Name -contains "Type" -and -not [string]::IsNullOrWhiteSpace($row.Type)) {
                        $row.Type.Trim()
                    } else {
                        "General"
                    }
                    
                    $rule = [MappingRule]::new($row.Source.Trim(), $row.Target.Trim(), $type)
                    $this.MappingRules += $rule
                    
                    $this.Logger.LogVerbose([LogCategory]::CsvProcessing, "Regra de mapeamento carregada", $rule.ToString(), @{})
                }
            }
            
            $this.Statistics.MappingRulesLoaded = $this.MappingRules.Count
            $this.Logger.LogInfo([LogCategory]::CsvProcessing, "Regras de mapeamento carregadas", "$($this.MappingRules.Count) regras", @{})
            
            return $this.MappingRules.Count -gt 0
        }
        catch {
            $this.Logger.LogError([LogCategory]::CsvProcessing, "Erro ao carregar regras de mapeamento", $_.Exception.Message, @{})
            return $false
        }
    }
    
    # Carrega dados de origem diretamente da subscription (fluxo original)
    [bool] LoadSourceData([string]$subscriptionId, [string[]]$resourceGroupNames = @()) {
        try {
            $this.Logger.LogInfo([LogCategory]::RbacExport, "Carregando dados da subscription origem", $subscriptionId, @{})
            
            # Usa o método otimizado GetRbacAssignmentsForSubscription
            $assignments = $this.RbacManager.GetRbacAssignmentsForSubscription($subscriptionId, $resourceGroupNames)
            
            # Converte RbacAssignment objects para RbacPermission objects
            $this.SourcePermissions = @()
            foreach ($assignment in $assignments) {
                $permission = [RbacPermission]::new()
                $permission.Properties.roleDefinitionId = $assignment.RoleDefinitionId
                $permission.Properties.principalId = $assignment.PrincipalId
                $permission.Properties.principalType = $assignment.PrincipalType
                $permission.Properties.scope = $assignment.Scope
                $permission.Properties.createdOn = $assignment.CreatedOn
                $permission.Properties.updatedOn = $assignment.UpdatedOn
                $permission.Properties.createdBy = $assignment.CreatedBy
                $permission.Properties.updatedBy = $assignment.UpdatedBy
                $permission.Properties.condition = $assignment.Condition
                $permission.Properties.conditionVersion = $assignment.ConditionVersion
                $permission.Properties.description = $assignment.Description
                $permission.Properties.delegatedManagedIdentityResourceId = $assignment.DelegatedManagedIdentityResourceId
                $permission.RoleDefinitionName = $assignment.RoleName
                $permission.Type = $assignment.Type
                $permission.Name = $assignment.Name
                $permission.Id = $assignment.Id
                
                $this.SourcePermissions += $permission
            }
            
            $this.Statistics.SourcePermissionsLoaded = $this.SourcePermissions.Count
            $this.Logger.LogInfo([LogCategory]::RbacExport, "Dados carregados da subscription", "", @{
                TotalPermissions = $this.SourcePermissions.Count
            })
            
            return $true
        }
        catch {
            $this.Logger.LogError([LogCategory]::RbacExport, "Erro ao carregar dados da subscription", $_.Exception.Message, @{
                SubscriptionId = $subscriptionId
            })
            return $false
        }
    }
    
    [bool] LoadSourcePermissions([string]$jsonFilePath) {
        try {
            $this.Logger.LogInfo([LogCategory]::RbacExport, "Carregando permissões de origem", $jsonFilePath, @{})
            
            if (-not (Test-Path -Path $jsonFilePath)) {
                throw "Arquivo JSON não encontrado: $jsonFilePath"
            }
            
            $jsonContent = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json
            
            # Verifica se é o formato da API (com "value") ou formato direto (array)
            $rbacObjects = if ($jsonContent.value) {
                $jsonContent.value  # Formato da API: { "value": [...] }
            } else {
                $jsonContent        # Formato direto: [...]
            }
            
            $this.SourcePermissions = @()
            
            foreach ($rbacObject in $rbacObjects) {
                $permission = [RbacPermission]::new($rbacObject)
                $this.SourcePermissions += $permission
            }
            
            $this.Statistics.SourcePermissionsLoaded = $this.SourcePermissions.Count
            $this.Logger.LogInfo([LogCategory]::RbacExport, "Permissões de origem carregadas", "$($this.SourcePermissions.Count) permissões", @{})
            
            return $this.SourcePermissions.Count -gt 0
        }
        catch {
            $this.Logger.LogError([LogCategory]::RbacExport, "Erro ao carregar permissões de origem", $_.Exception.Message, @{})
            return $false
        }
    }
    
    [bool] ApplyTransformations() {
        try {
            $this.Logger.LogInfo([LogCategory]::RbacImport, "Iniciando aplicação de transformações", "", @{})
            
            $transformedList = @()
            $transformationsApplied = 0
            $permissionsTransformed = 0
            
            foreach ($permission in $this.SourcePermissions) {
                $originalPermission = $permission.ToString()
                $transformationCount = 0
                
                # Aplica todas as regras de mapeamento na permissão
                foreach ($rule in $this.MappingRules) {
                    $beforeTransformation = $permission.IsTransformed
                    $permission.ApplyTransformation($rule)
                    
                    if ($permission.IsTransformed -and -not $beforeTransformation) {
                        $transformationCount++
                    }
                }
                
                if ($permission.IsTransformed) {
                    $permissionsTransformed++
                    $transformationsApplied += $permission.AppliedTransformations.Count
                    
                    $this.Logger.LogVerbose([LogCategory]::RbacImport, "Permissão transformada", 
                        "Original: $originalPermission | Transformada: $($permission.ToString())", @{
                            TransformationsApplied = $permission.AppliedTransformations
                        })
                }
                
                $transformedList += $permission
            }
            
            # Atualiza a propriedade apenas após completar a iteração
            $this.TransformedPermissions = $transformedList
            
            $this.Statistics.TransformationsApplied = $transformationsApplied
            $this.Statistics.PermissionsTransformed = $permissionsTransformed
            
            $this.Logger.LogInfo([LogCategory]::RbacImport, "Transformações aplicadas", 
                "$transformationsApplied transformações em $permissionsTransformed permissões", @{})
            
            # Retorna true mesmo sem transformações - não é um erro não ter permissões para migrar
            return $true
        }
        catch {
            $this.Logger.LogError([LogCategory]::RbacImport, "Erro durante aplicação de transformações", $_.Exception.Message, @{})
            return $false
        }
    }
    
    # Processa permissões para subscription/resource groups específicos (fluxo original)
    [void] ProcessPermissions([string]$targetSubscriptionId, [string[]]$targetResourceGroups) {
        try {
            $this.Logger.LogInfo([LogCategory]::RbacImport, "Processando permissões para destinos específicos", "", @{
                TargetSubscription = $targetSubscriptionId
                TargetResourceGroups = $targetResourceGroups -join ","
            })
            
            # Filtra permissões transformadas para os destinos especificados
            $this.PermissionsToImport = @()
            $this.DuplicateAssignments = @()
            
            foreach ($permission in $this.TransformedPermissions) {
                if (-not $permission.IsTransformed) {
                    continue
                }
                
                $targetScope = $permission.GetTargetScope()
                
                # Verifica se o scope está dentro dos targets especificados
                $shouldInclude = $false
                
                # Para subscription
                if ($targetScope -match "/subscriptions/$targetSubscriptionId`$") {
                    $shouldInclude = $true
                }
                
                # Para resource groups
                foreach ($rg in $targetResourceGroups) {
                    if ($targetScope -match "/subscriptions/$targetSubscriptionId/resourceGroups/$rg") {
                        $shouldInclude = $true
                        break
                    }
                }
                
                if ($shouldInclude) {
                    # Verifica duplicatas usando hash de comparação
                    $compareHash = $permission.GetComparisonHash()
                    $isDuplicate = $false
                    
                    foreach ($existing in $this.PermissionsToImport) {
                        $existingHash = $existing.GetComparisonHash()
                        if (($compareHash.roleDefinitionId -eq $existingHash.roleDefinitionId) -and
                            ($compareHash.principalId -eq $existingHash.principalId) -and
                            ($compareHash.scope -eq $existingHash.scope)) {
                            $isDuplicate = $true
                            break
                        }
                    }
                    
                    if ($isDuplicate) {
                        $this.DuplicateAssignments += $permission
                    } else {
                        $this.PermissionsToImport += $permission
                    }
                }
            }
            
            $this.Statistics.PermissionsToImport = $this.PermissionsToImport.Count
            
            $this.Logger.LogInfo([LogCategory]::RbacImport, "Processamento concluído", "", @{
                PermissionsToImport = $this.PermissionsToImport.Count
                DuplicatesFound = $this.DuplicateAssignments.Count
            })
        }
        catch {
            $this.Logger.LogError([LogCategory]::RbacImport, "Erro durante processamento de permissões", $_.Exception.Message, @{})
        }
    }
    
    [bool] CheckExistingPermissions() {
        try {
            $this.Logger.LogInfo([LogCategory]::RbacImport, "Verificando permissões existentes no destino", "", @{})
            
            $toImportList = @()
            $existingCount = 0
            $toImportCount = 0
            
            # Agrupa permissões transformadas por escopo para otimizar consultas
            $scopeGroups = $this.TransformedPermissions | Where-Object { $_.IsTransformed } | Group-Object { $_.GetTargetScope() }
            
            foreach ($scopeGroup in $scopeGroups) {
                $scope = $scopeGroup.Name
                $scopePermissions = $scopeGroup.Group
                
                $this.Logger.LogVerbose([LogCategory]::RbacImport, "Verificando escopo", $scope, @{
                    PermissionsCount = $scopePermissions.Count
                })
                
                # Obtém permissões existentes no escopo
                $existingPermissions = $this.GetExistingPermissionsForScope($scope)
                
                foreach ($permission in $scopePermissions) {
                    $permissionExists = $this.CheckIfPermissionExists($permission, $existingPermissions)
                    
                    if ($permissionExists) {
                        $existingCount++
                        $this.Logger.LogVerbose([LogCategory]::RbacImport, "Permissão já existe", $permission.ToString(), @{})
                    }
                    else {
                        $toImportCount++
                        $toImportList += $permission
                        $this.Logger.LogVerbose([LogCategory]::RbacImport, "Permissão será importada", $permission.ToString(), @{})
                    }
                }
            }
            
            # Atualiza a propriedade apenas após completar a iteração
            $this.PermissionsToImport = $toImportList
            
            $this.Statistics.ExistingPermissionsFound = $existingCount
            $this.Statistics.PermissionsToImport = $toImportCount
            
            $this.Logger.LogInfo([LogCategory]::RbacImport, "Verificação concluída", 
                "$existingCount existentes, $toImportCount para importar", @{})
            
            return $true
        }
        catch {
            $this.Logger.LogError([LogCategory]::RbacImport, "Erro durante verificação de permissões existentes", $_.Exception.Message, @{})
            return $false
        }
    }
    
    [array] GetExistingPermissionsForScope([string]$scope) {
        try {
            # Determina o tipo de escopo e faz a consulta apropriada
            if ($scope -match "^/subscriptions/([^/]+)/resourceGroups/([^/]+)") {
                $subscriptionId = $Matches[1]
                $resourceGroupName = $Matches[2]
                return $this.RbacManager.GetRbacAssignmentsForResourceGroup($subscriptionId, $resourceGroupName)
            }
            elseif ($scope -match "^/subscriptions/([^/]+)$") {
                $subscriptionId = $Matches[1]
                return $this.RbacManager.GetRbacAssignmentsForSubscription($subscriptionId)
            }
            else {
                $this.Logger.LogWarning([LogCategory]::RbacImport, "Escopo não suportado para verificação", $scope, @{})
                return @()
            }
        }
        catch {
            $this.Logger.LogError([LogCategory]::RbacImport, "Erro ao obter permissões existentes", $scope, @{
                Error = $_.Exception.Message
            })
            return @()
        }
    }
    
    [bool] CheckIfPermissionExists([RbacPermission]$permission, [array]$existingPermissions) {
        $permissionHash = $permission.GetComparisonHash()
        
        foreach ($existing in $existingPermissions) {
            # Cria hash de comparação para permissão existente
            $existingHash = @{}
            
            if ($existing.properties) {
                foreach ($key in $existing.properties.PSObject.Properties.Name) {
                    if ($key -notin @('createdOn', 'updatedOn', 'createdBy', 'updatedBy')) {
                        $existingHash[$key] = $existing.properties.$key
                    }
                }
            }
            
            $existingHash['type'] = $existing.type
            $existingHash['roleDefinitionName'] = $existing.roleDefinitionName
            
            # Compara os hashes
            $isMatch = $true
            foreach ($key in $permissionHash.Keys) {
                if ($permissionHash[$key] -ne $existingHash[$key]) {
                    $isMatch = $false
                    break
                }
            }
            
            if ($isMatch) {
                return $true
            }
        }
        
        return $false
    }
    
    [bool] ImportPermissions() {
        try {
            $this.Logger.LogInfo([LogCategory]::RbacImport, "Iniciando importação de permissões", 
                "$($this.PermissionsToImport.Count) permissões", @{})
            
            $importedCount = 0
            $errorCount = 0
            
            foreach ($permission in $this.PermissionsToImport) {
                try {
                    $scope = $permission.GetTargetScope()
                    $payload = $permission.GetCreatePayload()
                    
                    $this.Logger.LogVerbose([LogCategory]::RbacImport, "Importando permissão", $permission.ToString(), @{
                        Scope = $scope
                        Payload = $payload
                    })
                    
                    $result = $this.RbacManager.CreateRbacAssignment($scope, $payload)
                    
                    if ($result) {
                        $importedCount++
                        $this.Logger.LogInfo([LogCategory]::RbacImport, "Permissão importada com sucesso", $permission.ToString(), @{})
                    }
                    else {
                        $errorCount++
                        $this.Logger.LogError([LogCategory]::RbacImport, "Falha ao importar permissão", $permission.ToString(), @{})
                    }
                }
                catch {
                    $errorCount++
                    $this.Logger.LogError([LogCategory]::RbacImport, "Erro ao importar permissão", $permission.ToString(), @{
                        Error = $_.Exception.Message
                    })
                }
            }
            
            $this.Statistics.ImportedSuccessfully = $importedCount
            $this.Statistics.ImportErrors = $errorCount
            
            $this.Logger.LogInfo([LogCategory]::RbacImport, "Importação concluída", 
                "$importedCount importadas, $errorCount erros", @{})
            
            return $errorCount -eq 0
        }
        catch {
            $this.Logger.LogError([LogCategory]::RbacImport, "Erro durante importação de permissões", $_.Exception.Message, @{})
            return $false
        }
    }
    
    [bool] ExecuteMigration([string]$sourceJsonFile, [string]$mappingCsvFile) {
        try {
            $this.Statistics.StartTime = Get-Date
            $this.Logger.LogInfo([LogCategory]::General, "Iniciando migração RBAC", "", @{
                SourceFile = $sourceJsonFile
                MappingFile = $mappingCsvFile
            })
            
            # 1. Carrega regras de mapeamento
            if (-not $this.LoadMappingRules($mappingCsvFile)) {
                throw "Falha ao carregar regras de mapeamento"
            }
            
            # 2. Carrega permissões de origem
            if (-not $this.LoadSourcePermissions($sourceJsonFile)) {
                throw "Falha ao carregar permissões de origem"
            }
            
            # 3. Aplica transformações
            if (-not $this.ApplyTransformations()) {
                $this.Logger.LogWarning([LogCategory]::RbacImport, "Nenhuma transformação foi aplicada", "", @{})
            }
            
            # 4. Verifica permissões existentes
            if (-not $this.CheckExistingPermissions()) {
                throw "Falha ao verificar permissões existentes"
            }
            
            # 5. Importa permissões necessárias
            if ($this.PermissionsToImport.Count -gt 0) {
                if (-not $this.ImportPermissions()) {
                    $this.Logger.LogWarning([LogCategory]::RbacImport, "Alguns erros ocorreram durante a importação", "", @{})
                }
            }
            else {
                $this.Logger.LogInfo([LogCategory]::RbacImport, "Nenhuma permissão nova para importar", "", @{})
            }
            
            $this.Statistics.EndTime = Get-Date
            $this.LogFinalStatistics()
            
            return $true
        }
        catch {
            $this.Statistics.EndTime = Get-Date
            $this.Logger.LogError([LogCategory]::General, "Erro durante migração RBAC", $_.Exception.Message, @{})
            return $false
        }
    }
    
    [void] LogFinalStatistics() {
        $duration = $this.Statistics.EndTime - $this.Statistics.StartTime
        
        $this.Logger.LogInfo([LogCategory]::General, "Estatísticas da migração", "", @{
            Duration = $duration.ToString()
            SourcePermissionsLoaded = $this.Statistics.SourcePermissionsLoaded
            MappingRulesLoaded = $this.Statistics.MappingRulesLoaded
            TransformationsApplied = $this.Statistics.TransformationsApplied
            PermissionsTransformed = $this.Statistics.PermissionsTransformed
            ExistingPermissionsFound = $this.Statistics.ExistingPermissionsFound
            PermissionsToImport = $this.Statistics.PermissionsToImport
            ImportedSuccessfully = $this.Statistics.ImportedSuccessfully
            ImportErrors = $this.Statistics.ImportErrors
        })
    }
    
    [hashtable] GetStatistics() {
        return $this.Statistics
    }
    
    [bool] ExportMigrationReport([string]$outputPath) {
        try {
            $report = @{
                GeneratedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Statistics = $this.Statistics
                MappingRules = @()
                TransformedPermissions = @()
                PermissionsToImport = @()
            }
            
            # Adiciona regras de mapeamento
            foreach ($rule in $this.MappingRules) {
                $report.MappingRules += @{
                    Source = $rule.Source
                    Target = $rule.Target
                }
            }
            
            # Adiciona permissões transformadas
            foreach ($permission in $this.TransformedPermissions | Where-Object { $_.IsTransformed }) {
                $report.TransformedPermissions += @{
                    OriginalId = $permission.Id
                    TransformedScope = $permission.GetTargetScope()
                    RoleDefinitionName = $permission.RoleDefinitionName
                    PrincipalType = $permission.Properties.principalType
                    PrincipalId = $permission.Properties.principalId
                    AppliedTransformations = $permission.AppliedTransformations
                }
            }
            
            # Adiciona permissões a serem importadas
            foreach ($permission in $this.PermissionsToImport) {
                $report.PermissionsToImport += @{
                    Id = $permission.Id
                    Scope = $permission.GetTargetScope()
                    RoleDefinitionName = $permission.RoleDefinitionName
                    PrincipalType = $permission.Properties.principalType
                    PrincipalId = $permission.Properties.principalId
                }
            }
            
            $jsonReport = $report | ConvertTo-Json -Depth 6
            $jsonReport | Out-File -FilePath $outputPath -Encoding UTF8 -Force
            
            $this.Logger.LogInfo([LogCategory]::General, "Relatório de migração exportado", $outputPath, @{})
            return $true
        }
        catch {
            $this.Logger.LogError([LogCategory]::General, "Erro ao exportar relatório de migração", $_.Exception.Message, @{})
            return $false
        }
    }
}

# Função para criar uma nova instância do RbacMigrator
function New-RbacMigrator {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Logger,
        
        [Parameter(Mandatory = $true)]
        [object]$Authenticator,
        
        [Parameter(Mandatory = $true)]
        [object]$RbacManager
    )
    
    return [RbacMigrator]::new($Logger, $Authenticator, $RbacManager)
}

Export-ModuleMember -Function New-RbacMigrator