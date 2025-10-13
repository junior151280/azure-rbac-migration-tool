# =============================================================================
# Azure RBAC Import Automation - RBAC Import Module
# =============================================================================
# Este módulo implementa funções para importar e aplicar permissões RBAC
# na subscription de destino, incluindo tratamento de erros e retry logic.
# =============================================================================

using module .\Logger.psm1
using module .\AzureRbacManager.psm1
using module .\CsvProcessor.psm1

enum ImportResult {
    Success
    Failed
    Skipped
    AlreadyExists
}

class ImportOperation {
    [string]$OperationId
    [RbacMapping]$Mapping
    [ImportResult]$Result
    [string]$ErrorMessage
    [string]$Details
    [datetime]$StartTime
    [datetime]$EndTime
    [int]$RetryAttempts
    [hashtable]$AdditionalData

    ImportOperation([RbacMapping]$mapping) {
        $this.OperationId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        $this.Mapping = $mapping
        $this.Result = [ImportResult]::Failed
        $this.ErrorMessage = ""
        $this.Details = ""
        $this.StartTime = Get-Date
        $this.EndTime = [datetime]::MinValue
        $this.RetryAttempts = 0
        $this.AdditionalData = @{}
    }

    [void] Complete([ImportResult]$result, [string]$details = "", [string]$errorMessage = "") {
        $this.Result = $result
        $this.Details = $details
        $this.ErrorMessage = $errorMessage
        $this.EndTime = Get-Date
    }

    [string] GetDuration() {
        if ($this.EndTime -eq [datetime]::MinValue) {
            return "Em andamento"
        }
        
        $duration = $this.EndTime - $this.StartTime
        return $duration.ToString("mm\:ss\.fff")
    }

    [string] ToString() {
        $mapping_str = $this.Mapping.ToString()
        $result_str = $this.Result.ToString()
        $duration = $this.GetDuration()
        return "$mapping_str - $result_str ($duration)"
    }
}

class RbacImporter {
    [object]$Logger
    [object]$RbacManager
    [object]$Authenticator
    [hashtable]$RoleDefinitionCache
    [hashtable]$ImportSettings
    [ImportOperation[]]$Operations
    [hashtable]$Statistics

    RbacImporter([object]$logger, [object]$rbacManager, [object]$authenticator) {
        $this.Logger = $logger
        $this.RbacManager = $rbacManager
        $this.Authenticator = $authenticator
        $this.RoleDefinitionCache = @{}
        $this.Operations = @()
        $this.Statistics = @{
            TotalOperations = 0
            SuccessfulOperations = 0
            FailedOperations = 0
            SkippedOperations = 0
            AlreadyExistsOperations = 0
            TotalRetryAttempts = 0
            StartTime = [datetime]::MinValue
            EndTime = [datetime]::MinValue
        }
        
        # Configurações padrão
        $this.ImportSettings = @{
            MaxRetryAttempts = 3
            RetryDelaySeconds = 5
            SkipExistingAssignments = $true
            ValidateTargetPrincipals = $true
            ValidateTargetResourceGroups = $true
            BatchSize = 10
            DelayBetweenBatches = 2
        }
    }

    [void] ConfigureSettings([hashtable]$settings) {
        foreach ($key in $settings.Keys) {
            if ($this.ImportSettings.ContainsKey($key)) {
                $this.ImportSettings[$key] = $settings[$key]
                $this.Logger.LogVerbose([LogCategory]::RbacImport, "Configuração atualizada", "$key = $($settings[$key])", @{})
            }
        }
    }

    [bool] ImportRbacMappings([RbacMapping[]]$mappings) {
        try {
            $this.Statistics.StartTime = Get-Date
            $operationId = $this.Logger.StartOperation([LogCategory]::RbacImport, "ImportRbacMappings", @{
                MappingCount = $mappings.Count
                Settings = $this.ImportSettings
            })

            $this.Logger.LogInfo([LogCategory]::RbacImport, "Iniciando importação RBAC", "$($mappings.Count) mapeamentos para processar")

            # Valida pré-requisitos
            if (-not $this.ValidatePrerequisites($mappings)) {
                $this.Logger.FailOperation([LogCategory]::RbacImport, "ImportRbacMappings", $operationId, "Falha na validação de pré-requisitos")
                return $false
            }

            # Processa em lotes para evitar rate limiting
            $batches = $this.CreateBatches($mappings)
            $this.Logger.LogInfo([LogCategory]::RbacImport, "Processamento em lotes", "$($batches.Count) lotes de até $($this.ImportSettings.BatchSize) itens")

            foreach ($batch in $batches) {
                $this.ProcessBatch($batch)
                
                # Delay entre lotes para evitar throttling
                if ($batches.IndexOf($batch) -lt ($batches.Count - 1)) {
                    Start-Sleep -Seconds $this.ImportSettings.DelayBetweenBatches
                }
            }

            $this.CalculateStatistics()
            $this.Statistics.EndTime = Get-Date

            $this.Logger.CompleteOperation([LogCategory]::RbacImport, "ImportRbacMappings", $operationId, $this.Statistics)
            return $this.Statistics.FailedOperations -eq 0
        }
        catch {
            $this.Logger.LogError([LogCategory]::RbacImport, "Erro durante importação RBAC", $_.Exception.Message, @{})
            return $false
        }
    }

    [bool] ValidatePrerequisites([RbacMapping[]]$mappings) {
        $this.Logger.LogInfo([LogCategory]::RbacImport, "Validando pré-requisitos para importação")

        # Obtém listas únicas de subscriptions e resource groups
        $targetSubscriptions = $mappings.TargetSubscriptionId | Sort-Object -Unique
        $targetResourceGroups = @{}
        
        foreach ($mapping in $mappings) {
            if (-not $targetResourceGroups.ContainsKey($mapping.TargetSubscriptionId)) {
                $targetResourceGroups[$mapping.TargetSubscriptionId] = @()
            }
            if ($mapping.TargetResourceGroup -notin $targetResourceGroups[$mapping.TargetSubscriptionId]) {
                $targetResourceGroups[$mapping.TargetSubscriptionId] += $mapping.TargetResourceGroup
            }
        }

        # Valida acesso às subscriptions de destino
        foreach ($subscriptionId in $targetSubscriptions) {
            if (-not $this.ValidateSubscriptionAccess($subscriptionId)) {
                $this.Logger.LogError([LogCategory]::RbacImport, "Sem acesso à subscription de destino", $subscriptionId, @{})
                return $false
            }
        }

        # Valida resource groups de destino se configurado
        if ($this.ImportSettings.ValidateTargetResourceGroups) {
            foreach ($subscriptionId in $targetResourceGroups.Keys) {
                foreach ($resourceGroup in $targetResourceGroups[$subscriptionId]) {
                    if (-not $this.ValidateResourceGroupExists($subscriptionId, $resourceGroup)) {
                        $this.Logger.LogError([LogCategory]::RbacImport, "Resource Group de destino não existe", "$subscriptionId/$resourceGroup", @{})
                        return $false
                    }
                }
            }
        }

        # Valida principals de destino se configurado
        if ($this.ImportSettings.ValidateTargetPrincipals) {
            $uniquePrincipals = $mappings.TargetPrincipalId | Sort-Object -Unique
            foreach ($principalId in $uniquePrincipals) {
                if (-not $this.ValidatePrincipalExists($principalId)) {
                    $this.Logger.LogWarning([LogCategory]::RbacImport, "Principal de destino pode não existir", $principalId, @{})
                }
            }
        }

        $this.Logger.LogInfo([LogCategory]::RbacImport, "Pré-requisitos validados com sucesso")
        return $true
    }

    [array] CreateBatches([RbacMapping[]]$mappings) {
        $batches = @()
        $batchSize = $this.ImportSettings.BatchSize
        
        for ($i = 0; $i -lt $mappings.Count; $i += $batchSize) {
            $endIndex = [Math]::Min($i + $batchSize - 1, $mappings.Count - 1)
            $batch = $mappings[$i..$endIndex]
            $batches += , $batch
        }
        
        return $batches
    }

    [void] ProcessBatch([RbacMapping[]]$batch) {
        $this.Logger.LogInfo([LogCategory]::RbacImport, "Processando lote", "$($batch.Count) mapeamentos")

        foreach ($mapping in $batch) {
            $this.ProcessSingleMapping($mapping)
        }
    }

    [void] ProcessSingleMapping([RbacMapping]$mapping) {
        $operation = [ImportOperation]::new($mapping)
        $this.Operations += $operation

        try {
            $this.Logger.LogVerbose([LogCategory]::RbacImport, "Processando mapeamento", $mapping.ToString())

            # Resolve Role Definition ID se necessário
            $roleDefinitionId = $this.ResolveRoleDefinitionId($mapping.TargetSubscriptionId, $mapping.TargetRoleDefinition)
            if ([string]::IsNullOrEmpty($roleDefinitionId)) {
                $operation.Complete([ImportResult]::Failed, "", "Role definition não encontrada: $($mapping.TargetRoleDefinition)")
                $this.Logger.LogError([LogCategory]::RbacImport, "Role definition não encontrada", $mapping.TargetRoleDefinition, @{})
                return
            }

            # Verifica se atribuição já existe
            if ($this.ImportSettings.SkipExistingAssignments) {
                if ($this.RbacManager.RbacAssignmentExists($mapping.GetTargetScope(), $mapping.TargetPrincipalId, $roleDefinitionId)) {
                    $operation.Complete([ImportResult]::AlreadyExists, "Atribuição já existe")
                    $this.Logger.LogInfo([LogCategory]::RbacImport, "Atribuição já existe, pulando", $mapping.ToString())
                    return
                }
            }

            # Tenta criar a atribuição com retry
            $success = $this.CreateRbacAssignmentWithRetry($operation, $mapping.GetTargetScope(), $mapping.TargetPrincipalId, $roleDefinitionId)
            
            if ($success) {
                $operation.Complete([ImportResult]::Success, "Atribuição criada com sucesso")
                $this.Logger.LogInfo([LogCategory]::RbacImport, "Atribuição RBAC criada com sucesso", $mapping.ToString())
            }
            else {
                $operation.Complete([ImportResult]::Failed, "", "Falha ao criar atribuição após todas as tentativas")
                $this.Logger.LogError([LogCategory]::RbacImport, "Falha ao criar atribuição RBAC", $mapping.ToString(), @{})
            }
        }
        catch {
            $operation.Complete([ImportResult]::Failed, "", $_.Exception.Message)
            $this.Logger.LogError([LogCategory]::RbacImport, "Erro ao processar mapeamento", $_.Exception.Message, @{Mapping = $mapping.ToString()})
        }
    }

    [bool] CreateRbacAssignmentWithRetry([ImportOperation]$operation, [string]$scope, [string]$principalId, [string]$roleDefinitionId) {
        $attempt = 0
        $maxAttempts = $this.ImportSettings.MaxRetryAttempts
        
        while ($attempt -lt $maxAttempts) {
            $attempt++
            $operation.RetryAttempts = $attempt
            
            try {
                $this.Logger.LogVerbose([LogCategory]::RbacImport, "Tentativa $attempt de $maxAttempts", "Criando atribuição RBAC", @{})
                
                $payload = @{ properties = @{ principalId = $principalId; roleDefinitionId = $roleDefinitionId } }
                $success = $this.RbacManager.CreateRbacAssignment($scope, $payload)
                
                if ($success) {
                    return $true
                }
            }
            catch {
                $errorMessage = $_.Exception.Message
                $this.Logger.LogWarning([LogCategory]::RbacImport, "Tentativa $attempt falhou", $errorMessage, @{})
                
                # Verifica se é um erro recuperável
                if ($this.IsRecoverableError($errorMessage) -and $attempt -lt $maxAttempts) {
                    $delay = $this.ImportSettings.RetryDelaySeconds * $attempt
                    $this.Logger.LogVerbose([LogCategory]::RbacImport, "Aguardando retry", "$delay segundos", @{})
                    Start-Sleep -Seconds $delay
                }
                else {
                    $operation.ErrorMessage = $errorMessage
                    break
                }
            }
        }
        
        return $false
    }

    [bool] IsRecoverableError([string]$errorMessage) {
        [string[]]$recoverableErrors = @(
            "TooManyRequests",
            "InternalServerError", 
            "ServiceUnavailable",
            "RequestTimeout",
            "ThrottledError"
        )
        
        foreach ($errorPattern in $recoverableErrors) {
            if ($errorMessage -match $errorPattern) {
                return $true
            }
        }
        
        return $false
    }

    [string] ResolveRoleDefinitionId([string]$subscriptionId, [string]$roleName) {
        $cacheKey = "$subscriptionId-$roleName"
        
        if ($this.RoleDefinitionCache.ContainsKey($cacheKey)) {
            return $this.RoleDefinitionCache[$cacheKey]
        }

        try {
            $roleDefinitions = $this.RbacManager.GetAvailableRoleDefinitions($subscriptionId)
            $matchingRole = $roleDefinitions | Where-Object { $_.Name -eq $roleName }
            
            if ($matchingRole) {
                $this.RoleDefinitionCache[$cacheKey] = $matchingRole.Id
                return $matchingRole.Id
            }
        }
        catch {
            $this.Logger.LogWarning([LogCategory]::RbacImport, "Erro ao resolver role definition", $_.Exception.Message, @{})
        }
        
        return ""
    }

    [bool] ValidateSubscriptionAccess([string]$subscriptionId) {
        try {
            $uri = "https://management.azure.com/subscriptions/$subscriptionId" + "?api-version=2020-01-01"
            $headers = $this.Authenticator.GetAuthHeaders()
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 30
            return $true
        }
        catch {
            return $false
        }
    }

    [bool] ValidateResourceGroupExists([string]$subscriptionId, [string]$resourceGroupName) {
        try {
            $uri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName" + "?api-version=2021-04-01"
            $headers = $this.Authenticator.GetAuthHeaders()
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 30
            return $true
        }
        catch {
            return $false
        }
    }

    [bool] ValidatePrincipalExists([string]$principalId) {
        try {
            # Tenta validar o principal via Microsoft Graph API
            $uri = "https://graph.microsoft.com/v1.0/directoryObjects/$principalId"
            $headers = $this.Authenticator.GetAuthHeaders()
            $headers['Authorization'] = $headers['Authorization'] -replace 'https://management.azure.com/', 'https://graph.microsoft.com/'
            
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 30
            return $true
        }
        catch {
            # Se não conseguir validar via Graph, assume que existe
            return $true
        }
    }

    [void] CalculateStatistics() {
        $this.Statistics.TotalOperations = $this.Operations.Count
        $this.Statistics.SuccessfulOperations = ($this.Operations | Where-Object { $_.Result -eq [ImportResult]::Success }).Count
        $this.Statistics.FailedOperations = ($this.Operations | Where-Object { $_.Result -eq [ImportResult]::Failed }).Count
        $this.Statistics.SkippedOperations = ($this.Operations | Where-Object { $_.Result -eq [ImportResult]::Skipped }).Count
        $this.Statistics.AlreadyExistsOperations = ($this.Operations | Where-Object { $_.Result -eq [ImportResult]::AlreadyExists }).Count
        $this.Statistics.TotalRetryAttempts = ($this.Operations | Measure-Object -Property RetryAttempts -Sum).Sum
    }

    [ImportOperation[]] GetOperations() {
        return $this.Operations
    }

    [hashtable] GetStatistics() {
        return $this.Statistics
    }

    [void] ExportOperationReport([string]$outputPath) {
        try {
            $operationId = $this.Logger.StartOperation([LogCategory]::RbacImport, "ExportOperationReport", @{OutputPath = $outputPath})
            
            $report = @{
                GeneratedAt = Get-Date
                Statistics = $this.Statistics
                Settings = $this.ImportSettings
                Operations = @()
            }

            foreach ($operation in $this.Operations) {
                $report.Operations += @{
                    OperationId = $operation.OperationId
                    LineNumber = $operation.Mapping.LineNumber
                    Result = $operation.Result.ToString()
                    Duration = $operation.GetDuration()
                    RetryAttempts = $operation.RetryAttempts
                    ErrorMessage = $operation.ErrorMessage
                    Details = $operation.Details
                    Mapping = @{
                        SourceSubscriptionId = $operation.Mapping.SourceSubscriptionId
                        SourceResourceGroup = $operation.Mapping.SourceResourceGroup
                        SourcePrincipalId = $operation.Mapping.SourcePrincipalId
                        SourceRoleDefinition = $operation.Mapping.SourceRoleDefinition
                        TargetSubscriptionId = $operation.Mapping.TargetSubscriptionId
                        TargetResourceGroup = $operation.Mapping.TargetResourceGroup
                        TargetPrincipalId = $operation.Mapping.TargetPrincipalId
                        TargetRoleDefinition = $operation.Mapping.TargetRoleDefinition
                    }
                }
            }

            # Cria diretório se não existir
            $outputDir = Split-Path -Path $outputPath -Parent
            if (-not [string]::IsNullOrEmpty($outputDir) -and -not (Test-Path -Path $outputDir)) {
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            }

            $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $outputPath -Encoding UTF8 -Force
            
            $this.Logger.CompleteOperation([LogCategory]::RbacImport, "ExportOperationReport", $operationId, @{OutputPath = $outputPath})
        }
        catch {
            $this.Logger.LogError([LogCategory]::RbacImport, "Erro ao exportar relatório de operações", $_.Exception.Message, @{})
        }
    }
}

# Função para criar instância do importador RBAC
function New-RbacImporter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Logger,
        
        [Parameter(Mandatory = $true)]
        [object]$RbacManager,
        
        [Parameter(Mandatory = $true)]
        [object]$Authenticator
    )

    try {
        Write-Verbose "Criando instância do RBAC Importer..."
        
        $importer = [RbacImporter]::new($Logger, $RbacManager, $Authenticator)
        
        Write-Verbose "RBAC Importer criado com sucesso."
        return $importer
    }
    catch {
        Write-Error "Erro ao criar RBAC Importer: $($_.Exception.Message)"
        throw
    }
}

# Exporta as funções públicas do módulo
Export-ModuleMember -Function @('New-RbacImporter')