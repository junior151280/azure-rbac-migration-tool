# =============================================================================
# Azure RBAC Import Automation - CSV Processing Module
# =============================================================================
# Este módulo implementa funções para processar e validar o arquivo CSV
# de mapeamento das permissões RBAC entre subscriptions.
# =============================================================================

using module .\Logger.psm1

class RbacMapping {
    [string]$SourceSubscriptionId
    [string]$SourceResourceGroup
    [string]$SourcePrincipalId
    [string]$SourceRoleDefinition
    [string]$TargetSubscriptionId
    [string]$TargetResourceGroup
    [string]$TargetPrincipalId
    [string]$TargetRoleDefinition
    [int]$LineNumber
    [bool]$IsValid
    [string[]]$ValidationErrors

    RbacMapping() {
        $this.ValidationErrors = @()
        $this.IsValid = $false
    }

    RbacMapping([PSCustomObject]$csvRow, [int]$lineNumber) {
        $this.SourceSubscriptionId = $csvRow.SourceSubscriptionId?.Trim()
        $this.SourceResourceGroup = $csvRow.SourceResourceGroup?.Trim()
        $this.SourcePrincipalId = $csvRow.SourcePrincipalId?.Trim()
        $this.SourceRoleDefinition = $csvRow.SourceRoleDefinition?.Trim()
        $this.TargetSubscriptionId = $csvRow.TargetSubscriptionId?.Trim()
        $this.TargetResourceGroup = $csvRow.TargetResourceGroup?.Trim()
        $this.TargetPrincipalId = $csvRow.TargetPrincipalId?.Trim()
        $this.TargetRoleDefinition = $csvRow.TargetRoleDefinition?.Trim()
        $this.LineNumber = $lineNumber
        $this.ValidationErrors = @()
        
        $this.ValidateMapping()
    }

    [void] ValidateMapping() {
        $this.ValidationErrors = @()

        # Validação de campos obrigatórios
        if ([string]::IsNullOrWhiteSpace($this.SourceSubscriptionId)) {
            $this.ValidationErrors += "SourceSubscriptionId é obrigatório"
        }
        elseif (-not $this.IsValidGuid($this.SourceSubscriptionId)) {
            $this.ValidationErrors += "SourceSubscriptionId deve ser um GUID válido"
        }

        if ([string]::IsNullOrWhiteSpace($this.SourceResourceGroup)) {
            $this.ValidationErrors += "SourceResourceGroup é obrigatório"
        }

        if ([string]::IsNullOrWhiteSpace($this.SourcePrincipalId)) {
            $this.ValidationErrors += "SourcePrincipalId é obrigatório"
        }
        elseif (-not $this.IsValidGuid($this.SourcePrincipalId)) {
            $this.ValidationErrors += "SourcePrincipalId deve ser um GUID válido"
        }

        if ([string]::IsNullOrWhiteSpace($this.SourceRoleDefinition)) {
            $this.ValidationErrors += "SourceRoleDefinition é obrigatório"
        }

        if ([string]::IsNullOrWhiteSpace($this.TargetSubscriptionId)) {
            $this.ValidationErrors += "TargetSubscriptionId é obrigatório"
        }
        elseif (-not $this.IsValidGuid($this.TargetSubscriptionId)) {
            $this.ValidationErrors += "TargetSubscriptionId deve ser um GUID válido"
        }

        if ([string]::IsNullOrWhiteSpace($this.TargetResourceGroup)) {
            $this.ValidationErrors += "TargetResourceGroup é obrigatório"
        }

        if ([string]::IsNullOrWhiteSpace($this.TargetPrincipalId)) {
            $this.ValidationErrors += "TargetPrincipalId é obrigatório"
        }
        elseif (-not $this.IsValidGuid($this.TargetPrincipalId)) {
            $this.ValidationErrors += "TargetPrincipalId deve ser um GUID válido"
        }

        if ([string]::IsNullOrWhiteSpace($this.TargetRoleDefinition)) {
            $this.ValidationErrors += "TargetRoleDefinition é obrigatório"
        }

        # Validações de negócio
        if ($this.SourceSubscriptionId -eq $this.TargetSubscriptionId -and 
            $this.SourceResourceGroup -eq $this.TargetResourceGroup -and
            $this.SourcePrincipalId -eq $this.TargetPrincipalId -and
            $this.SourceRoleDefinition -eq $this.TargetRoleDefinition) {
            $this.ValidationErrors += "Mapeamento source e target são idênticos"
        }

        $this.IsValid = $this.ValidationErrors.Count -eq 0
    }

    [bool] IsValidGuid([string]$guidString) {
        if ([string]::IsNullOrWhiteSpace($guidString)) {
            return $false
        }

        $guid = [System.Guid]::Empty
        return [System.Guid]::TryParse($guidString, [ref]$guid)
    }

    [string] GetSourceScope() {
        return "/subscriptions/$($this.SourceSubscriptionId)/resourceGroups/$($this.SourceResourceGroup)"
    }

    [string] GetTargetScope() {
        return "/subscriptions/$($this.TargetSubscriptionId)/resourceGroups/$($this.TargetResourceGroup)"
    }

    [string] ToString() {
        return "Line $($this.LineNumber): $($this.SourcePrincipalId) -> $($this.TargetPrincipalId) [$($this.SourceRoleDefinition) -> $($this.TargetRoleDefinition)]"
    }
}

class CsvProcessor {
    [object]$Logger
    [string]$CsvFilePath
    [RbacMapping[]]$Mappings
    [RbacMapping[]]$ValidMappings
    [RbacMapping[]]$InvalidMappings
    [hashtable]$Statistics

    CsvProcessor([object]$logger) {
        $this.Logger = $logger
        $this.Mappings = @()
        $this.ValidMappings = @()
        $this.InvalidMappings = @()
        $this.Statistics = @{
            TotalRows = 0
            ValidRows = 0
            InvalidRows = 0
            ProcessingErrors = 0
        }
    }

    [bool] LoadCsvFile([string]$csvFilePath) {
        try {
            $operationId = $this.Logger.StartOperation([LogCategory]::CsvProcessing, "LoadCsvFile", @{FilePath = $csvFilePath})
            
            if (-not (Test-Path -Path $csvFilePath)) {
                $this.Logger.FailOperation([LogCategory]::CsvProcessing, "LoadCsvFile", $operationId, "Arquivo CSV não encontrado: $csvFilePath")
                return $false
            }

            $this.CsvFilePath = $csvFilePath
            $this.Logger.LogInfo([LogCategory]::CsvProcessing, "Carregando arquivo CSV", $csvFilePath)

            # Lê o arquivo CSV
            $csvContent = Import-Csv -Path $csvFilePath -Encoding UTF8
            
            if ($null -eq $csvContent -or $csvContent.Count -eq 0) {
                $this.Logger.FailOperation([LogCategory]::CsvProcessing, "LoadCsvFile", $operationId, "Arquivo CSV está vazio ou não contém dados válidos")
                return $false
            }

            # Valida os cabeçalhos esperados
            $expectedHeaders = @(
                'SourceSubscriptionId',
                'SourceResourceGroup', 
                'SourcePrincipalId',
                'SourceRoleDefinition',
                'TargetSubscriptionId',
                'TargetResourceGroup',
                'TargetPrincipalId',
                'TargetRoleDefinition'
            )

            $csvHeaders = $csvContent[0].PSObject.Properties.Name
            $missingHeaders = $expectedHeaders | Where-Object { $_ -notin $csvHeaders }
            
            if ($missingHeaders.Count -gt 0) {
                $missingHeadersText = $missingHeaders -join ', '
                $this.Logger.FailOperation([LogCategory]::CsvProcessing, "LoadCsvFile", $operationId, "Cabeçalhos obrigatórios ausentes: $missingHeadersText")
                return $false
            }

            # Processa cada linha do CSV
            $this.ProcessCsvRows($csvContent)
            
            # Calcula estatísticas
            $this.CalculateStatistics()
            
            $this.Logger.CompleteOperation([LogCategory]::CsvProcessing, "LoadCsvFile", $operationId, $this.Statistics)
            return $true
        }
        catch {
            $this.Logger.LogError([LogCategory]::CsvProcessing, "Erro ao carregar arquivo CSV", $_.Exception.Message, @{FilePath = $csvFilePath})
            return $false
        }
    }

    [void] ProcessCsvRows([array]$csvContent) {
        $lineNumber = 2  # Linha 1 são os cabeçalhos
        
        foreach ($row in $csvContent) {
            try {
                $mapping = [RbacMapping]::new($row, $lineNumber)
                $this.Mappings += $mapping
                
                if ($mapping.IsValid) {
                    $this.ValidMappings += $mapping
                    $this.Logger.LogVerbose([LogCategory]::CsvProcessing, "Linha válida processada", $mapping.ToString(), @{})
                }
                else {
                    $this.InvalidMappings += $mapping
                    $errorDetails = $mapping.ValidationErrors -join '; '
                    $this.Logger.LogWarning([LogCategory]::CsvProcessing, "Linha inválida encontrada", "Linha $lineNumber`: $errorDetails", @{})
                }
            }
            catch {
                $this.Statistics.ProcessingErrors++
                $this.Logger.LogError([LogCategory]::CsvProcessing, "Erro ao processar linha $lineNumber", $_.Exception.Message, @{})
            }
            
            $lineNumber++
        }
    }

    [void] CalculateStatistics() {
        $this.Statistics.TotalRows = $this.Mappings.Count
        $this.Statistics.ValidRows = $this.ValidMappings.Count
        $this.Statistics.InvalidRows = $this.InvalidMappings.Count
        
        $this.Logger.LogInfo([LogCategory]::CsvProcessing, "Estatísticas do processamento CSV", "", $this.Statistics)
    }

    [RbacMapping[]] GetValidMappings() {
        return $this.ValidMappings
    }

    [RbacMapping[]] GetInvalidMappings() {
        return $this.InvalidMappings
    }

    [hashtable] GetStatistics() {
        return $this.Statistics
    }

    [void] ExportValidationReport([string]$outputPath) {
        try {
            $operationId = $this.Logger.StartOperation([LogCategory]::CsvProcessing, "ExportValidationReport", @{OutputPath = $outputPath})
            
            $report = @{
                ProcessedAt = Get-Date
                CsvFilePath = $this.CsvFilePath
                Statistics = $this.Statistics
                ValidMappings = @()
                InvalidMappings = @()
            }

            # Adiciona mapeamentos válidos
            foreach ($mapping in $this.ValidMappings) {
                $report.ValidMappings += @{
                    LineNumber = $mapping.LineNumber
                    SourceSubscriptionId = $mapping.SourceSubscriptionId
                    SourceResourceGroup = $mapping.SourceResourceGroup
                    SourcePrincipalId = $mapping.SourcePrincipalId
                    SourceRoleDefinition = $mapping.SourceRoleDefinition
                    TargetSubscriptionId = $mapping.TargetSubscriptionId
                    TargetResourceGroup = $mapping.TargetResourceGroup
                    TargetPrincipalId = $mapping.TargetPrincipalId
                    TargetRoleDefinition = $mapping.TargetRoleDefinition
                }
            }

            # Adiciona mapeamentos inválidos com erros
            foreach ($mapping in $this.InvalidMappings) {
                $report.InvalidMappings += @{
                    LineNumber = $mapping.LineNumber
                    ValidationErrors = $mapping.ValidationErrors
                    SourceSubscriptionId = $mapping.SourceSubscriptionId
                    SourceResourceGroup = $mapping.SourceResourceGroup
                    SourcePrincipalId = $mapping.SourcePrincipalId
                    SourceRoleDefinition = $mapping.SourceRoleDefinition
                    TargetSubscriptionId = $mapping.TargetSubscriptionId
                    TargetResourceGroup = $mapping.TargetResourceGroup
                    TargetPrincipalId = $mapping.TargetPrincipalId
                    TargetRoleDefinition = $mapping.TargetRoleDefinition
                }
            }

            # Cria diretório se não existir
            $outputDir = Split-Path -Path $outputPath -Parent
            if (-not [string]::IsNullOrEmpty($outputDir) -and -not (Test-Path -Path $outputDir)) {
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            }

            # Exporta relatório
            $report | ConvertTo-Json -Depth 4 | Out-File -FilePath $outputPath -Encoding UTF8 -Force
            
            $this.Logger.CompleteOperation([LogCategory]::CsvProcessing, "ExportValidationReport", $operationId, @{OutputPath = $outputPath})
        }
        catch {
            $this.Logger.LogError([LogCategory]::CsvProcessing, "Erro ao exportar relatório de validação", $_.Exception.Message, @{OutputPath = $outputPath})
        }
    }

    [bool] HasValidMappings() {
        return $this.ValidMappings.Count -gt 0
    }

    [bool] HasInvalidMappings() {
        return $this.InvalidMappings.Count -gt 0
    }

    # Filtra mapeamentos por subscription de origem
    [RbacMapping[]] GetMappingsForSourceSubscription([string]$subscriptionId) {
        return $this.ValidMappings | Where-Object { $_.SourceSubscriptionId -eq $subscriptionId }
    }

    # Filtra mapeamentos por subscription de destino
    [RbacMapping[]] GetMappingsForTargetSubscription([string]$subscriptionId) {
        return $this.ValidMappings | Where-Object { $_.TargetSubscriptionId -eq $subscriptionId }
    }

    # Filtra mapeamentos por resource group de origem
    [RbacMapping[]] GetMappingsForSourceResourceGroup([string]$subscriptionId, [string]$resourceGroupName) {
        return $this.ValidMappings | Where-Object { 
            $_.SourceSubscriptionId -eq $subscriptionId -and 
            $_.SourceResourceGroup -eq $resourceGroupName 
        }
    }

    # Obtém lista única de subscriptions de origem
    [string[]] GetUniqueSourceSubscriptions() {
        return $this.ValidMappings.SourceSubscriptionId | Sort-Object -Unique
    }

    # Obtém lista única de subscriptions de destino
    [string[]] GetUniqueTargetSubscriptions() {
        return $this.ValidMappings.TargetSubscriptionId | Sort-Object -Unique
    }

    # Obtém lista única de resource groups de origem
    [hashtable] GetUniqueSourceResourceGroups() {
        $result = @{}
        
        foreach ($mapping in $this.ValidMappings) {
            if (-not $result.ContainsKey($mapping.SourceSubscriptionId)) {
                $result[$mapping.SourceSubscriptionId] = @()
            }
            
            if ($mapping.SourceResourceGroup -notin $result[$mapping.SourceSubscriptionId]) {
                $result[$mapping.SourceSubscriptionId] += $mapping.SourceResourceGroup
            }
        }
        
        return $result
    }
}

# Função para criar instância do processador CSV
function New-CsvProcessor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Logger
    )

    try {
        Write-Verbose "Criando instância do CSV Processor..."
        
        $csvProcessor = [CsvProcessor]::new($Logger)
        
        Write-Verbose "CSV Processor criado com sucesso."
        return $csvProcessor
    }
    catch {
        Write-Error "Erro ao criar CSV Processor: $($_.Exception.Message)"
        throw
    }
}

# Função para validar arquivo CSV sem processamento completo
function Test-CsvFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvFilePath
    )

    try {
        if (-not (Test-Path -Path $CsvFilePath)) {
            Write-Error "Arquivo CSV não encontrado: $CsvFilePath"
            return $false
        }

        $csvContent = Import-Csv -Path $CsvFilePath -Encoding UTF8 -ErrorAction Stop
        
        if ($null -eq $csvContent -or $csvContent.Count -eq 0) {
            Write-Error "Arquivo CSV está vazio"
            return $false
        }

        $expectedHeaders = @(
            'SourceSubscriptionId', 'SourceResourceGroup', 'SourcePrincipalId', 'SourceRoleDefinition',
            'TargetSubscriptionId', 'TargetResourceGroup', 'TargetPrincipalId', 'TargetRoleDefinition'
        )

        $csvHeaders = $csvContent[0].PSObject.Properties.Name
        $missingHeaders = $expectedHeaders | Where-Object { $_ -notin $csvHeaders }
        
        if ($missingHeaders.Count -gt 0) {
            Write-Error "Cabeçalhos obrigatórios ausentes: $($missingHeaders -join ', ')"
            return $false
        }

        Write-Verbose "Arquivo CSV é válido. Contém $($csvContent.Count) linhas de dados."
        return $true
    }
    catch {
        Write-Error "Erro ao validar arquivo CSV: $($_.Exception.Message)"
        return $false
    }
}

# Exporta as funções públicas do módulo
Export-ModuleMember -Function @(
    'New-CsvProcessor',
    'Test-CsvFile'
)