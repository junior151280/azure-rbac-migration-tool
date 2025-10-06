# =============================================================================
# Azure RBAC Import Automation - RBAC Transformation Module
# =============================================================================
# Este módulo implementa a transformação de atribuições RBAC exportadas
# baseada em mapeamentos CSV para aplicar em subscriptions/recursos de destino.
# =============================================================================

using module .\Logger.psm1

class ResourceMapping {
    [string]$SourceSubscriptionId
    [string]$SourceResourceGroup
    [string]$TargetSubscriptionId
    [string]$TargetResourceGroup
    [string]$PrincipalIdMapping
    [string]$RoleMapping
    [string]$Comments
    [int]$LineNumber
    [bool]$IsValid
    [string[]]$ValidationErrors

    ResourceMapping() {
        $this.ValidationErrors = @()
        $this.IsValid = $false
    }

    ResourceMapping([PSCustomObject]$csvRow, [int]$lineNumber) {
        $this.SourceSubscriptionId = $csvRow.SourceSubscriptionId?.Trim()
        $this.SourceResourceGroup = $csvRow.SourceResourceGroup?.Trim()
        $this.TargetSubscriptionId = $csvRow.TargetSubscriptionId?.Trim()
        $this.TargetResourceGroup = $csvRow.TargetResourceGroup?.Trim()
        $this.PrincipalIdMapping = $csvRow.PrincipalIdMapping?.Trim()
        $this.RoleMapping = $csvRow.RoleMapping?.Trim()
        $this.Comments = $csvRow.Comments?.Trim()
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

        if ([string]::IsNullOrWhiteSpace($this.TargetSubscriptionId)) {
            $this.ValidationErrors += "TargetSubscriptionId é obrigatório"
        }
        elseif (-not $this.IsValidGuid($this.TargetSubscriptionId)) {
            $this.ValidationErrors += "TargetSubscriptionId deve ser um GUID válido"
        }

        if ([string]::IsNullOrWhiteSpace($this.TargetResourceGroup)) {
            $this.ValidationErrors += "TargetResourceGroup é obrigatório"
        }

        $this.IsValid = $this.ValidationErrors.Count -eq 0
    }

    [bool] IsValidGuid([string]$value) {
        try {
            $guid = [System.Guid]::Parse($value)
            return $true
        }
        catch {
            return $false
        }
    }

    [string] ToString() {
        return "$($this.SourceSubscriptionId)/$($this.SourceResourceGroup) -> $($this.TargetSubscriptionId)/$($this.TargetResourceGroup)"
    }
}

class TransformedRbacAssignment {
    [string]$OriginalId
    [string]$OriginalScope
    [string]$NewScope
    [string]$PrincipalId
    [string]$RoleDefinitionId
    [string]$RoleDefinitionName
    [hashtable]$OriginalAssignment
    [hashtable]$TransformedAssignment

    TransformedRbacAssignment([hashtable]$originalAssignment, [ResourceMapping]$mapping) {
        $this.OriginalId = $originalAssignment.Id
        $this.OriginalScope = $originalAssignment.Scope
        $this.PrincipalId = $originalAssignment.PrincipalId
        $this.RoleDefinitionId = $originalAssignment.RoleDefinitionId
        $this.RoleDefinitionName = $originalAssignment.RoleDefinitionName
        $this.OriginalAssignment = $originalAssignment
        
        # Aplica a transformação
        $this.ApplyTransformation($mapping)
    }

    [void] ApplyTransformation([ResourceMapping]$mapping) {
        # Constrói o novo scope
        $this.NewScope = "/subscriptions/$($mapping.TargetSubscriptionId)/resourceGroups/$($mapping.TargetResourceGroup)"
        
        # Aplica mapeamento de Principal ID se fornecido
        $newPrincipalId = $this.PrincipalId
        if (-not [string]::IsNullOrWhiteSpace($mapping.PrincipalIdMapping)) {
            # Formato esperado: "old-id:new-id,old-id2:new-id2"
            $principalMappings = $mapping.PrincipalIdMapping.Split(',')
            foreach ($mappingPair in $principalMappings) {
                $parts = $mappingPair.Split(':')
                if ($parts.Length -eq 2 -and $parts[0].Trim() -eq $this.PrincipalId) {
                    $newPrincipalId = $parts[1].Trim()
                    break
                }
            }
        }

        # Aplica mapeamento de Role se fornecido
        $newRoleDefinitionId = $this.RoleDefinitionId
        if (-not [string]::IsNullOrWhiteSpace($mapping.RoleMapping)) {
            # Formato esperado: "old-role:new-role,old-role2:new-role2"
            $roleMappings = $mapping.RoleMapping.Split(',')
            foreach ($mappingPair in $roleMappings) {
                $parts = $mappingPair.Split(':')
                if ($parts.Length -eq 2 -and $parts[0].Trim() -eq $this.RoleDefinitionName) {
                    # Resolve novo role ID baseado no nome
                    $newRoleDefinitionId = "/subscriptions/$($mapping.TargetSubscriptionId)/providers/Microsoft.Authorization/roleDefinitions/$($parts[1].Trim())"
                    break
                }
            }
        }

        # Cria a atribuição transformada
        $this.TransformedAssignment = @{
            Scope = $this.NewScope
            PrincipalId = $newPrincipalId
            RoleDefinitionId = $newRoleDefinitionId
            RoleDefinitionName = $this.RoleDefinitionName
            OriginalScope = $this.OriginalScope
            TransformationApplied = $true
        }
    }

    [hashtable] GetCreateAssignmentPayload() {
        return @{
            properties = @{
                principalId = $this.TransformedAssignment.PrincipalId
                roleDefinitionId = $this.TransformedAssignment.RoleDefinitionId
            }
        }
    }
}

class RbacTransformer {
    [object]$Logger
    [ResourceMapping[]]$ResourceMappings
    [hashtable[]]$ExportedAssignments
    [TransformedRbacAssignment[]]$TransformedAssignments

    RbacTransformer([object]$logger) {
        $this.Logger = $logger
        $this.ResourceMappings = @()
        $this.ExportedAssignments = @()
        $this.TransformedAssignments = @()
    }

    [bool] LoadResourceMappings([string]$csvFilePath) {
        try {
            $this.Logger.LogInfo([LogCategory]::CsvProcessing, "Carregando mapeamentos de recursos", $csvFilePath, @{})
            
            if (-not (Test-Path -Path $csvFilePath)) {
                throw "Arquivo CSV não encontrado: $csvFilePath"
            }

            $csvData = Import-Csv -Path $csvFilePath -Encoding UTF8
            $lineNumber = 2 # Começa na linha 2 (após cabeçalho)
            
            foreach ($row in $csvData) {
                $mapping = [ResourceMapping]::new($row, $lineNumber)
                if ($mapping.IsValid) {
                    $this.ResourceMappings += $mapping
                    $this.Logger.LogVerbose([LogCategory]::CsvProcessing, "Mapeamento válido carregado", $mapping.ToString(), @{})
                }
                else {
                    $errorDetails = $mapping.ValidationErrors -join '; '
                    $this.Logger.LogWarning([LogCategory]::CsvProcessing, "Mapeamento inválido ignorado", "Linha $lineNumber`: $errorDetails", @{})
                }
                $lineNumber++
            }

            $this.Logger.LogInfo([LogCategory]::CsvProcessing, "Mapeamentos carregados", "$($this.ResourceMappings.Count) mapeamentos válidos", @{})
            return $this.ResourceMappings.Count -gt 0
        }
        catch {
            $this.Logger.LogError([LogCategory]::CsvProcessing, "Erro ao carregar mapeamentos", $_.Exception.Message, @{})
            return $false
        }
    }

    [bool] LoadExportedAssignments([string]$jsonFilePath) {
        try {
            $this.Logger.LogInfo([LogCategory]::RbacExport, "Carregando atribuições exportadas", $jsonFilePath, @{})
            
            if (-not (Test-Path -Path $jsonFilePath)) {
                throw "Arquivo de exportação não encontrado: $jsonFilePath"
            }

            $jsonContent = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json
            
            # Verifica se é o formato da API (com "value") ou formato direto (array)
            $assignments = if ($jsonContent.value) {
                $jsonContent.value  # Formato da API: { "value": [...] }
            } else {
                $jsonContent        # Formato direto: [...]
            }
            
            # Converte para hashtable para facilitar manipulação
            foreach ($assignment in $assignments) {
                $assignmentHash = @{
                    Id = $assignment.id
                    Name = $assignment.name
                    Type = $assignment.type
                    Scope = $assignment.properties.scope
                    PrincipalId = $assignment.properties.principalId
                    PrincipalType = $assignment.properties.principalType
                    RoleDefinitionId = $assignment.properties.roleDefinitionId
                    RoleDefinitionName = $assignment.roleDefinitionName  # Adicionado pelo export
                    CreatedOn = $assignment.properties.createdOn
                    CreatedBy = $assignment.properties.createdBy
                    UpdatedOn = $assignment.properties.updatedOn
                    UpdatedBy = $assignment.properties.updatedBy
                }
                
                # Extrai SubscriptionId e ResourceGroupName do scope
                if ($assignmentHash.Scope -match '/subscriptions/([^/]+)') {
                    $assignmentHash.SubscriptionId = $Matches[1]
                } else {
                    $assignmentHash.SubscriptionId = $null
                }
                
                if ($assignmentHash.Scope -match '/resourceGroups/([^/]+)') {
                    $assignmentHash.ResourceGroupName = $Matches[1]
                } else {
                    $assignmentHash.ResourceGroupName = $null
                }
                
                $this.ExportedAssignments += $assignmentHash
            }

            $this.Logger.LogInfo([LogCategory]::RbacExport, "Atribuições carregadas", "$($this.ExportedAssignments.Count) atribuições", @{})
            return $this.ExportedAssignments.Count -gt 0
        }
        catch {
            $this.Logger.LogError([LogCategory]::RbacExport, "Erro ao carregar atribuições exportadas", $_.Exception.Message, @{})
            return $false
        }
    }

    [bool] TransformAssignments() {
        try {
            $this.Logger.LogInfo([LogCategory]::RbacImport, "Iniciando transformação de atribuições", "", @{})
            
            $this.TransformedAssignments = @()
            $transformedCount = 0
            
            foreach ($assignment in $this.ExportedAssignments) {
                # Encontra mapeamento correspondente
                $mapping = $this.FindMappingForAssignment($assignment)
                
                if ($mapping) {
                    $transformed = [TransformedRbacAssignment]::new($assignment, $mapping)
                    $this.TransformedAssignments += $transformed
                    $transformedCount++
                    
                    $this.Logger.LogVerbose([LogCategory]::RbacImport, "Atribuição transformada", 
                        "De: $($assignment.Scope) Para: $($transformed.NewScope)", @{})
                }
                else {
                    $this.Logger.LogWarning([LogCategory]::RbacImport, "Nenhum mapeamento encontrado para atribuição", 
                        $assignment.Scope, @{})
                }
            }

            $this.Logger.LogInfo([LogCategory]::RbacImport, "Transformação concluída", 
                "$transformedCount de $($this.ExportedAssignments.Count) atribuições transformadas", @{})
            
            return $transformedCount -gt 0
        }
        catch {
            $this.Logger.LogError([LogCategory]::RbacImport, "Erro durante transformação", $_.Exception.Message, @{})
            return $false
        }
    }

    [ResourceMapping] FindMappingForAssignment([hashtable]$assignment) {
        foreach ($mapping in $this.ResourceMappings) {
            if ($assignment.SubscriptionId -eq $mapping.SourceSubscriptionId -and 
                $assignment.ResourceGroupName -eq $mapping.SourceResourceGroup) {
                return $mapping
            }
        }
        return $null
    }

    [TransformedRbacAssignment[]] GetTransformedAssignments() {
        return $this.TransformedAssignments
    }

    [bool] ExportTransformationReport([string]$outputPath) {
        try {
            $report = @{
                GeneratedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                SourceAssignments = $this.ExportedAssignments.Count
                AppliedMappings = $this.ResourceMappings.Count
                TransformedAssignments = $this.TransformedAssignments.Count
                Transformations = @()
            }

            foreach ($transformed in $this.TransformedAssignments) {
                $report.Transformations += @{
                    OriginalScope = $transformed.OriginalScope
                    NewScope = $transformed.NewScope
                    PrincipalId = $transformed.PrincipalId
                    RoleDefinitionName = $transformed.RoleDefinitionName
                    TransformedAssignment = $transformed.TransformedAssignment
                }
            }

            $jsonReport = $report | ConvertTo-Json -Depth 5
            $jsonReport | Out-File -FilePath $outputPath -Encoding UTF8 -Force
            
            $this.Logger.LogInfo([LogCategory]::RbacImport, "Relatório de transformação exportado", $outputPath, @{})
            return $true
        }
        catch {
            $this.Logger.LogError([LogCategory]::RbacImport, "Erro ao exportar relatório de transformação", $_.Exception.Message, @{})
            return $false
        }
    }
}

# Função para criar instância do transformador
function New-RbacTransformer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Logger
    )

    try {
        $transformer = [RbacTransformer]::new($Logger)
        return $transformer
    }
    catch {
        Write-Error "Erro ao criar RBAC Transformer: $($_.Exception.Message)"
        throw
    }
}

# Exporta as funções públicas do módulo
Export-ModuleMember -Function @(
    'New-RbacTransformer'
) -Cmdlet @()