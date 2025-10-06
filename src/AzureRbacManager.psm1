# =============================================================================
# Azure RBAC Import Automation - RBAC Management Module
# =============================================================================
# Este módulo implementa funções para listar e gerenciar permissões RBAC
# usando as APIs REST do Azure Management.
# =============================================================================

using module .\AzureAuthenticator.psm1

class RbacAssignment {
    [string]$Id
    [string]$Name
    [string]$Type
    [string]$Scope
    [string]$PrincipalId
    [string]$PrincipalType
    [string]$RoleDefinitionId
    [string]$RoleDefinitionName
    [string]$SubscriptionId
    [string]$ResourceGroupName
    [datetime]$CreatedOn
    [string]$CreatedBy
    [datetime]$UpdatedOn
    [string]$UpdatedBy
    [string]$Condition
    [string]$ConditionVersion
    [string]$Description
    [string]$DelegatedManagedIdentityResourceId
    [string]$RoleName 

    RbacAssignment() {}

    RbacAssignment([PSCustomObject]$azureResponse) {
        $this.Id = $azureResponse.id
        $this.Name = $azureResponse.name
        $this.Type = $azureResponse.type
        $this.Scope = $azureResponse.properties.scope
        $this.PrincipalId = $azureResponse.properties.principalId
        $this.PrincipalType = $azureResponse.properties.principalType
        $this.RoleDefinitionId = $azureResponse.properties.roleDefinitionId
        $this.CreatedOn = $azureResponse.properties.createdOn
        $this.CreatedBy = $azureResponse.properties.createdBy
        $this.UpdatedOn = $azureResponse.properties.updatedOn
        $this.UpdatedBy = $azureResponse.properties.updatedBy
        $this.Condition = $azureResponse.properties.condition
        $this.ConditionVersion = $azureResponse.properties.conditionVersion
        $this.Description = $azureResponse.properties.description
        $this.DelegatedManagedIdentityResourceId = $azureResponse.properties.delegatedManagedIdentityResourceId
        $this.RoleName = $azureResponse.properties.roleName
        
        # Extrai SubscriptionId e ResourceGroupName do scope
        $this.ExtractScopeComponents()
    }

    [void] ExtractScopeComponents() {
        if ($this.Scope -match '/subscriptions/([^/]+)') {
            $this.SubscriptionId = $Matches[1]
        }
        
        if ($this.Scope -match '/resourceGroups/([^/]+)') {
            $this.ResourceGroupName = $Matches[1]
        }
    }

    [string] ToString() {
        return "Principal: $($this.PrincipalId), Role: $($this.RoleDefinitionName), Scope: $($this.Scope)"
    }
}

class RoleDefinition {
    [string]$Id
    [string]$Name
    [string]$Type
    [string]$Description
    [string[]]$Actions
    [string[]]$NotActions
    [string[]]$DataActions
    [string[]]$NotDataActions
    [string[]]$AssignableScopes

    RoleDefinition([PSCustomObject]$azureResponse) {
        $this.Id = $azureResponse.id
        $this.Name = $azureResponse.properties.roleName
        $this.Type = $azureResponse.properties.type
        $this.Description = $azureResponse.properties.description
        $this.Actions = $azureResponse.properties.permissions[0].actions
        $this.NotActions = $azureResponse.properties.permissions[0].notActions
        $this.DataActions = $azureResponse.properties.permissions[0].dataActions
        $this.NotDataActions = $azureResponse.properties.permissions[0].notDataActions
        $this.AssignableScopes = $azureResponse.properties.assignableScopes
    }
}

class AzureRbacManager {
    [object]$Authenticator
    [hashtable]$RoleDefinitionCache
    [int]$MaxRetryAttempts = 3
    [int]$RetryDelaySeconds = 5

    AzureRbacManager([object]$authenticator) {
        $this.Authenticator = $authenticator
        $this.RoleDefinitionCache = @{}
    }

    # Lista todas as atribuições RBAC de uma Subscription específica (formato original da API)
    [PSCustomObject] GetRbacAssignmentsForSubscriptionRaw([string]$subscriptionId, [string[]]$resourceGroupNames = @()) {
        try {
            Write-Verbose "Listando atribuições RBAC para Subscription: $subscriptionId and Resource Groups: $($resourceGroupNames -join ', ')"
            
            if ($resourceGroupNames.Count -gt 0) {
                $scope = "/subscriptions/$subscriptionId/resourceGroups/$($resourceGroupNames -join ',')"
            } else {
                $scope = "/subscriptions/$subscriptionId"
            }

            $uri = "https://management.azure.com$scope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=atScope()"
            
            $response = $this.InvokeAzureRestApi($uri, 'GET', $null)
            
            # Enriquece as atribuições com nomes de roles
            foreach ($assignment in $response.value) {
                $roleDefinitionId = $assignment.properties.roleDefinitionId
                
                # Busca o nome da role definition se ainda não estiver no cache
                if (-not $this.RoleDefinitionCache.ContainsKey($roleDefinitionId)) {
                    $roleDef = $this.GetRoleDefinition($roleDefinitionId)
                    if ($roleDef) {
                        $this.RoleDefinitionCache[$roleDefinitionId] = $roleDef.Name
                    }
                }
                
                # Adiciona o nome da role no objeto
                $assignment.properties | Add-Member -Type NoteProperty -Name "roleName" -Value $this.RoleDefinitionCache[$roleDefinitionId] -Force
            }
            
            return $response
        }
        catch {
            Write-Error "Erro ao listar atribuições RBAC da subscription $subscriptionId`: $($_.Exception.Message)"
            throw
        }
    }

    # Lista todas as atribuições RBAC de uma Subscription específica (objetos estruturados)
    [RbacAssignment[]] GetRbacAssignmentsForSubscription([string]$subscriptionId, [string[]]$resourceGroupNames = @()) {
        try {
            $response = $this.GetRbacAssignmentsForSubscriptionRaw($subscriptionId, $resourceGroupNames)
            $assignments = @()
            
            foreach ($assignment in $response.value) {
                $rbacAssignment = [RbacAssignment]::new()
                $rbacAssignment.Id = $assignment.id
                $rbacAssignment.Name = $assignment.name
                $rbacAssignment.Type = $assignment.type
                $rbacAssignment.Scope = $assignment.properties.scope
                $rbacAssignment.RoleDefinitionId = $assignment.properties.roleDefinitionId
                $rbacAssignment.PrincipalId = $assignment.properties.principalId
                $rbacAssignment.PrincipalType = $assignment.properties.principalType
                $rbacAssignment.RoleName = $assignment.properties.roleName
                $rbacAssignment.CreatedOn = $assignment.properties.createdOn
                $rbacAssignment.UpdatedOn = $assignment.properties.updatedOn
                $rbacAssignment.CreatedBy = $assignment.properties.createdBy
                $rbacAssignment.UpdatedBy = $assignment.properties.updatedBy
                $rbacAssignment.Condition = $assignment.properties.condition
                $rbacAssignment.ConditionVersion = $assignment.properties.conditionVersion
                $rbacAssignment.Description = $assignment.properties.description
                $rbacAssignment.DelegatedManagedIdentityResourceId = $assignment.properties.delegatedManagedIdentityResourceId
                
                $assignments += $rbacAssignment
            }
            
            return $assignments
        }
        catch {
            Write-Error "Erro ao processar atribuições RBAC da subscription $subscriptionId`: $($_.Exception.Message)"
            throw
        }
    }

    # Lista todas as atribuições RBAC de um Resource Group específico (formato original da API)
    [PSCustomObject] GetRbacAssignmentsForResourceGroupRaw([string]$subscriptionId, [string]$resourceGroupName) {
        try {
            Write-Verbose "Listando atribuições RBAC para Resource Group: $resourceGroupName (Subscription: $subscriptionId)"
            
            $scope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName"
            $uri = "https://management.azure.com$scope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=atScope()"
            
            $response = $this.InvokeAzureRestApi($uri, 'GET', $null)
            
            # Enriquece as atribuições com nomes de roles
            foreach ($assignment in $response.value) {
                $roleDefinitionId = $assignment.properties.roleDefinitionId
                
                # Busca o nome da role definition se ainda não estiver no cache
                if (-not $this.RoleDefinitionCache.ContainsKey($roleDefinitionId)) {
                    try {
                        $roleDefinition = $this.GetRoleDefinition($roleDefinitionId)
                        $this.RoleDefinitionCache[$roleDefinitionId] = $roleDefinition.Name
                    }
                    catch {
                        Write-Warning "Não foi possível obter nome da role $roleDefinitionId"
                        $this.RoleDefinitionCache[$roleDefinitionId] = "Unknown Role"
                    }
                }
                
                # Adiciona o nome da role como propriedade adicional (não modifica a estrutura original)
                $assignment | Add-Member -MemberType NoteProperty -Name "roleDefinitionName" -Value $this.RoleDefinitionCache[$roleDefinitionId] -Force
            }

            Write-Verbose "Encontradas $($response.value.Count) atribuições RBAC no Resource Group $resourceGroupName"
            return $response
        }
        catch {
            Write-Error "Erro ao listar atribuições RBAC para $resourceGroupName`: $($_.Exception.Message)"
            throw
        }
    }

    # Lista todas as atribuições RBAC de um Resource Group específico
    [RbacAssignment[]] GetRbacAssignmentsForResourceGroup([string]$subscriptionId, [string]$resourceGroupName) {
        try {
            Write-Verbose "Listando atribuições RBAC para Resource Group: $resourceGroupName (Subscription: $subscriptionId)"
            
            $scope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName"
            $uri = "https://management.azure.com$scope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=atScope()"
            
            $assignments = $this.InvokeAzureRestApi($uri, 'GET', $null)
            $result = @()

            foreach ($assignment in $assignments.value) {
                $rbacAssignment = [RbacAssignment]::new($assignment)
                
                # Busca o nome da role definition se ainda não estiver no cache
                if (-not $this.RoleDefinitionCache.ContainsKey($rbacAssignment.RoleDefinitionId)) {
                    $roleDefinition = $this.GetRoleDefinition($rbacAssignment.RoleDefinitionId)
                    $this.RoleDefinitionCache[$rbacAssignment.RoleDefinitionId] = $roleDefinition.Name
                }
                
                $rbacAssignment.RoleDefinitionName = $this.RoleDefinitionCache[$rbacAssignment.RoleDefinitionId]
                $result += $rbacAssignment
            }

            Write-Verbose "Encontradas $($result.Count) atribuições RBAC no Resource Group $resourceGroupName"
            return $result
        }
        catch {
            Write-Error "Erro ao listar atribuições RBAC para $resourceGroupName`: $($_.Exception.Message)"
            throw
        }
    }

    # Lista todas as atribuições RBAC de múltiplos Resource Groups (formato original da API)
    [PSCustomObject] GetRbacAssignmentsForResourceGroupsRaw([string]$subscriptionId, [string[]]$resourceGroupNames) {
        $allAssignments = @{
            value = @()
        }
        
        foreach ($rgName in $resourceGroupNames) {
            try {
                $response = $this.GetRbacAssignmentsForResourceGroupRaw($subscriptionId, $rgName)
                $allAssignments.value += $response.value
            }
            catch {
                Write-Warning "Erro ao processar Resource Group '$rgName': $($_.Exception.Message)"
                continue
            }
        }

        Write-Verbose "Total de atribuições RBAC encontradas: $($allAssignments.value.Count)"
        return [PSCustomObject]$allAssignments
    }

    # Lista todas as atribuições RBAC de múltiplos Resource Groups
    [RbacAssignment[]] GetRbacAssignmentsForResourceGroups([string]$subscriptionId, [string[]]$resourceGroupNames) {
        $allAssignments = @()
        
        foreach ($rgName in $resourceGroupNames) {
            try {
                $assignments = $this.GetRbacAssignmentsForResourceGroup($subscriptionId, $rgName)
                $allAssignments += $assignments
            }
            catch {
                Write-Warning "Erro ao processar Resource Group '$rgName': $($_.Exception.Message)"
                continue
            }
        }

        Write-Verbose "Total de atribuições RBAC encontradas: $($allAssignments.Count)"
        return $allAssignments
    }

    # Obtém detalhes de uma role definition
    [RoleDefinition] GetRoleDefinition([string]$roleDefinitionId) {
        try {
            Write-Verbose "Obtendo detalhes da role definition: $roleDefinitionId"
            
            $uri = "https://management.azure.com$roleDefinitionId" + "?api-version=2022-04-01"
            $response = $this.InvokeAzureRestApi($uri, 'GET', $null)
            
            return [RoleDefinition]::new($response)
        }
        catch {
            Write-Error "Erro ao obter role definition $roleDefinitionId`: $($_.Exception.Message)"
            throw
        }
    }

    # Lista todas as role definitions disponíveis em uma subscription
    [RoleDefinition[]] GetAvailableRoleDefinitions([string]$subscriptionId) {
        try {
            Write-Verbose "Listando role definitions disponíveis na subscription: $subscriptionId"
            
            $uri = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
            $response = $this.InvokeAzureRestApi($uri, 'GET', $null)
            
            $roleDefinitions = @()
            foreach ($roleDef in $response.value) {
                $roleDefinitions += [RoleDefinition]::new($roleDef)
            }

            Write-Verbose "Encontradas $($roleDefinitions.Count) role definitions"
            return $roleDefinitions
        }
        catch {
            Write-Error "Erro ao listar role definitions: $($_.Exception.Message)"
            throw
        }
    }

    # Cria uma nova atribuição RBAC
    [bool] CreateRbacAssignment([string]$scope, [hashtable]$payload) {
        try {
            Write-Verbose "Criando atribuição RBAC - Principal: $($payload.properties.principalId), Role: $($payload.properties.roleDefinitionId), Scope: $scope"
            
            # Gera um GUID único para a atribuição
            $assignmentName = [System.Guid]::NewGuid().ToString()
            $uri = "https://management.azure.com$scope/providers/Microsoft.Authorization/roleAssignments/$assignmentName" + "?api-version=2022-04-01"
            
            $body = $payload | ConvertTo-Json -Depth 3

            $response = $this.InvokeAzureRestApi($uri, 'PUT', $body)
            
            Write-Verbose "Atribuição RBAC criada com sucesso: $($response.name)"
            return $true
        }
        catch {
            # Verifica se o erro é devido à atribuição já existir ou problemas de permissão
            if (($_.Exception.Message -match "RoleAssignmentExists") -or 
                ($_.Exception.Message -match "Forbidden") -or 
                ($_.Exception.Message -match "Conflict") -or
                ($_.Exception.Message -match "already exists")) {
                Write-Warning "Atribuição RBAC já existe ou problema de permissão para Principal: $($payload.properties.principalId), Role: $($payload.properties.roleDefinitionId), Scope: $scope"
                return $true
            }
            
            Write-Error "Erro ao criar atribuição RBAC: $($_.Exception.Message)"
            return $false
        }
    }

    # Remove uma atribuição RBAC
    [bool] RemoveRbacAssignment([string]$assignmentId) {
        try {
            Write-Verbose "Removendo atribuição RBAC: $assignmentId"
            
            $uri = "https://management.azure.com$assignmentId" + "?api-version=2022-04-01"
            $response = $this.InvokeAzureRestApi($uri, 'DELETE')
            
            Write-Verbose "Atribuição RBAC removida com sucesso"
            return $true
        }
        catch {
            Write-Error "Erro ao remover atribuição RBAC: $($_.Exception.Message)"
            return $false
        }
    }

    # Verifica se uma atribuição RBAC já existe
    [bool] RbacAssignmentExists([string]$scope, [string]$principalId, [string]$roleDefinitionId) {
        try {
            $uri = "https://management.azure.com$scope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$principalId'"
            $response = $this.InvokeAzureRestApi($uri, 'GET', $null)
            
            foreach ($assignment in $response.value) {
                if ($assignment.properties.roleDefinitionId -eq $roleDefinitionId) {
                    return $true
                }
            }
            
            return $false
        }
        catch {
            Write-Warning "Erro ao verificar existência da atribuição RBAC: $($_.Exception.Message)"
            return $false
        }
    }

    # Método auxiliar para invocar APIs REST do Azure com retry logic
    [PSCustomObject] InvokeAzureRestApi([string]$uri, [string]$method, [string]$body = $null) {
        $attempt = 0
        $success = $false
        $response = $null

        while (-not $success -and $attempt -lt $this.MaxRetryAttempts) {
            $attempt++
            
            try {
                Write-Verbose "Tentativa $attempt de $($this.MaxRetryAttempts) - $method $uri"
                
                $headers = $this.Authenticator.GetAuthHeaders()
                $params = @{
                    Uri         = $uri
                    Method      = $method
                    Headers     = $headers
                    TimeoutSec  = 60
                }

                if ($method -in @('POST', 'PUT', 'PATCH') -and $body) {
                    $params.Body = $body
                }

                $response = Invoke-RestMethod @params
                $success = $true
            }
            catch {
                $statusCode = $_.Exception.Response.StatusCode.value__
                $errorMessage = $_.Exception.Message
                
                Write-Warning "Tentativa $attempt falhou - Status: $statusCode, Erro: $errorMessage"
                
                # Verifica se é um erro que vale a pena tentar novamente
                if ($statusCode -in @(429, 500, 502, 503, 504) -and $attempt -lt $this.MaxRetryAttempts) {
                    $delay = $this.RetryDelaySeconds * $attempt  # Exponential backoff
                    Write-Verbose "Aguardando $delay segundos antes da próxima tentativa..."
                    Start-Sleep -Seconds $delay
                }
                else {
                    throw
                }
            }
        }

        return $response
    }
}

# Função para criar instância do gerenciador RBAC
function New-AzureRbacManager {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Authenticator
    )

    try {
        Write-Verbose "Criando instância do Azure RBAC Manager..."
        
        $rbacManager = [AzureRbacManager]::new($Authenticator)
        
        Write-Verbose "Azure RBAC Manager criado com sucesso."
        return $rbacManager
    }
    catch {
        Write-Error "Erro ao criar Azure RBAC Manager: $($_.Exception.Message)"
        throw
    }
}

# Função para exportar atribuições RBAC para arquivo JSON (formato original da API)
function Export-RbacAssignmentsRaw {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ApiResponse,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    try {
        Write-Verbose "Exportando $($ApiResponse.value.Count) atribuições RBAC para: $OutputFile"
        
        # Cria o diretório se não existir
        $outputDir = Split-Path -Path $OutputFile -Parent
        if ((-not [string]::IsNullOrEmpty($outputDir)) -and (-not (Test-Path -Path $outputDir))) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }

        # Converte para JSON mantendo o formato original da API
        $jsonOutput = $ApiResponse | ConvertTo-Json -Depth 10 -Compress:$false
        
        # Salva no arquivo
        $jsonOutput | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
        
        Write-Verbose "Exportação concluída com sucesso."
    }
    catch {
        Write-Error "Erro ao exportar atribuições RBAC: $($_.Exception.Message)"
        throw
    }
}

# Função para exportar atribuições RBAC para arquivo JSON
function Export-RbacAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [RbacAssignment[]]$Assignments,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    try {
        Write-Verbose "Exportando $($Assignments.Count) atribuições RBAC para: $OutputFile"
        
        # Cria o diretório se não existir
        $outputDir = Split-Path -Path $OutputFile -Parent
        if ((-not [string]::IsNullOrEmpty($outputDir)) -and (-not (Test-Path -Path $outputDir))) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }

        # Converte para JSON com formatação
        $jsonOutput = $Assignments | ConvertTo-Json -Depth 4 -Compress:$false
        
        # Salva no arquivo
        $jsonOutput | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
        
        Write-Verbose "Exportação concluída com sucesso."
    }
    catch {
        Write-Error "Erro ao exportar atribuições RBAC: $($_.Exception.Message)"
        throw
    }
}

# Exporta as funções públicas do módulo
Export-ModuleMember -Function @(
    'New-AzureRbacManager',
    'Export-RbacAssignments',
    'Export-RbacAssignmentsRaw'
) -Cmdlet @()