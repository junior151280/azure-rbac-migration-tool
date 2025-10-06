using module ".\src\Logger.psm1"
using module ".\src\AzureAuthenticator.psm1"
using module ".\src\AzureRbacManager.psm1"
using module ".\src\RbacMigrator.psm1"

# Azure RBAC Migration Tool - Script Principal Simplificado
# Executa migração baseada em config.json e CSV de mapeamento

param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile = ".\config\config.json",
    
    [Parameter(Mandatory = $false)]
    [string]$MappingCsvFile = ".\config\rbac-mapping-new.csv",
    
    [Parameter(Mandatory = $false)]
    [string]$LogDirectory = ".\logs",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = ".\output",
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

function Write-Status {
    param(
        [string]$Message,
        [string]$Status = "INFO",
        [ConsoleColor]$Color = "White"
    )
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] [$Status] $Message" -ForegroundColor $Color
}

try {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "AZURE RBAC MIGRATION TOOL" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Validacao de arquivos
    Write-Status "Validando arquivos necessarios..." "INFO" "Yellow"
    
    if (-not (Test-Path $ConfigFile)) {
        throw "Arquivo de configuracao nao encontrado: $ConfigFile"
    }
    Write-Status "Config encontrado: $ConfigFile" "OK" "Green"
    
    if (-not (Test-Path $MappingCsvFile)) {
        throw "Arquivo de mapeamento nao encontrado: $MappingCsvFile"
    }
    Write-Status "Mapping encontrado: $MappingCsvFile" "OK" "Green"
    
    # Cria diretorios se necessario
    @($LogDirectory, $OutputDirectory) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Status "Diretorio criado: $_" "INFO" "Gray"
        }
    }
    
    # Carrega configuracao
    Write-Status "Carregando configuracao..." "INFO" "Yellow"
    $config = Get-Content -Path $ConfigFile -Raw | ConvertFrom-Json
    
    # Ajusta estrutura do config - SourceSubscriptions é array, pega o primeiro
    $sourceSubscription = if ($config.SourceSubscriptions -and $config.SourceSubscriptions.Count -gt 0) {
        $config.SourceSubscriptions[0]
    } elseif ($config.SourceSubscription) {
        $config.SourceSubscription
    } else {
        throw "Nenhuma subscription de origem encontrada no config.json"
    }
    
    Write-Status "Subscription Origem: $($sourceSubscription.SubscriptionId)" "INFO" "Gray"
    Write-Status "Resource Groups: $($sourceSubscription.ResourceGroups -join ', ')" "INFO" "Gray"
    Write-Status "Subscription Destino: $($config.TargetSubscription.SubscriptionId)" "INFO" "Gray"
    Write-Status "Resource Groups: $($config.TargetSubscription.ResourceGroups -join ', ')" "INFO" "Gray"
    
    # Inicializa logger
    Write-Status "Inicializando logger..." "INFO" "Yellow"
    $logger = [Logger]::new($LogDirectory, "RbacMigration")
    $logger.InitializeLogFiles()
    
    $logger.LogInfo([LogCategory]::General, "Migracao RBAC iniciada", "", @{
        SourceSubscription = $sourceSubscription.SubscriptionId
        TargetSubscription = $config.TargetSubscription.SubscriptionId
        WhatIfMode = $WhatIf.IsPresent
    })
    
    if ($WhatIf) {
        Write-Status "MODO WHAT-IF - Nenhuma alteracao sera feita" "INFO" "Yellow"
    }
    
    # Inicializa autenticacao
    Write-Status "Configurando autenticacao..." "INFO" "Yellow"
    
    $tenantId = $env:AZURE_TENANT_ID
    $clientId = $env:AZURE_CLIENT_ID  
    $clientSecret = $env:AZURE_CLIENT_SECRET
    
    if (-not $tenantId -or -not $clientId -or -not $clientSecret) {
        if ($config.ServicePrincipal) {
            $tenantId = $config.ServicePrincipal.TenantId
            $clientId = $config.ServicePrincipal.ClientId
            Write-Status "Usando credenciais do config.json" "INFO" "Gray"
            
            if ($config.ServicePrincipal.ClientSecret) {
                $clientSecret = $config.ServicePrincipal.ClientSecret
                Write-Status "Client Secret obtido do config.json" "INFO" "Gray"
            } else {
                $clientSecret = Read-Host "Digite o Client Secret" -AsSecureString
                $clientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientSecret))
            }
        } elseif ($config.Authentication) {
            $tenantId = $config.Authentication.TenantId
            $clientId = $config.Authentication.ClientId
            Write-Status "Usando credenciais do config.json (Authentication)" "INFO" "Gray"
            
            $clientSecret = Read-Host "Digite o Client Secret" -AsSecureString
            $clientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientSecret))
        } else {
            throw "Credenciais Azure nao disponiveis. Configure variaveis de ambiente ou config.json"
        }
    }
    
    $secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
    $authenticator = [AzureAuthenticator]::new($tenantId, $clientId, $secureSecret)
    $rbacManager = [AzureRbacManager]::new($authenticator)
    
    Write-Status "Autenticacao configurada" "OK" "Green"
    
    # Inicializa migrator
    Write-Status "Inicializando migrator..." "INFO" "Yellow"
    $migrator = [RbacMigrator]::new($logger, $authenticator, $rbacManager)
    
    # Carrega regras de mapeamento
    Write-Status "Carregando regras de mapeamento..." "INFO" "Yellow"
    $mappingResult = $migrator.LoadMappingRules($MappingCsvFile)
    if (-not $mappingResult) {
        throw "Falha ao carregar regras de mapeamento"
    }
    Write-Status "Regras carregadas: $($migrator.MappingRules.Count)" "OK" "Green"
    
    # Carrega dados da subscription origem
    Write-Status "Carregando dados da subscription origem..." "INFO" "Yellow"
    $sourceResult = $migrator.LoadSourceData($sourceSubscription.SubscriptionId, $sourceSubscription.ResourceGroups)
    if (-not $sourceResult) {
        throw "Falha ao carregar dados da subscription origem"
    }
    Write-Status "Permissoes carregadas: $($migrator.SourcePermissions.Count)" "OK" "Green"
    
    # Aplica transformacoes
    Write-Status "Aplicando transformacoes otimizadas..." "INFO" "Yellow"
    $transformResult = $migrator.ApplyTransformations()
    if (-not $transformResult) {
        throw "Falha ao aplicar transformacoes"
    }
    
    # Verifica se há permissões para processar
    if ($migrator.SourcePermissions.Count -eq 0) {
        Write-Status "Nenhuma permissao encontrada na subscription origem" "WARNING" "Yellow"
        Write-Status "Migracao concluida (sem acoes necessarias)" "OK" "Green"
        return
    }
    
    Write-Status "Transformacoes aplicadas" "OK" "Green"
    
    # Processa para destinos especificos
    Write-Status "Processando para destinos especificos..." "INFO" "Yellow"
    $migrator.ProcessPermissions($config.TargetSubscription.SubscriptionId, $config.TargetSubscription.ResourceGroups)
    
    Write-Status "Permissoes para importar: $($migrator.PermissionsToImport.Count)" "INFO" "Gray"
    Write-Status "Duplicadas encontradas: $($migrator.DuplicateAssignments.Count)" "INFO" "Gray"
    
    # Verifica permissoes existentes
    Write-Status "Verificando permissoes existentes..." "INFO" "Yellow"
    $checkResult = $migrator.CheckExistingPermissions()
    Write-Status "Verificacao concluida" "OK" "Green"
    
    # Executa importacao
    if ($WhatIf) {
        Write-Status "MODO WHAT-IF: $($migrator.PermissionsToImport.Count) permissoes seriam importadas" "INFO" "Yellow"
    } else {
        if ($migrator.PermissionsToImport.Count -gt 0) {
            Write-Status "Iniciando importacao de $($migrator.PermissionsToImport.Count) permissoes..." "INFO" "Yellow"
            
            $confirm = Read-Host "Confirma a importacao? (S/N)"
            if ($confirm -eq 'S' -or $confirm -eq 's') {
                $importResult = $migrator.ImportPermissions()
                
                if ($importResult) {
                    Write-Status "Importacao concluida com sucesso!" "OK" "Green"
                } else {
                    Write-Status "Importacao concluida com alguns erros" "WARN" "Yellow"
                }
            } else {
                Write-Status "Importacao cancelada pelo usuario" "INFO" "Yellow"
            }
        } else {
            Write-Status "Nenhuma permissao para importar" "INFO" "Yellow"
        }
    }
    
    # Gera relatorio
    Write-Status "Gerando relatorio..." "INFO" "Yellow"
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportFile = Join-Path $OutputDirectory "rbac-migration-report-$timestamp.json"
    $migrator.ExportMigrationReport($reportFile)
    
    # Exibe estatisticas finais
    $stats = $migrator.GetStatistics()
    Write-Host ""
    Write-Host "ESTATISTICAS FINAIS:" -ForegroundColor Cyan
    Write-Host "  Permissoes carregadas: $($stats.SourcePermissionsLoaded)" -ForegroundColor Gray
    Write-Host "  Transformacoes aplicadas: $($stats.TransformationsApplied)" -ForegroundColor Gray
    Write-Host "  Permissoes para importar: $($stats.PermissionsToImport)" -ForegroundColor Gray
    Write-Host "  Importadas com sucesso: $($stats.ImportedSuccessfully)" -ForegroundColor Gray
    Write-Host "  Erros de importacao: $($stats.ImportErrors)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Relatorio salvo em: $reportFile" -ForegroundColor Gray
    
    Write-Status "MIGRACAO CONCLUIDA!" "OK" "Green"
    
} catch {
    Write-Status "ERRO: $($_.Exception.Message)" "ERROR" "Red"
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    
    if ($logger) {
        $logger.LogError([LogCategory]::General, "Erro critico durante migracao", $_.Exception.Message, @{
            StackTrace = $_.ScriptStackTrace
        })
    }
    
    exit 1
} finally {
    if ($logger) {
        Write-Status "Logs salvos em: $LogDirectory" "INFO" "Gray"
        $logger.CloseSession()
    }
}