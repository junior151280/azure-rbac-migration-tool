# =============================================================================
# Azure RBAC Import Automation - Authentication Module
# =============================================================================
# Este módulo implementa autenticação segura com Service Principal para
# acesso às APIs REST do Azure Management seguindo as melhores práticas.
# =============================================================================

using namespace System.Security

class AzureAuthenticator {
    [string]$TenantId
    [string]$ClientId
    [SecureString]$ClientSecret
    [string]$AccessToken
    [datetime]$TokenExpiration
    [int]$MaxRetryAttempts = 3
    [int]$RetryDelaySeconds = 5

    # Construtor
    AzureAuthenticator([string]$tenantId, [string]$clientId, [SecureString]$clientSecret) {
        $this.TenantId = $tenantId
        $this.ClientId = $clientId
        $this.ClientSecret = $clientSecret
        $this.AccessToken = ""
        $this.TokenExpiration = [datetime]::MinValue
    }

    # Obtém um token de acesso válido, renovando se necessário
    [string] GetAccessToken() {
        try {
            # Verifica se o token atual ainda é válido (com margem de 5 minutos)
            if ($this.IsTokenValid()) {
                Write-Verbose "Token de acesso ainda é válido. Reutilizando token existente."
                return $this.AccessToken
            }

            Write-Verbose "Obtendo novo token de acesso do Azure AD..."
            $this.RequestNewAccessToken()
            return $this.AccessToken
        }
        catch {
            Write-Error "Erro ao obter token de acesso: $($_.Exception.Message)"
            throw
        }
    }

    # Verifica se o token atual ainda é válido
    [bool] IsTokenValid() {
        if ([string]::IsNullOrEmpty($this.AccessToken)) {
            return $false
        }

        # Adiciona margem de 5 minutos para evitar expiração durante uso
        $bufferTime = [datetime]::UtcNow.AddMinutes(5)
        return $this.TokenExpiration -gt $bufferTime
    }

    # Solicita um novo token de acesso do Azure AD
    [void] RequestNewAccessToken() {
        $attempt = 0
        $success = $false

        while (-not $success -and $attempt -lt $this.MaxRetryAttempts) {
            $attempt++
            
            try {
                Write-Verbose "Tentativa $attempt de $($this.MaxRetryAttempts) para obter token..."

                # Converte SecureString para texto plano (apenas durante a requisição)
                $clientSecretText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($this.ClientSecret)
                )

                # Prepara os dados da requisição OAuth2
                $tokenUri = "https://login.microsoftonline.com/$($this.TenantId)/oauth2/v2.0/token"
                $body = @{
                    grant_type    = "client_credentials"
                    client_id     = $this.ClientId
                    client_secret = $clientSecretText
                    scope         = "https://management.azure.com/.default"
                }

                # Configurações da requisição HTTP
                $headers = @{
                    'Content-Type' = 'application/x-www-form-urlencoded'
                    'Accept'       = 'application/json'
                }

                # Faz a requisição para o Azure AD
                $response = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -Headers $headers -TimeoutSec 30

                # Processa a resposta
                $this.AccessToken = $response.access_token
                $this.TokenExpiration = [datetime]::UtcNow.AddSeconds($response.expires_in)
                
                Write-Verbose "Token obtido com sucesso. Expira em: $($this.TokenExpiration.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
                $success = $true

                # Limpa o client secret da memória
                $clientSecretText = $null
                [System.GC]::Collect()
            }
            catch {
                Write-Warning "Tentativa $attempt falhou: $($_.Exception.Message)"
                
                if ($attempt -lt $this.MaxRetryAttempts) {
                    Write-Verbose "Aguardando $($this.RetryDelaySeconds) segundos antes da próxima tentativa..."
                    Start-Sleep -Seconds $this.RetryDelaySeconds
                }
                else {
                    throw "Falha ao obter token após $($this.MaxRetryAttempts) tentativas: $($_.Exception.Message)"
                }
            }
        }
    }

    # Cria headers de autorização para requisições à API REST
    [hashtable] GetAuthHeaders() {
        $token = $this.GetAccessToken()
        return @{
            'Authorization' = "Bearer $token"
            'Content-Type'  = 'application/json'
            'Accept'        = 'application/json'
        }
    }

    # Valida as credenciais testando acesso à API do Azure
    [bool] ValidateCredentials() {
        try {
            Write-Verbose "Validando credenciais do Service Principal..."
            
            $headers = $this.GetAuthHeaders()
            $uri = "https://management.azure.com/tenants?api-version=2020-01-01"
            
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 30
            
            Write-Verbose "Credenciais validadas com sucesso."
            return $true
        }
        catch {
            Write-Error "Falha na validação das credenciais: $($_.Exception.Message)"
            return $false
        }
    }

    # Limpa dados sensíveis da memória
    [void] Dispose() {
        $this.AccessToken = $null
        $this.ClientSecret = $null
        [System.GC]::Collect()
    }
}

# Função para criar instância do autenticador a partir de configuração
function New-AzureAuthenticator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [SecureString]$ClientSecret
    )

    try {
        Write-Verbose "Criando instância do Azure Authenticator..."
        
        # Validação básica dos parâmetros
        if ([string]::IsNullOrWhiteSpace($TenantId)) {
            throw "TenantId não pode ser vazio"
        }
        
        if ([string]::IsNullOrWhiteSpace($ClientId)) {
            throw "ClientId não pode ser vazio"
        }
        
        if ($null -eq $ClientSecret -or $ClientSecret.Length -eq 0) {
            throw "ClientSecret não pode ser vazio"
        }

        $authenticator = [AzureAuthenticator]::new($TenantId, $ClientId, $ClientSecret)
        
        # Testa as credenciais
        if (-not $authenticator.ValidateCredentials()) {
            throw "Falha na validação das credenciais do Service Principal"
        }

        Write-Verbose "Azure Authenticator criado e validado com sucesso."
        return $authenticator
    }
    catch {
        Write-Error "Erro ao criar Azure Authenticator: $($_.Exception.Message)"
        throw
    }
}

# Função para carregar client secret do Azure Key Vault (se especificado)
function Get-ClientSecretFromKeyVault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyVaultUrl,
        
        [Parameter(Mandatory = $true)]
        [object]$Authenticator
    )

    try {
        Write-Verbose "Obtendo client secret do Azure Key Vault: $KeyVaultUrl"
        
        $headers = $Authenticator.GetAuthHeaders()
        $uri = "$KeyVaultUrl" + "?api-version=7.3"
        
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 30
        
        $secretValue = $response.value
        $secureSecret = ConvertTo-SecureString -String $secretValue -AsPlainText -Force
        
        Write-Verbose "Client secret obtido do Key Vault com sucesso."
        return $secureSecret
    }
    catch {
        Write-Error "Erro ao obter client secret do Key Vault: $($_.Exception.Message)"
        throw
    }
}

# Exporta as funções públicas do módulo
Export-ModuleMember -Function @(
    'New-AzureAuthenticator',
    'Get-ClientSecretFromKeyVault'
)