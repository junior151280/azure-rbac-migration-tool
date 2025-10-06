# Azure RBAC Migration Tool

Uma automação PowerShell para migrar permissões RBAC entre subscriptions do Azure usando APIs REST.

## 📋 Funcionalidades

- **Exportação de Permissões**: Lista todas as permissões RBAC de Resource Groups específicos
- **Importação com Mapeamento**: Aplica permissões em nova subscription baseado em mapeamento CSV
- **Autenticação Segura**: Utiliza Service Principal com suporte a Azure Key Vault
- **Tratamento de Erros**: Skip e continue em erros + retry logic
- **Logging Detalhado**: Arquivos separados para sucessos e erros
- **Validação Completa**: Valida CSV, principals, resource groups e permissions
- **Relatórios**: Gera relatórios JSON detalhados de todas as operações

## 🏗️ Estrutura do Projeto

```
zurich-rbac-import/
├── src/                          # Módulos PowerShell
│   ├── AzureAuthenticator.psm1   # Autenticação com Service Principal
│   ├── AzureRbacManager.psm1     # Gerenciamento de RBAC via APIs REST
│   ├── Logger.psm1               # Sistema de logging estruturado
│   ├── CsvProcessor.psm1         # Processamento e validação de CSV
│   └── RbacImporter.psm1         # Importação e aplicação de permissões
├── config/                       # Arquivos de configuração
│   └── config.json               # Configuração principal
├── examples/                     # Exemplos e templates
│   ├── rbac-mapping.csv          # Template do arquivo CSV
│   ├── Export-Only.ps1           # Exemplo de exportação
│   ├── Validate-Only.ps1         # Exemplo de validação
│   └── Full-Process.ps1          # Processo completo
├── logs/                         # Arquivos de log (gerados automaticamente)
├── exports/                      # Arquivos de exportação
└── Start-RbacMigration.ps1       # Script principal
```

## ⚙️ Configuração

### 1. Service Principal

Crie um Service Principal no Azure AD:

```powershell
# Criar Service Principal
az ad sp create-for-rbac --name "rbac-migration-sp" --role "User Access Administrator" --scopes "/subscriptions/{subscription-id}"
```

O Service Principal precisa das seguintes permissões:
- **User Access Administrator** nas subscriptions de origem e destino
- **Reader** para validar resource groups
- **Directory.Read.All** no Microsoft Graph (opcional, para validação de principals)

### 2. Arquivo de Configuração

Edite `config/config.json`:

```json
{
  "SourceSubscriptions": [
    {
      "SubscriptionId": "00000000-0000-0000-0000-000000000000",
      "Name": "Subscription Origem",
      "ResourceGroups": [
        "rg-prod-web",
        "rg-prod-data"
      ]
    }
  ],
  "TargetSubscription": {
    "SubscriptionId": "11111111-1111-1111-1111-111111111111",
    "Name": "Subscription Destino"
  },
  "ServicePrincipal": {
    "TenantId": "22222222-2222-2222-2222-222222222222",
    "ClientId": "33333333-3333-3333-3333-333333333333",
    "ClientSecretKeyVaultUrl": "https://kv-exemplo.vault.azure.net/secrets/sp-secret"
  },
  "Settings": {
    "CsvMappingFile": "examples/rbac-mapping.csv",
    "ExportedRbacFile": "exports/rbac-export.json",
    "MaxRetryAttempts": 3,
    "RetryDelaySeconds": 5,
    "LogLevel": "Information",
    "SkipExistingAssignments": true
  }
}
```

### 3. Arquivo CSV de Mapeamento

Crie o arquivo CSV com o mapeamento das permissões:

```csv
SourceSubscriptionId,SourceResourceGroup,SourcePrincipalId,SourceRoleDefinition,TargetSubscriptionId,TargetResourceGroup,TargetPrincipalId,TargetRoleDefinition
00000000-0000-0000-0000-000000000000,rg-prod-web,aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa,Contributor,11111111-1111-1111-1111-111111111111,rg-new-web,bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb,Contributor
00000000-0000-0000-0000-000000000000,rg-prod-data,cccccccc-cccc-cccc-cccc-cccccccccccc,Reader,11111111-1111-1111-1111-111111111111,rg-new-data,dddddddd-dddd-dddd-dddd-dddddddddddd,Reader
```

**Campos obrigatórios:**
- **SourceSubscriptionId**: GUID da subscription de origem
- **SourceResourceGroup**: Nome do resource group de origem
- **SourcePrincipalId**: GUID do principal (usuário/grupo/service principal) de origem
- **SourceRoleDefinition**: Nome da role (ex: "Contributor", "Reader")
- **TargetSubscriptionId**: GUID da subscription de destino
- **TargetResourceGroup**: Nome do resource group de destino
- **TargetPrincipalId**: GUID do principal de destino
- **TargetRoleDefinition**: Nome da role de destino (geralmente igual à origem)

## 🚀 Como Usar

### Opção 1: Processo Completo (Exportar + Importar)

```powershell
# Execução completa com todas as validações
.\Start-RbacMigration.ps1 `
    -ConfigFile "config\config.json" `
    -CsvMappingFile "examples\rbac-mapping.csv" `
    -Operation "Both" `
    -SkipExistingAssignments `
    -LogLevel "Information"
```

### Opção 2: Apenas Exportação

```powershell
# Exporta permissões RBAC dos Resource Groups especificados
.\Start-RbacMigration.ps1 `
    -ConfigFile "config\config.json" `
    -Operation "Export" `
    -LogLevel "Verbose"
```

### Opção 3: Apenas Importação

```powershell
# Importa permissões baseado no mapeamento CSV
.\Start-RbacMigration.ps1 `
    -ConfigFile "config\config.json" `
    -CsvMappingFile "examples\rbac-mapping.csv" `
    -Operation "Import" `
    -SkipExistingAssignments `
    -MaxRetryAttempts 3
```

### Opção 4: Validação Apenas

```powershell
# Valida o CSV e configurações sem aplicar mudanças
.\Start-RbacMigration.ps1 `
    -ConfigFile "config\config.json" `
    -CsvMappingFile "examples\rbac-mapping.csv" `
    -Operation "Import" `
    -ValidateOnly
```

## 📊 Parâmetros Disponíveis

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|---------|-----------|
| `ConfigFile` | String | "config\config.json" | Caminho para arquivo de configuração |
| `CsvMappingFile` | String | - | Caminho para arquivo CSV de mapeamento |
| `ClientSecret` | String | - | Client Secret (se não fornecido, será solicitado) |
| `Operation` | String | "Both" | Operação: "Export", "Import", "Both" |
| `ValidateOnly` | Switch | false | Apenas valida, não aplica mudanças |
| `SkipExistingAssignments` | Switch | false | Pula atribuições que já existem |
| `MaxRetryAttempts` | Int | 3 | Máximo de tentativas em caso de erro |
| `LogLevel` | String | "Information" | Nível de log: Error, Warning, Information, Verbose, Debug |

## 📈 Logs e Relatórios

### Arquivos de Log
- **RbacImport-{timestamp}-{sessionId}-All.log**: Log completo
- **RbacImport-{timestamp}-{sessionId}-Errors.log**: Apenas erros
- **RbacImport-{timestamp}-{sessionId}-Success.log**: Apenas sucessos
- **RbacImport-{timestamp}-{sessionId}-All.json**: Log estruturado em JSON

### Relatórios Gerados
- **csv-validation-report.json**: Relatório de validação do CSV
- **import-operations-report.json**: Relatório detalhado de todas as operações de importação
- **rbac-export.json**: Arquivo de exportação das permissões RBAC

## 🔒 Segurança

### Melhores Práticas Implementadas
- ✅ Autenticação via Service Principal (sem credenciais hardcoded)
- ✅ Suporte a Azure Key Vault para secrets
- ✅ Client Secret limpo da memória após uso
- ✅ Retry logic com exponential backoff
- ✅ Validação de principals e resource groups
- ✅ Logs detalhados para auditoria
- ✅ Tratamento seguro de erros

### Configuração de Segurança
1. Use sempre Service Principal com permissions mínimas necessárias
2. Armazene Client Secret no Azure Key Vault quando possível
3. Execute em ambiente controlado com logs auditáveis
4. Revise sempre o CSV antes da execução
5. Teste em ambiente não-produtivo primeiro

## 🐛 Troubleshooting

### Erros Comuns

**1. "Falha na validação das credenciais"**
- Verifique TenantId, ClientId e ClientSecret
- Confirme que o Service Principal existe e tem as permissões adequadas

**2. "Resource Group de destino não existe"**
- Crie o resource group de destino antes da execução
- Ou desabilite a validação: `"ValidateTargetResourceGroups": false`

**3. "Role definition não encontrada"**
- Verifique se o nome da role está correto (case-sensitive)
- Use nomes built-in como "Contributor", "Reader", "Owner"

**4. "RoleAssignmentExists"**
- Use `-SkipExistingAssignments` para pular atribuições existentes
- Ou remova manualmente as atribuições duplicadas

**5. "TooManyRequests"**
- O script já inclui retry logic e rate limiting
- Aguarde e execute novamente se persistir

### Verificação de Logs
```powershell
# Ver últimos erros
Get-Content "logs\*-Errors.log" | Select-Object -Last 20

# Ver estatísticas do último relatório
Get-Content "logs\import-operations-report.json" | ConvertFrom-Json | Select-Object Statistics
```

## 🔄 Workflow Recomendado

1. **Planejamento**
   - Identifique subscriptions e resource groups de origem
   - Mapeie principals e roles para destino
   - Crie Service Principal com permissões adequadas

2. **Preparação**
   - Configure `config/config.json`
   - Crie arquivo CSV de mapeamento
   - Crie resource groups de destino se necessário

3. **Validação**
   - Execute com `-ValidateOnly` primeiro
   - Revise relatório de validação
   - Corrija erros no CSV se necessário

4. **Teste**
   - Execute em ambiente de desenvolvimento/teste
   - Verifique logs e relatórios
   - Valide permissões aplicadas

5. **Produção**
   - Execute o processo completo
   - Monitore logs em tempo real
   - Valide resultado final

## 📚 Exemplos Adicionais

### Executar com Client Secret via parâmetro
```powershell
$clientSecret = "seu-client-secret"
.\Start-RbacMigration.ps1 -ClientSecret $clientSecret -Operation "Both"
```

### Executar apenas para uma subscription
Edite o `config.json` para incluir apenas a subscription desejada.

### Processamento em lotes grandes
O script já divide automaticamente em lotes para evitar rate limiting do Azure.

## 📞 Suporte

Para questões, bugs ou melhorias:
1. Verifique os logs detalhados primeiro
2. Consulte a seção de Troubleshooting
3. Execute com `-LogLevel Debug` para informações adicionais

## 📄 Licença

Este projeto está licenciado sob a licença MIT. Veja o arquivo LICENSE para detalhes.

---

**⚠️ AVISO IMPORTANTE:** 
- Sempre teste em ambiente não-produtivo primeiro
- Revise cuidadosamente o arquivo CSV antes da execução
- Mantenha backups das configurações RBAC existentes
- Este script modifica permissões de acesso - use com cautela