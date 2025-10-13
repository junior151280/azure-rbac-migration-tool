# Azure RBAC Migration Tool

Uma automação PowerShell para migrar permissões RBAC entre subscriptions do Azure usando APIs REST, com transformações otimizadas e estrutura simplificada.

## 📋 Funcionalidades

- **Exportação Otimizada**: Lista permissões RBAC com métodos API otimizados para subscription completa
- **Transformações Inteligentes**: Sistema de mapeamento CSV com Type columns para transformações direcionadas
- **Autenticação Flexível**: Service Principal com suporte a config.json e Azure Key Vault
- **Processamento Eficiente**: Evita transformações desnecessárias em campos vazios
- **Tratamento de Erros Robusto**: Retry logic, detecção de conflitos e permissões existentes
- **Logging Estruturado**: Sistema de logging categorizado com diferentes níveis
- **Validação Inteligente**: Verifica duplicatas e valida permissões antes da aplicação
- **Relatórios Detalhados**: Estatísticas completas e rastreamento de transformações
- **Migração RG→RG Recursiva**: Novo fluxo dedicado para exportar e importar permissões de um Resource Group incluindo todos os recursos internos sem criar recursos inexistentes
- **Dois Arquivos de Mapping Específicos**: Separação clara entre mapeamento do RG e mapeamento de recursos/principals/roles (renomeação granular)
- **WhatIf Avançado**: Simula criação e fornece relatório com contagem por nível (RG vs recurso) e motivos de skip

## 🏗️ Estrutura do Projeto

```
zurich-rbac-import/
├── src/                          # Módulos PowerShell (arquitetura modular)
│   ├── AzureAuthenticator.psm1   # Autenticação com Service Principal e Key Vault
│   ├── AzureRbacManager.psm1     # APIs REST otimizadas para RBAC
│   ├── Logger.psm1               # Sistema de logging estruturado e categorizado
│   ├── CsvProcessor.psm1         # Processamento CSV com validação Type-aware
│   ├── RbacMigrator.psm1         # Migração com transformações inteligentes
│   └── RbacTransformer.psm1      # Engine de transformações direcionadas
├── config/                       # Configuração centralizada
│   ├── config.json               # Configuração principal (SourceSubscriptions array)
│   └── rbac-mapping-new.csv      # Mapeamento com Type columns
├── examples/                     # Exemplos e templates
├── logs/                         # Logs estruturados (auto-gerados)
├── output/                       # Arquivos de saída
├── Start-RbacMigration.ps1       # Script principal (versão completa)
├── Start-RbacMigrationSimple.ps1 # Script simplificado (versão otimizada)
└── Debug-Transformation.ps1     # Ferramenta de debug de transformações
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
    "Name": "Subscription Destino",
    "ResourceGroups": [
      "rg-new-web",
      "rg-new-data"
    ]
  },
  "Authentication": {
    "TenantId": "22222222-2222-2222-2222-222222222222",
    "ClientId": "33333333-3333-3333-3333-333333333333",
    "ClientSecretKeyVaultUrl": "https://kv-exemplo.vault.azure.net/secrets/sp-secret"
  },
  "ServicePrincipal": {
    "TenantId": "22222222-2222-2222-2222-222222222222",
    "ClientId": "33333333-3333-3333-3333-333333333333",
    "ClientSecret": "client-secret-direto"
  },
  "Settings": {
    "WhatIfMode": false,
    "MaxRetryAttempts": 3,
    "RetryDelaySeconds": 5,
    "LogLevel": "Information",
    "SkipExistingAssignments": true
  }
}
```

### 3. Arquivo CSV de Mapeamento com Type Columns

Crie o arquivo CSV `config/rbac-mapping-new.csv` com o mapeamento otimizado:

```csv
Source,Target,Type
cad9e0b6-be6e-4cb0-a4bc-3f81708540f9,cad9e0b6-be6e-4cb0-a4bc-3f81708540f9,SubscriptionId
rg-poc-service-bus,demo-rebac-import,ResourceGroup
```

**Nova Estrutura Simplificada:**
- **Source**: Valor original a ser transformado
- **Target**: Valor de destino para a transformação
- **Type**: Categoria da transformação (SubscriptionId, ResourceGroup, etc.)

**Tipos de Transformação Suportados:**
- **SubscriptionId**: Transforma IDs de subscription
- **ResourceGroup**: Mapeia resource groups de origem para destino
- **PrincipalId**: Mapeia usuários/grupos/service principals
- **RoleDefinition**: Transforma nomes de roles
- **Scope**: Transforma escopos completos

**Vantagens da Nova Estrutura:**
- ✅ **Mais eficiente**: Evita transformações desnecessárias em campos vazios
- ✅ **Tipo-específico**: Aplicação direcionada baseada no Type
- ✅ **Menos redundância**: Reutiliza transformações para múltiplas permissões
- ✅ **Mais legível**: Estrutura clara e concisa

## 🚀 Como Usar

### Opção 1: Script Simplificado (Recomendado)

```powershell
# Execução otimizada com configuração centralizada
.\Start-RbacMigrationSimple.ps1
```

**Características do Script Simplificado:**
- ✅ Usa `config/config.json` automaticamente
- ✅ Carrega `config/rbac-mapping-new.csv` automaticamente
- ✅ Transformações otimizadas com Type columns
- ✅ Logging estruturado e categorizado
- ✅ Tratamento robusto de erros e conflitos
- ✅ Detecção automática de permissões existentes

### Opção 2: Script Completo (Flexibilidade Total)

```powershell
# Execução completa com parâmetros customizados
.\Start-RbacMigration.ps1 `
    -ConfigFile "config\config.json" `
    -CsvMappingFile "config\rbac-mapping-new.csv" `
    -Operation "Both" `
    -SkipExistingAssignments `
    -LogLevel "Information"
```

### Opção 3: Migração RG → RG Recursiva (Dois CSVs)

Pode executar um fluxo dedicado para copiar permissões de um RG origem para outro RG (mesma ou outra subscription), aplicando renomeação opcional de recursos, principals e roles.

```powershell
./Start-RgRbacMigration.ps1 `
  -SourceSubscriptionId "00000000-0000-0000-0000-000000000000" `
  -SourceResourceGroup "rg-origem" `
  -TargetSubscriptionId "11111111-1111-1111-1111-111111111111" `
  -TargetResourceGroup "rg-destino" `
  -RgMappingFile "config/rg-mapping.csv" `
  -ResourceMappingFile "config/resource-mapping.csv" `
  -PreserveHierarchy `
  -WhatIf
```

Remova `-WhatIf` para aplicar de fato. Use `-PreserveHierarchy` para manter a estrutura de scopes (ex: `/providers/Microsoft.Storage/storageAccounts/st1`). Sem esse switch, todas as permissões são trazidas para o escopo do próprio RG destino.

Relatório gerado em `output/rg-rbac-import-report.json` contendo:
- `totals`: created, skipped, errors, processed
- `levelStats`: estatísticas segmentadas por `resourceGroup` e `resource`
- `missingResources`: lista de recursos que não existem no destino (não são criados)
- `items`: ações detalhadas (`Created`, `WhatIfCreate`, `SkipDuplicate`, `SkipRoleNotFound`, `SkipMissingResource` etc.)

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
| `PreserveHierarchy` | Switch | false | (RG→RG) Mantém estrutura de recursos originais |
| `RgMappingFile` | String | - | (RG→RG) CSV de mapeamento do RG origem para destino |
| `ResourceMappingFile` | String | - | (RG→RG) CSV de mapeamento de recursos/principals/roles |
| `WhatIf` | Switch | false | (RG→RG) Simula import reportando ações |

## 📈 Logs e Relatórios

### Sistema de Logging Estruturado
```
logs/
├── RbacImport-{timestamp}-{sessionId}.log    # Log principal com todas as operações
├── transformation-details.log                # Detalhes das transformações aplicadas
└── error-analysis.log                       # Análise detalhada de erros
```

### Categorias de Log Implementadas
- **General**: Operações principais do sistema
- **RbacExport**: Exportação de permissões da origem
- **RbacImport**: Importação e aplicação no destino
- **CsvProcessing**: Processamento e validação do CSV
- **Authentication**: Operações de autenticação
- **Transformation**: Detalhes das transformações aplicadas

### Relatórios Automatizados
- **Estatísticas de Transformação**: Quantas transformações foram aplicadas por tipo
- **Permissões Duplicadas**: Lista de atribuições já existentes
- **Conflitos de Importação**: Erros 403/409 tratados automaticamente
- **Performance Metrics**: Tempo de execução e taxa de sucesso

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

**4. "RoleAssignmentExists" ou "Conflict"**
- O sistema agora detecta automaticamente conflitos e permissões existentes
- Mensagens 403 Forbidden são tratadas como warnings, não erros fatais
- Use WhatIfMode para simular sem aplicar mudanças

**5. "Cannot find an overload for 'new'"**
- Cache de módulos PowerShell - execute `Get-Module | Remove-Module -Force`
- Reinicie a sessão PowerShell se o problema persistir
- Use o script em uma nova sessão PowerShell isolada

**6. "TooManyRequests"**
- O script inclui retry logic com exponential backoff
- APIs otimizadas reduzem o número de chamadas necessárias
- Aguarde e execute novamente se persistir

### Verificação de Logs
```powershell
# Ver últimos erros
Get-Content "logs\*-Errors.log" | Select-Object -Last 20

# Ver estatísticas do último relatório
Get-Content "logs\import-operations-report.json" | ConvertFrom-Json | Select-Object Statistics
```

## 🔄 Workflow Recomendado

1. **Configuração Inicial**
   - Configure Service Principal com permissões `User Access Administrator`
   - Edite `config/config.json` com subscriptions de origem e destino
   - Crie `config/rbac-mapping-new.csv` com transformações Source→Target

2. **Teste de Conectividade**
   - Execute script para verificar autenticação
   - Confirme que consegue listar permissões da origem
   - Valide se consegue acessar subscription de destino

3. **Simulação (WhatIfMode)**
   - Configure `"WhatIfMode": true` no config.json
   - Execute `Start-RbacMigrationSimple.ps1`
   - Analise logs e transformações planejadas

4. **Execução Controlada**
   - Configure `"WhatIfMode": false`
   - Execute migração real
   - Monitore logs para conflitos e erros 403 (tratados automaticamente)

5. **Validação Pós-Migração**
   - Verifique permissões aplicadas no destino
   - Confirme que apenas novas permissões foram criadas
   - Analise estatísticas de transformação nos logs

## 📚 Exemplos Adicionais

### Executar com Client Secret via parâmetro
```powershell
$clientSecret = "seu-client-secret"
.\Start-RbacMigration.ps1 -ClientSecret $clientSecret -Operation "Both"
```

### Executar apenas para uma subscription
### Migração RG → RG com Flatten (sem hierarquia)
```powershell
./Start-RgRbacMigration.ps1 `
  -SourceSubscriptionId $subSrc `
  -SourceResourceGroup $rgSrc `
  -TargetSubscriptionId $subDst `
  -TargetResourceGroup $rgDst `
  -RgMappingFile config/rg-mapping.csv `
  -ResourceMappingFile config/resource-mapping.csv `
  -WhatIf
```

### Migração RG → RG preservando hierarquia
```powershell
./Start-RgRbacMigration.ps1 `
  -SourceSubscriptionId $subSrc `
  -SourceResourceGroup $rgSrc `
  -TargetSubscriptionId $subDst `
  -TargetResourceGroup $rgDst `
  -RgMappingFile config/rg-mapping.csv `
  -ResourceMappingFile config/resource-mapping.csv `
  -PreserveHierarchy
```

### Exemplo de relatório (trecho)
```json
{
  "totals": { "created": 5, "skipped": 3, "errors": 0, "processed": 8 },
  "levelStats": {
    "resourceGroup": { "processed": 2, "created": 2, "skipped": 0, "errors": 0 },
    "resource": { "processed": 6, "created": 3, "skipped": 3, "errors": 0 }
  },
  "missingResources": [
    "/subscriptions/1111/resourceGroups/rg-destino/providers/Microsoft.ServiceBus/namespaces/ns1"
  ]
}
```

## 📑 Estrutura dos Dois CSVs (RG→RG)

### 1. rg-mapping.csv

Campos obrigatórios (uma única linha):
```csv
SourceSubscriptionId,SourceResourceGroup,TargetSubscriptionId,TargetResourceGroup
00000000-0000-0000-0000-000000000000,rg-origem,11111111-1111-1111-1111-111111111111,rg-destino
```

Uso: Determina a substituição básica do prefixo de escopo.

### 2. resource-mapping.csv

Colunas: `SourceScopeRelative,TargetScopeRelative,PrincipalRemap,RoleRemap`

```csv
SourceScopeRelative,TargetScopeRelative,PrincipalRemap,RoleRemap
/providers/Microsoft.Storage/storageAccounts/appfiles,/providers/Microsoft.Storage/storageAccounts/appfiles,,
/providers/Microsoft.KeyVault/vaults/kvold,/providers/Microsoft.KeyVault/vaults/kvnew,,
/providers/Microsoft.Web/sites/webappA,/providers/Microsoft.Web/sites/webappB,11111111-2222-3333-4444-555555555555,
/,,,
```

Regras:
- `SourceScopeRelative` deve iniciar com `/` ou ser `/` (que representa o próprio RG)
- `TargetScopeRelative` vazio → usa mesmo relativo origem
- `PrincipalRemap` (opcional) substitui `principalId`
- `RoleRemap` suporta:
  - GUID puro (ex: `d73bb868-a0df-4d4d-bd69-98a00b01fccb`)
  - ID completo `/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/{guid}`
  - (Nome de role ainda não suportado diretamente na importação RG→RG)
- Linha com apenas `/` pode redefinir comportamento para nível RG

Validações no processo de import:
- Role inexistente → `SkipRoleNotFound`
- Recurso destino não existe → `SkipMissingResource` (não tenta criar)
- Assignment já existe → `SkipDuplicate`

### Hierarquia vs Flatten
- Com `-PreserveHierarchy`: scopes reconstruídos no destino mantendo sufixo relativo.
- Sem `-PreserveHierarchy`: todos assignments aplicados diretamente no escopo do RG destino.

### Dicas de Qualidade
- Ordene `resource-mapping.csv` por profundidade (mais específicos primeiro) se planejar fazer revisões manuais.
- Use GUIDs de principal confirmados (Azure AD) antes da execução real.
- Execute sempre com `-WhatIf` para validar cobertura antes da execução efetiva.

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