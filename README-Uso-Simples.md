# 🚀 Azure RBAC Migration Tool - Guia Simples

## ✅ Como Usar (Fluxo Original Restaurado)

### 1. **Configurar Credenciais Azure**
```powershell
# Opção A: Variáveis de ambiente
$env:AZURE_TENANT_ID = "seu-tenant-id"
$env:AZURE_CLIENT_ID = "seu-client-id"  
$env:AZURE_CLIENT_SECRET = "seu-client-secret"

# Opção B: Adicionar no config.json
{
  "Authentication": {
    "TenantId": "seu-tenant-id",
    "ClientId": "seu-client-id"
  }
}
```

### 2. **Configurar config.json**
```json
{
  "Authentication": {
    "TenantId": "seu-tenant-id",
    "ClientId": "seu-client-id"
  },
  "SourceSubscription": {
    "SubscriptionId": "subscription-origem-id",
    "ResourceGroups": ["rg-destino1", "rg-destino2"]
  },
  "TargetSubscription": {
    "SubscriptionId": "subscription-destino-id",
    "ResourceGroups": ["rg-destino1", "rg-destino2"]
  }
}
```

### 3. **Configurar rbac-mapping-new.csv**
```csv
Source,Target,Type
subscription-origem-id,subscription-destino-id,SubscriptionId
rg-origem,rg-destino,ResourceGroup
```

### 4. **Executar Migração**

**Teste primeiro (recomendado):**
```powershell
.\Start-RbacMigrationSimple.ps1 -WhatIf
```

**Execução real:**
```powershell
.\Start-RbacMigrationSimple.ps1
```

## 🎯 O que o script faz (Fluxo Simples)

1. ✅ **Carrega config.json** - informações de origem e destino
2. ✅ **Carrega CSV** - transformações Source → Target
3. ✅ **Conecta Azure** - busca atribuições da subscription origem
4. ✅ **Aplica transformações** - usando regras otimizadas do CSV
5. ✅ **Filtra destinos** - apenas subscription/RGs especificados
6. ✅ **Verifica duplicatas** - evita criações desnecessárias
7. ✅ **Importa permissões** - cria atribuições na subscription destino
8. ✅ **Gera relatório** - estatísticas e logs estruturados

## ⚡ Otimizações Implementadas (Internas)

- 🚀 **GetRbacAssignmentsForSubscription** - método direto da API
- 🚀 **Transformações direcionadas** - por tipo (SubscriptionId, ResourceGroup)
- 🚀 **Evita campos vazios** - não transforma createdOn, updatedOn, etc.
- 🚀 **CreateRbacAssignment corrigido** - payload estruturado
- 🚀 **Logs otimizados** - menos ruído, mais precisão

## 📁 Estrutura Simples

```
zurich-rbac-import/
├── config/
│   ├── config.json              # Configuração principal
│   └── rbac-mapping-new.csv     # Transformações
├── Start-RbacMigrationSimple.ps1 # SCRIPT PRINCIPAL
├── logs/                        # Logs automáticos
└── output/                      # Relatórios
```

## 🔧 Exemplo Completo

```powershell
# 1. Configure credenciais
$env:AZURE_TENANT_ID = "12345678-1234-1234-1234-123456789012"
$env:AZURE_CLIENT_ID = "87654321-4321-4321-4321-210987654321"  
$env:AZURE_CLIENT_SECRET = "seu-secret"

# 2. Execute
.\Start-RbacMigrationSimple.ps1 -WhatIf

# 3. Se OK, execute real
.\Start-RbacMigrationSimple.ps1
```

---

**Use apenas: `.\Start-RbacMigrationSimple.ps1 -WhatIf`** 🎯