# Documentação dos CSVs de Mapping (Migração RG→RG)

## 1. rg-mapping.csv

Arquivo com **uma única linha** definindo origem e destino do Resource Group.

| Coluna | Obrigatório | Exemplo | Descrição |
|--------|-------------|---------|-----------|
| SourceSubscriptionId | Sim | 00000000-0000-0000-0000-000000000000 | Subscription onde está o RG origem |
| SourceResourceGroup  | Sim | rg-origem | Nome do RG origem |
| TargetSubscriptionId | Sim | 11111111-1111-1111-1111-111111111111 | Subscription de destino |
| TargetResourceGroup  | Sim | rg-destino | Nome do RG destino |

Exemplo:
```csv
SourceSubscriptionId,SourceResourceGroup,TargetSubscriptionId,TargetResourceGroup
00000000-0000-0000-0000-000000000000,rg-origem,11111111-1111-1111-1111-111111111111,rg-destino
```

## 2. resource-mapping.csv

Arquivo para remapear recursos específicos, principals e roles.

| Coluna | Obrigatório | Exemplo | Descrição |
|--------|-------------|---------|-----------|
| SourceScopeRelative | Sim | /providers/Microsoft.Storage/storageAccounts/appfiles | Caminho relativo ao RG origem (ou `/` para o próprio RG) |
| TargetScopeRelative | Não | /providers/Microsoft.Storage/storageAccounts/appfiles2 | Caminho relativo no RG destino (se vazio usa o mesmo) |
| PrincipalRemap | Não | 11111111-2222-3333-4444-555555555555 | Substitui principalId original |
| RoleRemap | Não | d73bb868-a0df-4d4d-bd69-98a00b01fccb | GUID ou roleDefinitionId completo destino |

Exemplo:
```csv
SourceScopeRelative,TargetScopeRelative,PrincipalRemap,RoleRemap
/providers/Microsoft.Storage/storageAccounts/appfiles,/providers/Microsoft.Storage/storageAccounts/appfiles2,,
/providers/Microsoft.KeyVault/vaults/kvold,/providers/Microsoft.KeyVault/vaults/kvnew,,
/providers/Microsoft.Web/sites/webappA,/providers/Microsoft.Web/sites/webappB,11111111-2222-3333-4444-555555555555,
/,,,
```

### Regras de Correspondência
- Comparação case-insensitive.
- `SourceScopeRelative` deve começar com `/`.
- Use `/` para regras aplicáveis ao nível do RG.
- Linhas sem `TargetScopeRelative` mantêm o valor original.

### RoleRemap
- GUID puro → convertido para id completo na subscription destino.
- ID completo aceito (`/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/{guid}`).
- Nome de role ainda não suportado diretamente (planejado).

### Processamento
1. Assignment exportado → extrai parte relativa do scope.
2. Aplica correspondência no índice `SourceScopeRelative`.
3. Constrói novo scope destino (com hierarquia preservada se `-PreserveHierarchy`).
4. Valida existência de recurso (não cria).
5. Verifica existência de assignment igual → SkipDuplicate.
6. Role inexistente → SkipRoleNotFound.

### Boas Práticas
- Trate primeiro recursos críticos (armazenamento, identity, key vault).
- Execute em `-WhatIf` até não haver `SkipMissingResource` inesperado.
- Versione seus CSVs (ex: `resource-mapping.v1.csv`).
- Mantenha comentários externos (não dentro do CSV) descrevendo decisões.

### Erros Comuns
| Erro | Causa | Ação |
|------|-------|------|
| SkipMissingResource | Recurso não existe no destino | Criar recurso manualmente ou ajustar TargetScopeRelative |
| SkipRoleNotFound | Role GUID não está disponível na subscription destino | Verificar se role é custom e precisa ser recriada |
| SkipDuplicate | Assignment já existe | Nenhuma ação necessária |

---
Atualizado em: $(Get-Date -Format 'yyyy-MM-dd')
