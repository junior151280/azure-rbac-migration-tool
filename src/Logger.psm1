# =============================================================================
# Azure RBAC Import Automation - Logging Module
# =============================================================================
# Este módulo implementa sistema de logging estruturado com arquivos separados
# para sucessos e erros, incluindo rotação de logs e diferentes níveis.
# =============================================================================

enum LogLevel {
    Error = 1
    Warning = 2
    Information = 3
    Verbose = 4
    Debug = 5
}

enum LogCategory {
    Authentication
    RbacExport
    RbacImport
    CsvProcessing
    General
}

class LogEntry {
    [datetime]$Timestamp
    [LogLevel]$Level
    [LogCategory]$Category
    [string]$Message
    [string]$Details
    [string]$CorrelationId
    [hashtable]$AdditionalData

    LogEntry([LogLevel]$level, [LogCategory]$category, [string]$message, [string]$details = "", [hashtable]$additionalData = @{}) {
        $this.Timestamp = Get-Date
        $this.Level = $level
        $this.Category = $category
        $this.Message = $message
        $this.Details = $details
        $this.CorrelationId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        $this.AdditionalData = $additionalData
    }

    [string] ToLogString() {
        $timestamp_str = $this.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")
        $level_str = $this.Level.ToString().ToUpper().PadRight(7)
        $category_str = $this.Category.ToString().PadRight(15)

        $logLine = "[$timestamp_str] [$level_str] [$category_str] [$($this.CorrelationId)] $($this.Message)"

        if (-not [string]::IsNullOrWhiteSpace($this.Details)) {
            $logLine += " | Details: $($this.Details)"
        }
        
        if ($this.AdditionalData.Count -gt 0) {
            $additionalDataJson = $this.AdditionalData | ConvertTo-Json -Compress
            $logLine += " | Data: $additionalDataJson"
        }
        
        return $logLine
    }

    [PSCustomObject] ToStructuredLog() {
        return [PSCustomObject]@{
            Timestamp = $this.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            Level = $this.Level.ToString()
            Category = $this.Category.ToString()
            Message = $this.Message
            Details = $this.Details
            CorrelationId = $this.CorrelationId
            AdditionalData = $this.AdditionalData
        }
    }
}

class Logger {
    [string]$LogDirectory
    [string]$BaseFileName
    [LogLevel]$MinLogLevel
    [bool]$EnableFileLogging
    [bool]$EnableConsoleLogging
    [bool]$EnableStructuredLogging
    [int]$MaxLogFileSizeMB
    [int]$MaxLogFiles
    [string]$CurrentLogFile
    [string]$CurrentErrorLogFile
    [string]$CurrentSuccessLogFile
    [string]$SessionId

    Logger([string]$logDirectory, [string]$baseFileName = "RbacImport") {
        $this.LogDirectory = $logDirectory
        $this.BaseFileName = $baseFileName
        $this.MinLogLevel = [LogLevel]::Information
        $this.EnableFileLogging = $true
        $this.EnableConsoleLogging = $true
        $this.EnableStructuredLogging = $true
        $this.MaxLogFileSizeMB = 50
        $this.MaxLogFiles = 10
        $this.SessionId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        
        $this.InitializeLogFiles()
    }

    [void] InitializeLogFiles() {
        try {
            # Cria o diretório de logs se não existir
            if (-not (Test-Path -Path $this.LogDirectory)) {
                New-Item -ItemType Directory -Path $this.LogDirectory -Force | Out-Null
            }

            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $sessionPrefix = "$($this.BaseFileName)-$timestamp-$($this.SessionId)"

            # Define os caminhos dos arquivos de log
            $this.CurrentLogFile = Join-Path -Path $this.LogDirectory -ChildPath "$sessionPrefix-All.log"
            $this.CurrentErrorLogFile = Join-Path -Path $this.LogDirectory -ChildPath "$sessionPrefix-Errors.log"
            $this.CurrentSuccessLogFile = Join-Path -Path $this.LogDirectory -ChildPath "$sessionPrefix-Success.log"

            # Cria os arquivos de log iniciais
            $this.WriteToFile($this.CurrentLogFile, "=== Log Session Started at $(Get-Date) ===")
            $this.WriteToFile($this.CurrentErrorLogFile, "=== Error Log Session Started at $(Get-Date) ===")
            $this.WriteToFile($this.CurrentSuccessLogFile, "=== Success Log Session Started at $(Get-Date) ===")

            Write-Verbose "Logger inicializado. Session ID: $($this.SessionId)"
            Write-Verbose "Log files:"
            Write-Verbose "  All: $($this.CurrentLogFile)"
            Write-Verbose "  Errors: $($this.CurrentErrorLogFile)"
            Write-Verbose "  Success: $($this.CurrentSuccessLogFile)"
        }
        catch {
            Write-Warning "Erro ao inicializar arquivos de log: $($_.Exception.Message)"
            $this.EnableFileLogging = $false
        }
    }

    [void] Log([LogLevel]$level, [LogCategory]$category, [string]$message, [string]$details = "", [hashtable]$additionalData = @{}) {
        # Verifica se deve registrar este nível de log
        if ($level -gt $this.MinLogLevel) {
            return
        }

        $logEntry = [LogEntry]::new($level, $category, $message, $details, $additionalData)
        
        # Log no console se habilitado
        if ($this.EnableConsoleLogging) {
            $this.WriteToConsole($logEntry)
        }

        # Log em arquivos se habilitado
        if ($this.EnableFileLogging) {
            $this.WriteToLogFiles($logEntry)
        }
    }

    [void] WriteToConsole([LogEntry]$logEntry) {
        $color = switch ($logEntry.Level) {
            ([LogLevel]::Error) { 'Red' }
            ([LogLevel]::Warning) { 'Yellow' }
            ([LogLevel]::Information) { 'White' }
            ([LogLevel]::Verbose) { 'Gray' }
            ([LogLevel]::Debug) { 'DarkGray' }
            default { 'White' }
        }

        Write-Host $logEntry.ToLogString() -ForegroundColor $color
    }

    [void] WriteToLogFiles([LogEntry]$logEntry) {
        try {
            $logString = $logEntry.ToLogString()
            
            # Escreve em log geral
            $this.WriteToFile($this.CurrentLogFile, $logString)
            
            # Escreve em log específico baseado no nível
            switch ($logEntry.Level) {
                ([LogLevel]::Error) {
                    $this.WriteToFile($this.CurrentErrorLogFile, $logString)
                }
                ([LogLevel]::Information) {
                    # Considera como sucesso se não for erro ou warning
                    if ($logEntry.Message -match "sucesso|completed|criado|importado|processado") {
                        $this.WriteToFile($this.CurrentSuccessLogFile, $logString)
                    }
                }
            }

            # Log estruturado em JSON se habilitado
            if ($this.EnableStructuredLogging) {
                $this.WriteStructuredLog($logEntry)
            }

            # Verifica se precisa rotacionar os logs
            $this.CheckLogRotation()
        }
        catch {
            Write-Warning "Erro ao escrever no arquivo de log: $($_.Exception.Message)"
        }
    }

    [void] WriteToFile([string]$filePath, [string]$content) {
        Add-Content -Path $filePath -Value $content -Encoding UTF8
    }

    [void] WriteStructuredLog([LogEntry]$logEntry) {
        try {
            $structuredLogFile = $this.CurrentLogFile -replace '\.log$', '.json'
            $structuredEntry = $logEntry.ToStructuredLog() | ConvertTo-Json -Compress
            $this.WriteToFile($structuredLogFile, $structuredEntry)
        }
        catch {
            # Falha silenciosa no log estruturado
        }
    }

    [void] CheckLogRotation() {
        try {
            if (Test-Path -Path $this.CurrentLogFile) {
                $fileSize = (Get-Item $this.CurrentLogFile).Length / 1MB
                
                if ($fileSize -gt $this.MaxLogFileSizeMB) {
                    $this.RotateLogFiles()
                }
            }
        }
        catch {
            # Falha silenciosa na rotação
        }
    }

    [void] RotateLogFiles() {
        try {
            Write-Verbose "Rotacionando arquivos de log..."
            
            # Remove logs antigos excedentes
            $existingLogs = Get-ChildItem -Path $this.LogDirectory -Filter "$($this.BaseFileName)-*.log" | 
                           Sort-Object LastWriteTime -Descending
            
            if ($existingLogs.Count -gt $this.MaxLogFiles) {
                $logsToRemove = $existingLogs | Select-Object -Skip $this.MaxLogFiles
                foreach ($log in $logsToRemove) {
                    Remove-Item -Path $log.FullName -Force
                }
            }

            # Cria novos arquivos de log
            $this.InitializeLogFiles()
        }
        catch {
            Write-Warning "Erro durante rotação de logs: $($_.Exception.Message)"
        }
    }

    # Métodos de conveniência para diferentes níveis de log
    [void] LogError([LogCategory]$category, [string]$message, [string]$details = "", [hashtable]$additionalData = @{}) {
        $this.Log([LogLevel]::Error, $category, $message, $details, $additionalData)
    }

    [void] LogWarning([LogCategory]$category, [string]$message, [string]$details = "", [hashtable]$additionalData = @{}) {
        $this.Log([LogLevel]::Warning, $category, $message, $details, $additionalData)
    }

    [void] LogInfo([LogCategory]$category, [string]$message, [string]$details = "", [hashtable]$additionalData = @{}) {
        $this.Log([LogLevel]::Information, $category, $message, $details, $additionalData)
    }

    [void] LogVerbose([LogCategory]$category, [string]$message, [string]$details = "", [hashtable]$additionalData = @{}) {
        $this.Log([LogLevel]::Verbose, $category, $message, $details, $additionalData)
    }

    [void] LogDebug([LogCategory]$category, [string]$message, [string]$details = "", [hashtable]$additionalData = @{}) {
        $this.Log([LogLevel]::Debug, $category, $message, $details, $additionalData)
    }

    # Registra início de operação
    [string] StartOperation([LogCategory]$category, [string]$operationName, [hashtable]$operationData = @{}) {
        $operationId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        $data = $operationData.Clone()
        $data.OperationId = $operationId
        
        $this.LogInfo($category, "Iniciando operação: $operationName", "", $data)
        return $operationId
    }

    # Registra fim de operação com sucesso
    [void] CompleteOperation([LogCategory]$category, [string]$operationName, [string]$operationId, [hashtable]$resultData = @{}) {
        $data = $resultData.Clone()
        $data.OperationId = $operationId
        
        $this.LogInfo($category, "Operação concluída com sucesso: $operationName", "", $data)
    }

    # Registra fim de operação com erro
    [void] FailOperation([LogCategory]$category, [string]$operationName, [string]$operationId, [string]$errorDetails, [hashtable]$errorData = @{}) {
        $data = $errorData.Clone()
        $data.OperationId = $operationId
        
        $this.LogError($category, "Operação falhou: $operationName", $errorDetails, $data)
    }

    # Encerra a sessão de log
    [void] CloseSession() {
        try {
            $this.WriteToFile($this.CurrentLogFile, "=== Log Session Ended at $(Get-Date) ===")
            $this.WriteToFile($this.CurrentErrorLogFile, "=== Error Log Session Ended at $(Get-Date) ===")
            $this.WriteToFile($this.CurrentSuccessLogFile, "=== Success Log Session Ended at $(Get-Date) ===")
            
            Write-Verbose "Sessão de log encerrada. Session ID: $($this.SessionId)"
        }
        catch {
            Write-Warning "Erro ao encerrar sessão de log: $($_.Exception.Message)"
        }
    }
}

# Função para criar instância do logger
function New-Logger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogDirectory,
        
        [Parameter()]
        [string]$BaseFileName = "RbacImport",
        
        [Parameter()]
        [LogLevel]$MinLogLevel = [LogLevel]::Information,
        
        [Parameter()]
        [switch]$DisableConsoleLogging,
        
        [Parameter()]
        [switch]$DisableFileLogging,
        
        [Parameter()]
        [switch]$DisableStructuredLogging
    )

    try {
        Write-Verbose "Criando instância do Logger..."
        
        $logger = [Logger]::new($LogDirectory, $BaseFileName)
        $logger.MinLogLevel = $MinLogLevel
        $logger.EnableConsoleLogging = -not $DisableConsoleLogging.IsPresent
        $logger.EnableFileLogging = -not $DisableFileLogging.IsPresent
        $logger.EnableStructuredLogging = -not $DisableStructuredLogging.IsPresent
        
        Write-Verbose "Logger criado com sucesso."
        return $logger
    }
    catch {
        Write-Error "Erro ao criar Logger: $($_.Exception.Message)"
        throw
    }
}

# Exporta as funções públicas do módulo
Export-ModuleMember -Function @('New-Logger')