# Agent Keychain secret access hook.
# Dot-source this file to get Find-AkcSecret, Get-AkcSecret, and Get-AkcSecrets, or execute it directly:
#   .\agent-keychain-secret-access.ps1 -Name <secret-name>[,<secret-name>...] -Reason <reason>
param(
    [string[]]$Name,
    [string]$Query,
    [string]$Reason
)

function Get-AkcSecret {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $akc = Get-Command akc -ErrorAction SilentlyContinue
    if (-not $akc) {
        throw "akc is not installed or not on PATH"
    }

    $agentName = if ($env:AKC_AGENT_NAME) { $env:AKC_AGENT_NAME } else { $env:USERNAME }
    if (-not $agentName) { $agentName = "agent" }

    & akc agent-get --name $Name --agent $agentName --reason $Reason
}

function Get-AkcSecrets {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateCount(2, 64)]
        [string[]]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $akc = Get-Command akc -ErrorAction SilentlyContinue
    if (-not $akc) {
        throw "akc is not installed or not on PATH"
    }

    $agentName = if ($env:AKC_AGENT_NAME) { $env:AKC_AGENT_NAME } else { $env:USERNAME }
    if (-not $agentName) { $agentName = "agent" }

    & akc agent-get --name $Name --agent $agentName --reason $Reason
}

function Find-AkcSecret {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $akc = Get-Command akc -ErrorAction SilentlyContinue
    if (-not $akc) {
        throw "akc is not installed or not on PATH"
    }

    $agentName = if ($env:AKC_AGENT_NAME) { $env:AKC_AGENT_NAME } else { $env:USERNAME }
    if (-not $agentName) { $agentName = "agent" }

    & akc agent-search --query $Query --agent $agentName --reason $Reason
}

if ($Query -and $Reason) {
    Find-AkcSecret -Query $Query -Reason $Reason
} elseif ($Name -and $Reason) {
    if ($Name.Count -gt 1) {
        Get-AkcSecrets -Name $Name -Reason $Reason
    } else {
        Get-AkcSecret -Name $Name[0] -Reason $Reason
    }
}
