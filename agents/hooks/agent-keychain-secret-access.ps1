# Agent Keychain secret access hook.
# Dot-source this file to get Find-AkcSecret and Get-AkcSecret, or execute it directly:
#   .\agent-keychain-secret-access.ps1 -Name <secret-name> -Reason <reason>
param(
    [string]$Name,
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
    Get-AkcSecret -Name $Name -Reason $Reason
}
