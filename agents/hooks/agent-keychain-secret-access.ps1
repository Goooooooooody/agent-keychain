# Agent Keychain secret access hook.
# Dot-source this file to get Get-AkcSecret, or execute it directly:
#   .\agent-keychain-secret-access.ps1 -Name <secret-name> -Reason <reason>
param(
    [string]$Name,
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

if ($Name -and $Reason) {
    Get-AkcSecret -Name $Name -Reason $Reason
}
