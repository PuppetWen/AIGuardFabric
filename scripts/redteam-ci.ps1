<#
.SYNOPSIS
Submit or inspect a red-team campaign and enforce its saved CI verdict.
.DESCRIPTION
Use AGF_CI_API_KEY from your CI secret store; never pass credentials on the command line.
Exit 0 = passed, 1 = gate failed, 2 = incomplete/invalid/execution/API failure.
Simulator results require explicit -AllowSimulation and are not a production security gate.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][uri]$BaseUrl,
    [Parameter(Mandatory=$true)][guid]$TenantId,
    [guid]$CampaignId=[guid]::Empty,
    [guid]$AgentTargetId=[guid]::Empty,
    [guid]$McpTargetId=[guid]::Empty,
    [string]$Name='CI red-team check',
    [string[]]$CaseKeys=@(),
    [ValidateRange(0,100)][int]$GuardStrength=30,
    [ValidateSet('critical','high','medium','low')][string]$SeverityThreshold='high',
    [ValidateRange(1,500)][int]$MaxCases=200,
    [ValidateRange(1,900)][int]$TimeoutSeconds=660,
    [switch]$AllowSimulation,
    [string]$OutputDirectory=(Join-Path $PSScriptRoot '..\artifacts\redteam')
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$taskId=$CampaignId
$submitted=$false
$timer=[Diagnostics.Stopwatch]::StartNew()
try {
    if ($BaseUrl.Scheme -notin @('http','https') -or $BaseUrl.UserInfo -or $BaseUrl.Query -or $BaseUrl.Fragment) {
        throw 'BaseUrl must be an HTTP(S) service root without embedded credentials, query or fragment.'
    }
    if ([string]::IsNullOrWhiteSpace($env:AGF_CI_API_KEY)) { throw 'Set AGF_CI_API_KEY through the CI secret store.' }
    $apiRoot=$BaseUrl.AbsoluteUri.TrimEnd('/')+'/api/v1/redteam/campaigns'
    $headers=@{'X-AGF-Key'=$env:AGF_CI_API_KEY;'X-AGF-Tenant'=$TenantId.ToString()}
    function Invoke-CampaignApi([string]$Method,[string]$Uri,$Payload=$null) {
        $remaining=$TimeoutSeconds-[int][Math]::Ceiling($timer.Elapsed.TotalSeconds)
        if ($remaining -le 0) { throw 'Campaign wait timed out.' }
        $request=@{Method=$Method;Uri=$Uri;Headers=$headers;TimeoutSec=[Math]::Min(30,$remaining)}
        if ($null -ne $Payload) {
            $request.ContentType='application/json; charset=utf-8'
            $request.Body=[Text.Encoding]::UTF8.GetBytes(($Payload|ConvertTo-Json -Depth 20 -Compress))
        }
        Invoke-RestMethod @request
    }
    if ($CampaignId -eq [guid]::Empty) {
        if ($AgentTargetId -ne [guid]::Empty -and $McpTargetId -ne [guid]::Empty) {
            throw 'Choose one target type per campaign.'
        }
        if ($AgentTargetId -ne [guid]::Empty) {
            if ($CaseKeys.Count -lt 1 -or $CaseKeys.Count -gt 20) { throw 'Agent HTTP runs require 1–20 explicit compatible case keys.' }
            $profile=Invoke-CampaignApi 'GET' ($BaseUrl.AbsoluteUri.TrimEnd('/')+'/api/v1/redteam/agent-targets/'+$AgentTargetId)
            if (-not $profile.enabled -or [int]$profile.version -lt 1) { throw 'Agent target is disabled or has no valid version.' }
            $payload=@{name=$Name;case_keys=$CaseKeys;execution_mode='agent-http';
                target_profile_id=$AgentTargetId.ToString();target_profile_version=[int]$profile.version;
                severity_threshold=$SeverityThreshold;ci_gate=$true;max_cases=$CaseKeys.Count}
        } elseif ($McpTargetId -ne [guid]::Empty) {
            if ($CaseKeys.Count -ne 1 -or $CaseKeys[0] -ne 'RT-MCP-001') {
                throw 'MCP HTTP currently supports only RT-MCP-001.'
            }
            $profile=Invoke-CampaignApi 'GET' ($BaseUrl.AbsoluteUri.TrimEnd('/')+'/api/v1/redteam/mcp-targets/'+$McpTargetId)
            if (-not $profile.enabled -or [int]$profile.version -lt 1) { throw 'MCP target is disabled or has no valid version.' }
            $payload=@{name=$Name;case_keys=$CaseKeys;execution_mode='mcp-http';
                target_profile_id=$McpTargetId.ToString();target_profile_version=[int]$profile.version;
                severity_threshold=$SeverityThreshold;ci_gate=$true;max_cases=1}
        } else {
            if (-not $AllowSimulation) { throw 'Choose -AgentTargetId, -McpTargetId, or explicitly pass -AllowSimulation.' }
            $payload=@{name=$Name;case_keys=$CaseKeys;execution_mode='simulator';guard_strength=$GuardStrength;
                severity_threshold=$SeverityThreshold;ci_gate=$true;max_cases=$MaxCases}
        }
        $accepted=Invoke-CampaignApi 'POST' $apiRoot $payload
        $taskId=[guid]$accepted.task_id
        if ($taskId -eq [guid]::Empty) { throw 'Server did not return a task ID.' }
        $submitted=$true
        Write-Output ('Accepted campaign '+$taskId)
    }
    do {
        $detail=Invoke-CampaignApi 'GET' ($apiRoot+'/'+$taskId)
        $campaign=$detail.campaign
        if ($campaign.state -in @('completed','failed','cancelled')) { break }
        if ($campaign.state -notin @('queued','running')) { throw 'Unknown campaign state.' }
        if ($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw 'Campaign wait timed out.' }
        Start-Sleep -Milliseconds 500
    } while ($true)
    if ($campaign.state -ne 'completed') { throw ('Campaign ended as '+$campaign.state+'.') }
    if ([int]$campaign.executed_cases -le 0 -or $campaign.executed_cases -ne $campaign.total_cases) { throw 'Campaign did not execute its complete case selection.' }
    if ($campaign.execution_mode -eq 'simulator') {
        if (-not $AllowSimulation) { throw 'Simulator results require -AllowSimulation; no production gate verdict is inferred.' }
        Write-Output 'SIMULATED: no actual asset protection has been assessed.'
    } elseif ($campaign.execution_mode -notin @('agent-http','mcp-http')) { throw 'Execution provenance is unknown.' }
    if ($campaign.ci_gate -isnot [bool] -or -not $campaign.ci_gate) { throw 'CI gating was not enabled for this campaign.' }
    $result=Invoke-CampaignApi 'GET' ($apiRoot+'/'+$taskId+'/report')
    if ($null -eq $result.report -or $result.ci_passed -isnot [bool] -or [string]::IsNullOrWhiteSpace($result.markdown)) { throw 'A valid saved CI report is required.' }
    if ([guid]$result.report.campaign_id -ne $taskId -or $result.report.executed -ne $campaign.executed_cases) { throw 'Report does not match the campaign.' }
    $evidence=Invoke-CampaignApi 'GET' ($apiRoot+'/'+$taskId+'/evidence')
    $outputRoot=[IO.Path]::GetFullPath($OutputDirectory)
    $runDirectory=Join-Path $outputRoot $taskId.ToString()
    [void](New-Item -ItemType Directory -Path $runDirectory -Force)
    $utf8=New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText((Join-Path $runDirectory 'report.md'),$result.markdown,$utf8)
    [IO.File]::WriteAllText((Join-Path $runDirectory 'evidence.json'),($evidence|ConvertTo-Json -Depth 80),$utf8)
    Write-Output ('Evidence: '+$runDirectory)
    if ($null -eq $campaign.evaluated_cases -or $campaign.evaluated_cases -ne $campaign.total_cases) {
        throw 'Evaluation coverage is incomplete or unknown; evidence was saved, but this run cannot pass CI.'
    }
    if (-not $result.ci_passed) { Write-Output 'CI gate failed.'; exit 1 }
    Write-Output 'CI gate passed.'
    exit 0
} catch {
    # Never dump request headers or tokens into a CI log.
    Write-Error -ErrorAction Continue ('Red-team CI check failed: '+$_.Exception.Message)
    if ($submitted -and $timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
        try { [void](Invoke-RestMethod -Method Post -Uri ($apiRoot+'/'+$taskId+'/cancel') -Headers $headers -ContentType 'application/json' -Body '{}' -TimeoutSec 10) } catch { Write-Warning 'Automatic cancellation could not be confirmed; inspect the task ID.' }
    }
    exit 2
}
