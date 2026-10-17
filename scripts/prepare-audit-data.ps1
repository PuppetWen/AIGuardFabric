#Requires -Version 5.1
<#
.SYNOPSIS
    首次部署前初始化项目持久审计见证目录；已有目录只验证，不接管。
.DESCRIPTION
    不生成签名、检查点或见证JSON。Linux容器使用10001:10001，运维方需先设置
    数据目录ACL/所有者；本入口只设置Unix0700/0600或继承Windows受控ACL。
#>
param([switch]$WhatIf)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib.ps1"
. "$PSScriptRoot\audit-witness-backup.ps1"
$root = $global:AgfRoot
$dataRoot = Get-AgfAuditDataRoot $root $env:AGF_DATA_DIR
$snapshot = Get-AgfWitnessSnapshot $root $dataRoot
if ($WhatIf) {
    Write-AgfInfo ('见证目录：{0}；状态：{1}；未修改文件。' -f $snapshot.Root, $snapshot.State)
    exit 0
}
Initialize-AgfAuditWitnessDirectory $root $dataRoot
$snapshot = Get-AgfWitnessSnapshot $root $dataRoot
Write-AgfOk ('见证目录归属已验证：{0}；没有创建签名检查点。' -f $snapshot.Root)
Write-AgfInfo '部署前确认此精确目录可由容器10001:10001读写，并排除编译/测试清理。'
exit 0