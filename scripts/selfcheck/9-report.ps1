# 自检分段 9：汇总输出与退出码（0 = 通过 / 1 = 存在阻断项）。

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------
$fails = @($script:Checks | Where-Object { $_.status -eq 'fail' })
$warns = @($script:Checks | Where-Object { $_.status -eq 'warn' })

if ($Json) {
    $payload = [pscustomobject]@{
        generatedAt = (Get-Date).ToString('o')
        projectRoot = $AgfRoot
        envRoot     = $AgfEnvRoot
        checks      = $script:Checks
        failCount   = $fails.Count
        warnCount   = $warns.Count
        verdict     = if ($fails.Count -eq 0) { 'pass' } else { 'fail' }
    }
    $payload | ConvertTo-Json -Depth 6
}
else {
    Write-Host ''
    Write-AgfBanner ("自检结果: {0} 项通过 / {1} 项警告 / {2} 项阻断" -f (@($script:Checks | Where-Object { $_.status -eq 'ok' }).Count), $warns.Count, $fails.Count)
    if ($warns.Count -gt 0) {
        Write-Host '警告项（不阻塞离线开发，需要时登记到 docs/pending-verification.md）：' -ForegroundColor Yellow
        foreach ($w in $warns) { Write-Host ("  - {0}: {1}" -f $w.name, $w.detail) -ForegroundColor Yellow }
    }
    if ($fails.Count -gt 0) {
        Write-Host '阻断项：' -ForegroundColor Red
        foreach ($f in $fails) { Write-Host ("  - {0}: {1}" -f $f.name, $f.detail) -ForegroundColor Red }
    }
    else {
        Write-Host '无阻断项：路径纪律与缓存重定向生效，未触碰 D:\Environment。' -ForegroundColor Green
    }
}

if ($fails.Count -gt 0) { exit 1 }
exit 0
