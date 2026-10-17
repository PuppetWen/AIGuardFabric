# 自检分段 4：关键配置项强度（JWT 密钥 / 主密钥 / 数据库口令 / Mock 开关）。

# ---------------------------------------------------------------------------
# 6. 配置强度
# ---------------------------------------------------------------------------
if (-not $Json) { Write-Host ''; Write-Host '--- 6. 配置强度 ---' -ForegroundColor DarkCyan }

$jwt = Get-AgfEnv -Name 'AGF_JWT_SECRET' -Default ''
if ($jwt.Length -ge 32 -and $jwt -notmatch 'CHANGE_ME') {
    Add-Check -Name 'JWT 密钥' -Status ok -Detail "$($jwt.Length) 字符"
}
else {
    Add-Check -Name 'JWT 密钥' -Status warn -Detail "长度 $($jwt.Length)（<32 或为占位值；生产将拒绝启动）"
}

$mk = Get-AgfEnv -Name 'AGF_MASTER_KEY_BASE64' -Default ''
if ($mk -match 'CHANGE_ME' -or [string]::IsNullOrEmpty($mk)) {
    Add-Check -Name '主密钥' -Status warn -Detail '未配置真实值（运行 agfctl genkey 生成）'
}
else {
    try {
        $bytes = [Convert]::FromBase64String($mk)
        if ($bytes.Length -eq 32) {
            Add-Check -Name '主密钥' -Status ok -Detail '32 字节（AES-256）'
        }
        else {
            Add-Check -Name '主密钥' -Status fail -Detail "解码后 $($bytes.Length) 字节，应为 32"
        }
    }
    catch {
        Add-Check -Name '主密钥' -Status fail -Detail '非法 base64'
    }
}

$pgPass = Get-AgfEnv -Name 'AGF_PG_PASSWORD' -Default ''
if ($pgPass.Length -ge 12 -and $pgPass -notmatch 'CHANGE_ME') {
    Add-Check -Name '数据库口令' -Status ok -Detail "$($pgPass.Length) 字符"
}
else {
    Add-Check -Name '数据库口令' -Status warn -Detail '弱口令或占位值（生产将拒绝启动）'
}

$mock = Get-AgfEnv -Name 'AGF_MOCK_MODE' -Default '1'
Add-Check -Name 'Mock 模式' -Status info -Detail $(if ($mock -eq '1') { '开启（离线可演示；外部适配器返回 fixtures 数据）' } else { '关闭（将尝试真实外部调用）' })
