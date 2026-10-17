# parsers/ 厂商日志解析模板库统计（模板总数 / 厂商分布 / 引擎分布 / 样本覆盖）
# 用法：powershell -NoProfile -File scripts\parsers-stats.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$parsers = Join-Path $root 'parsers'

$yaml = Get-ChildItem -Path $parsers -Recurse -File | Where-Object { $_.Extension -in '.yaml', '.yml' } | Sort-Object FullName
$samples = @{}
$fixtures = @{}
Get-ChildItem -Path $parsers -Recurse -File -Filter samples.json | ForEach-Object {
    $json = [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
    foreach ($p in $json.samples.PSObject.Properties) {
        $samples[$p.Name] = $p.Value
        if ($null -ne $p.Value.fixture) { $fixtures[$p.Name] = $p.Value.fixture }
    }
}

'=== parsers/ 模板库统计 ==='
'模板总数（YAML）        : ' + $yaml.Count
'厂商目录数              : ' + (Get-ChildItem -Path $parsers -Directory).Count
''
'按厂商目录分布：'
$yaml | Group-Object { Split-Path (Split-Path $_.FullName -Parent) -Leaf } | Sort-Object Name | ForEach-Object {
    '  {0,-12} {1,3}' -f $_.Name, $_.Count
}
''
'按 vendor 字段分布：'
$vendors = @{}
foreach ($f in $yaml) {
    $t = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
    $v = [regex]::Match($t, '(?m)^vendor:\s*(.+?)\s*$').Groups[1].Value
    if ($v) { $vendors[$v] = 1 + $vendors[$v] }
}
$vendors.GetEnumerator() | Sort-Object Name | ForEach-Object { '  {0,-18} {1,3}' -f $_.Key, $_.Value }
''
'按引擎分布：'
$engines = @{}
foreach ($f in $yaml) {
    $t = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
    $e = [regex]::Match($t, '(?m)^engine:\s*(\S+)\s*$').Groups[1].Value
    $engines[$e] = 1 + $engines[$e]
}
$engines.GetEnumerator() | Sort-Object Name | ForEach-Object { '  {0,-12} {1,3}' -f $_.Key, $_.Value }
''
'样本覆盖：'
'  样本条目（模板 key）     : ' + $samples.Count
'  行内正样本（line）       : ' + ($samples.Values | Where-Object { $null -ne $_.line }).Count
'  独立样本文件（fixture）  : ' + $fixtures.Count
'  独立样本文件落盘         : ' + (Get-ChildItem -Path (Join-Path $root 'tests\fixtures\logs\parsers') -File -Filter *.log).Count
'  未验证（untested_reason）: ' + ($samples.Values | Where-Object { $null -ne $_.untested_reason }).Count
$manifest = [System.IO.File]::ReadAllText((Join-Path $root 'tests\fixtures\logs\manifest.json'), [System.Text.Encoding]::UTF8) | ConvertFrom-Json
$libVendors = $manifest.parser_library.samples.PSObject.Properties | ForEach-Object { $_.Value.vendor } | Sort-Object -Unique
'  独立样本覆盖厂商数       : ' + $libVendors.Count + '  [' + ($libVendors -join ', ') + ']'
''
'每个模板的正样本关键字段断言位于 parsers/<vendor>/samples.json；校验入口：cargo test -p agf-ingest --test parsers_library'