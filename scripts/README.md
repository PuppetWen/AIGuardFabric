# AIGuardFabric 脚本索引（`scripts/`）

所有脚本面向 **Windows PowerShell 5.1**（本机无 `pwsh`）。脚本文件必须保存为
**UTF-8 with BOM**，否则 PS 5.1 会按 GBK 解码中文并报语法错误。
所有脚本 dot-source `lib.ps1`（统一路径解析、文件 IO、确定性伪随机、控制台输出），
路径一律从 `$AgfRoot` 推导，**不硬编码绝对路径**（铁律 4）。

## 环境与自检

| 脚本 | 用途 | 常用参数 | 依赖 | 预期输出 |
|---|---|---|---|---|
| `env.ps1` | 环境初始化（dot-source）：`$AgfRoot`、读 `.env`、把 `CARGO_TARGET_DIR`/`CARGO_INSTALL_ROOT`/npm 缓存重定向到项目内 | `$env:AGF_ENV_QUIET='1'` 静默 | 无 | 打印生效的路径与工具版本 |
| `lib.ps1` | 公共库（被其它脚本 dot-source） | — | 无 | — |
| `selfcheck.ps1` | 零外部依赖自检：项目根、工具版本、数据卷占用、端口占用、Docker、配置强度、路径纪律 | `-Json`、`-WriteBaseline` | 无（Docker 可选） | `N 项通过 / M 项警告 / 0 项阻断` |
| `init-env.ps1` | 由 `.env.example` 生成 `.env`（随机强口令与密钥）、建 `data/` 子目录 | `-Force` | 无 | `.env` + 目录树 |
| `gate.ps1` | **全部门禁**：fmt → clippy → test → rules → deny → (coverage) → web → compose → selfcheck | `-Only fmt,clippy`、`-Skip web`、`-Coverage` | cargo/deny/llvm-cov/docker/pnpm（缺项报 SKIP） | 总结表 + 退出码 |
| `coverage.ps1` | 覆盖率门禁（≥70%），报告落 `target/coverage/` | `-Threshold 70`、`-Open` | `tools\bin\cargo-llvm-cov.exe` | 行覆盖率 + `html/index.html` |

## 开发与演示

| 脚本 | 用途 | 常用参数 | 依赖 | 预期输出 |
|---|---|---|---|---|
| `dev-up.ps1` | 起本地依赖（postgres/redis/nats/minio），可选后台起后端与前端 | `-DepsOnly`、`-WithApps`、`-NoWait`、`-Down` | Docker | 依赖 healthy；日志落 `data\logs\` |
| `seed.ps1` | 灌演示数据（资产/规则/告警/案件/红队结果） | `-ApiBase`、`-WhatIf` | 后端可选 | 各资源计数 |
| `demo.ps1` | 单机全链路演示：资产发现→风险检出→告警→案件→策略下发→拦截生效 | `-WhatIf` | Docker + 后端 | 每步"预期/实测" |
| `gen-fixtures.ps1` | 生成合成夹具（幂等、固定种子） | `-Force` | 无 | `tests/fixtures/**` + `SOURCES.md` |
| `fetch-fixtures.ps1` | 抓取公开样本（默认干跑） | `-Execute` | 外网 | `tests/fixtures/downloaded/**` + 来源记录 |

## 运维

| 脚本 | 用途 | 常用参数 | 依赖 | 预期输出 |
|---|---|---|---|---|
| `backup.ps1` | PostgreSQL 逻辑备份 + 数据目录 + sha256 清单 | `-Keep 10`、`-SkipData`、`-WhatIf` | Docker + postgres 运行中 | `data\backup\<时间戳>\{agf.dump,data-files.zip,MANIFEST.txt}` |
| `restore.ps1` | 从备份目录恢复数据库（可选数据目录） | `-BackupFile <目录>`、`-WithData`、`-Force`、`-NoPreBackup`、`-WhatIf` | Docker + postgres 运行中 | 校验 MANIFEST → 自动预备份 → `pg_restore` |

## Justfile 对应关系

```
just selfcheck  -> scripts\selfcheck.ps1
just init       -> scripts\init-env.ps1
just up-deps    -> scripts\dev-up.ps1 -DepsOnly
just seed       -> scripts\seed.ps1
just demo       -> scripts\demo.ps1
just coverage   -> scripts\coverage.ps1
just backup     -> scripts\backup.ps1
just restore    -> scripts\restore.ps1 -BackupFile <路径>
just gate       -> scripts\gate.ps1
```

## 约定

1. **绝不静默跳过**：做不到的事打印 `[SKIP]` 并说明原因与所需条件，或直接 `[FAIL]` 退出非零。
2. **破坏性操作**必须支持 `-WhatIf` 或交互确认（`restore.ps1` 两者都有）。
3. 需要联网/凭据/设备的动作，先登记 `docs/pending-verification.md`，再继续做不依赖它的部分。
4. 依赖工具一律装在项目内（`tools/bin`，由 `CARGO_INSTALL_ROOT` 控制），不污染 `D:\Environment`。
