# Justfile —— AIGuardFabric 常用任务（Windows 优先；所有命令都从项目内注入路径）
#
# 依赖 just ≥ 1.0（可选）。无 just 时直接用 scripts/*.ps1。
# 不硬编码除「项目根」以外的绝对路径（铁律 4）。

set shell := ["powershell.exe", "-NoProfile", "-Command"]
set windows-shell := ["powershell.exe", "-NoProfile", "-Command"]

project_root := justfile_directory()

# 列出所有任务
default:
    @just --list

# 打印环境摘要（路径纪律自检）
env:
    . "{{project_root}}\scripts\env.ps1"

# 零外部依赖自检：项目根 / 工具版本 / 数据卷 / 端口 / Docker / 配置强度
selfcheck:
    & "{{project_root}}\scripts\selfcheck.ps1"

selfcheck-json:
    & "{{project_root}}\scripts\selfcheck.ps1" -Json

# 生成 .env（首次部署；随机生成强口令与密钥）
init:
    & "{{project_root}}\scripts\init-env.ps1"

# ---------------------------------------------------------------------------
# 依赖服务
# ---------------------------------------------------------------------------

# 只启动依赖（postgres/redis/nats/minio）
up-deps:
    & "{{project_root}}\scripts\dev-up.ps1" -DepsOnly

# 全栈启动（docker compose up -d）
up:
    docker compose -f "{{project_root}}\docker-compose.yml" up -d --build

up-observability:
    docker compose -f "{{project_root}}\docker-compose.yml" --profile clickhouse --profile grafana up -d

down:
    docker compose -f "{{project_root}}\docker-compose.yml" down

# 彻底清理（含数据卷，谨慎）
clean-volumes:
    docker compose -f "{{project_root}}\docker-compose.yml" down -v

logs:
    docker compose -f "{{project_root}}\docker-compose.yml" logs -f --tail=200

ps:
    docker compose -f "{{project_root}}\docker-compose.yml" ps

# 校验 compose 配置（含 profile 与变量插值）
compose-check:
    docker compose -f "{{project_root}}\docker-compose.yml" config --quiet
    @echo "compose 配置校验通过"

# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------

check:
    cargo check --workspace --all-targets

build:
    cargo build --workspace

build-release:
    cargo build --release --workspace

test:
    cargo test --workspace --all-targets

# 单元/集成测试（nextest，未安装时回退 cargo test）
nextest:
    cargo nextest run --workspace --no-fail-fast

lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

# 覆盖率（>=70%，报告落 target/coverage/）
coverage:
    & "{{project_root}}\scripts\coverage.ps1"

# 依赖安全检查
audit:
    cargo deny check
    cargo audit

# 加载并校验规则包（全量正负样本必须全绿）
rules-verify:
    cargo run -p agf-cli -- rules verify --dir "{{project_root}}\rules"

# 红队用例库自检（数量/字段完整性）
redteam-verify:
    cargo run -p agf-cli -- redteam verify --dir "{{project_root}}\redteam"

# ---------------------------------------------------------------------------
# 前端
# ---------------------------------------------------------------------------

web-install:
    cd "{{project_root}}\apps\web"; pnpm install

web-dev:
    cd "{{project_root}}\apps\web"; pnpm dev

web-build:
    cd "{{project_root}}\apps\web"; pnpm build

web-lint:
    cd "{{project_root}}\apps\web"; pnpm lint

web-test:
    cd "{{project_root}}\apps\web"; pnpm test

# ---------------------------------------------------------------------------
# 数据与夹具
# ---------------------------------------------------------------------------

# 从公开来源抓取真实样本（需要外网；抓不到则转合成数据）
fetch-fixtures:
    & "{{project_root}}\scripts\fetch-fixtures.ps1"

# 生成合成夹具（离线）
gen-fixtures:
    & "{{project_root}}\scripts\gen-fixtures.ps1"

# 灌入演示数据（资产/规则/告警/案件/红队结果）
seed:
    & "{{project_root}}\scripts\seed.ps1"

# 端到端演示：资产发现 → 风险检出 → 告警 → 案件 → 策略下发 → 拦截生效
demo:
    & "{{project_root}}\scripts\demo.ps1"

# ---------------------------------------------------------------------------
# 运维
# ---------------------------------------------------------------------------

backup:
    & "{{project_root}}\scripts\backup.ps1"

restore db="":
    & "{{project_root}}\scripts\restore.ps1" -BackupFile "{{db}}"

# 全部质量门禁（fmt → clippy → test → deny → coverage → 规则/用例校验）
gate:
    & "{{project_root}}\scripts\gate.ps1"
