# `.github/workflows` —— CI/CD 流水线说明

> AIGuardFabric（智御矩阵）的**全部** CI/CD 定义都在本目录。
> 本文件回答三件事：**什么时候跑**、**需要什么 secrets/variables**、**离线时会发生什么**。
>
> 配套文件：
> - `ci.yml` —— 合入门禁（8 个 job）
> - `release.yml` —— tag 发布（镜像 + SBOM + 气隙包）
> - `redteam-nightly.yml` —— 红队用例库夜间回归
> - 阻塞项总账：`docs/pending-verification.deploy.md`

---

## 0. 两个必须理解的前提

### 0.1 `AGF_OFFLINE` 开关（离线自托管 runner）

三种 workflow 的**每个 job** 都显式声明：

```yaml
env:
  AGF_OFFLINE: ${{ vars.AGF_OFFLINE || '0' }}
```

| 取值 | 含义 |
|---|---|
| `0`（默认） | 常规联网 runner：会下载 Rust 工具链、装 pnpm/node、装 cargo 子命令、用 `actions/cache`、推镜像、传 artifact |
| `1` | **离线/气隙自托管 runner**：跳过一切需要外网的步骤 |

**设置方式**：仓库 `Settings → Secrets and variables → Actions → Variables` 新增变量 `AGF_OFFLINE = 1`。

**`AGF_OFFLINE=1` 时被跳过的步骤**（全部用 `if: env.AGF_OFFLINE != '1'` 守卫）：

| 被跳过的动作 | 离线 runner 需要预先具备什么 |
|---|---|
| `dtolnay/rust-toolchain@stable` | 预装 Rust 工具链（含 `rustfmt`、`clippy`、`llvm-tools-preview` 组件） |
| `actions/cache@v4` / `actions/upload-artifact@v4` | 无需（缓存与产物上传被跳过，上传步骤另设 `continue-on-error: true`） |
| `pnpm/action-setup` / `actions/setup-node` / `pnpm install` | 预置 node 24 + pnpm 11，且 `apps/web/node_modules` 已就绪 |
| `cargo install --root tools ...` | 预置 `tools/bin/cargo-deny`、`tools/bin/cargo-llvm-cov` |
| `actions/setup-python` / `pip install PyYAML` | 预置 Python 3.12 + PyYAML |
| `docker/build-push-action`、镜像推送、`anchore/sbom-action` | 无需（发布类步骤整体跳过） |
| `softprops/action-gh-release` | 无需（Release 创建被跳过） |

> **`AGF_OFFLINE` 只跳过"需要外网"的动作，绝不跳过任何检查本身。**
> 离线 runner 上 `fmt` / `clippy` / `test` / `deny` / `coverage` / 前端四项 / `compose` 校验 /
> 规则回归 / 红队回归**全部照常执行**——离线不等于豁免门禁。
> 若离线 runner 缺少预置工具（如没有 `tools/bin/cargo-deny`），job 会**显式报错退出**，
> 而不是静默变绿。

### 0.2 缓存策略

联网 runner 用 `actions/cache@v4` 缓存 `target/` 与项目内 `CARGO_HOME`
（`.cargo/registry`、`.cargo/git`）—— 与 §0 铁律 2「缓存也重定向进项目内」一致。
每个 job 用独立 key 前缀（`clippy` / `test` / `coverage` / `rules` / `redteam`），
避免不同 job 互相踢缓存。

---

## 1. `ci.yml` —— 合入门禁

**触发**：`push` 到 `main` / `master` / `develop`；任意 `pull_request`；`workflow_dispatch`。
**并发**：同一 ref 的新提交取消旧运行（`cancel-in-progress: true`）。
**权限**：`contents: read`。

| job | 命令 | 对应验收 |
|---|---|---|
| `fmt` | `cargo fmt --all --check` | §6 门禁 |
| `clippy` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | §6 门禁（警告即失败） |
| `test` | `cargo test --workspace` | §6 门禁 |
| `deny` | `cargo deny check` | §11.8 |
| `coverage` | `cargo-llvm-cov` 采集 lcov + `report --fail-under-lines 70` | §11.8（覆盖率 ≥70%） |
| `web` | `pnpm --dir apps/web install --frozen-lockfile` → `lint` → `typecheck` → `test` → `build` | §2.1 前端 |
| `compose` | `docker compose -f <3 个 compose 文件> config --quiet` | §9 部署 |
| `rules` | `cargo test -p agf-scan --test rules_library` | §11.7（规则库 + 正负样本全绿） |

**覆盖率产物**：落 `target/coverage/`（`lcov.info`、`summary.json`、`html/`），
阈值 70% 由 `cargo-llvm-cov report --fail-under-lines 70` 强制（低于阈值即非零退出）。
`summary.json` 的行覆盖百分比会写入 job summary。

**`compose` job 的占位环境变量**：`docker-compose.yml` 里 5 处 `${VAR:?}` 是**强制项**
（`AGF_PG_PASSWORD` / `AGF_S3_SECRET_KEY` / `AGF_JWT_SECRET` / `AGF_MASTER_KEY_BASE64` /
`AGF_GRAFANA_ADMIN_PASSWORD`），不填会让 `config` 直接失败。因此该 job 用
**仅用于校验的占位值**（`ci-config-check-only`）在内存中展开，**不落盘、不是真实凭据**。
本地等价的验证命令见 §4。

**需要的 secrets/variables**：

| 名称 | 类型 | 必需 | 用途 |
|---|---|---|---|
| `AGF_OFFLINE` | variable | 否（默认 `0`） | 离线开关 |

> `ci.yml` **不需要任何 secret**。`GITHUB_TOKEN` 由 Actions 自动提供（本 workflow 只读）。

---

## 2. `release.yml` —— tag 发布

**触发**：`push` tag 匹配 `v[0-9]+.[0-9]+.[0-9]+`（含 `-rc.1` 这类后缀）；
或 `workflow_dispatch`（可传 `tag`、`push_images`）。
**权限**：`contents: write`（建 Release）、`packages: write`（推 GHCR）。

| job | 做什么 |
|---|---|
| `preflight` | 解析版本号，打印 `Cargo.toml` / `apps/web/package.json` / `Chart.yaml` 的版本供人工核对 |
| `build-and-push` | 矩阵 `server` / `ingest` / `scheduler` / `web`，复用 `deploy/docker/Dockerfile` 的 `target`，Buildx + GHA 层缓存 |
| `sbom` | `syft` 生成 SPDX-JSON（**best-effort**） |
| `airgap-bundle` | 气隙离线包导出（**当前跳过**，见下） |
| `github-release` | 汇总镜像清单 + 已知缺口，创建 Release |

**镜像命名**：`${AGF_REGISTRY}/${AGF_IMAGE_NAMESPACE}/agf-<target>:<version>`
（默认 `ghcr.io/<repo_owner>/agf-server:0.1.0`）。
两者都可用仓库 variable 覆盖为内网 Harbor，例如
`AGF_REGISTRY=harbor.corp.local`、`AGF_IMAGE_NAMESPACE=ai-security`。

**SBOM**：`syft` 缺失时**只告警不失败**（`::warning::` + 跳过生成）。SBOM 是增强项，
不是发布硬门禁——离线 runner 通常没有 syft。若需要 SBOM，联网跑一次
`anchore/sbom-action/download-syft@v0` 或把 syft 预置进 runner PATH 即可自动启用。

**气隙离线包 —— 已核对为"尚不存在"，故只探测不伪造**：

- `crates/agf-cli/src/main.rs` 全文 4 行（函数体只有 `println!("agfctl 脚手架：实现见 docs/roadmap.md")`），
  `crates/agf-cli/src/lib.rs` 5 行；
- 全仓库 `grep bundle *.rs` **零命中** → **`agfctl bundle` 子命令不存在**；
- 因此 `airgap-bundle` job 只做 `agfctl bundle --help` **探测**：不可用就 `::warning::` 跳过，
  绝不产出假产物。workflow 内以 `TODO(release-bundle)` 标注了实现位与目标命令形态。
- 阻塞登记：`docs/pending-verification.deploy.md` → **PV-DEPLOY-004**。

**需要的 secrets/variables**：

| 名称 | 类型 | 必需 | 用途 |
|---|---|---|---|
| `GITHUB_TOKEN` | 内置 secret | 是 | 推 GHCR + 建 Release（workflow 已声明 `packages: write`） |
| `AGF_REGISTRY` | variable | 否（默认 `ghcr.io`） | 容器仓库地址 |
| `AGF_IMAGE_NAMESPACE` | variable | 否（默认 `github.repository_owner`） | 仓库命名空间 |
| `AGF_OFFLINE` | variable | 否（默认 `0`） | 离线开关 |

> 若改用非 GHCR 的内网仓库，`docker/login-action` 当前用 `GITHUB_TOKEN`，
> 需替换为对应仓库的凭据 secret（例如 `HARBOR_USERNAME` / `HARBOR_PASSWORD`）。

**离线行为**：`AGF_OFFLINE=1` 时所有 job 跳过构建/推送/SBOM/Release。
发布流水线在离线环境**无法完整执行**（推镜像本身就要外网仓库）；
气隙场景应走「离线导出 → 人工搬运 → 内网 registry 导入」，该路径目前阻塞（PV-DEPLOY-004）。

---

## 3. `redteam-nightly.yml` —— 红队用例库夜间回归

**触发**：`schedule` 每日 `17 2 * * *`（02:17 UTC = 10:17 北京时间）；
`workflow_dispatch`（可传 `structure_only`）；
以及 `push` 到 `main`/`master` 且改动涉及 `redteam/**`、`crates/agf-scan/**`、`rules/**`。

| job | 命令 | 说明 |
|---|---|---|
| `redteam-regression` | `cargo test -p agf-scan` + `cargo test -p agf-scan --test rules_library` | **真实命令**（已核对 crate 内 `src/redteam.rs` 含成批 `#[test]`/`#[tokio::test]`） |
| `catalog-structure` | PyYAML 结构校验 `redteam/**/*.yaml` | **过渡性替代**，见下 |
| `summary` | 汇总结论，任一失败即非零退出 | 供通知/看板消费 |

**已核对的缺口（`TODO(nightly-redteam-catalog)`）**：
仓库**没有**"把 `redteam/**/*.yaml` 用例库当数据加载并回归"的测试目标——
`crates/agf-scan/tests/` 下仅有 `rules_library.rs`，全仓库 `grep redteam/`、`RT-CT` 在 `*.rs` 下零命中。
所以本流水线**不会**调用 `cargo test -p agf-scan --test redteam_catalog`（那是不存在的假命令）。
过渡保障是 PyYAML 的**结构级**校验：220 个用例文件全部可解析、`key` 唯一、
`title`/`category` 齐全。它只证明用例库"没坏"，**不证明"能打中"**。
阻塞登记：`docs/pending-verification.deploy.md` → **PV-DEPLOY-005**。

**需要的 secrets/variables**：

| 名称 | 类型 | 必需 | 用途 |
|---|---|---|---|
| `AGF_OFFLINE` | variable | 否（默认 `0`） | 离线开关 |

> 本流水线默认**不拉取外网用例**（用例库随仓库分发），因此离线 runner 上
> 除工具链/缓存/PyYAML 安装外的全部回归检查都会真实执行。

---

## 4. 本地等价验证命令（无网络也能跑）

CI 不是唯一入口——下列命令在开发机上可直接复现每个 job 的核心检查：

```powershell
# fmt / clippy / test
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace

# 规则库回归
cargo test -p agf-scan --test rules_library

# 红队回归（注意：无独立用例库测试目标，见 §3）
cargo test -p agf-scan

# compose 校验（5 个强制环境变量用占位值，仅内存展开）
$env:AGF_PG_PASSWORD='ci-config-check-only'
$env:AGF_S3_SECRET_KEY='ci-config-check-only'
$env:AGF_JWT_SECRET='ci-config-check-only-placeholder-value-32b'
$env:AGF_MASTER_KEY_BASE64='Y2ktY29uZmlnLWNoZWNrLW9ubHktMzJieXRlcyE='
$env:AGF_GRAFANA_ADMIN_PASSWORD='ci-config-check-only'
docker compose -f docker-compose.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.dev.yml config --quiet
docker compose -f docker-compose.prod.yml config --quiet

# 前端四项
pnpm --dir apps/web install --frozen-lockfile
pnpm --dir apps/web run lint
pnpm --dir apps/web run typecheck
pnpm --dir apps/web run test
pnpm --dir apps/web run build
```

---

## 5. 相关阻塞项速查

| 编号 | 阻塞内容 | 影响 |
|---|---|---|
| PV-DEPLOY-001 | 未在本机执行 `helm lint` / `helm template`（`helm` 不在本机 PATH） | Helm Chart 仅通过结构校验 |
| PV-DEPLOY-002 | 指标名与实现对齐（代码尚未注册 `/metrics`） | Grafana/Prometheus 配置使用**约定占位指标名** |
| PV-DEPLOY-003 | 未在真实 K8s 集群 `helm install` | 渲染结果未在集群侧验证 |
| PV-DEPLOY-004 | 镜像未构建推送；`agfctl bundle` 不存在 | 发布流水线无法产出气隙离线包 |
| PV-DEPLOY-005 | 红队用例库无能力级回归测试目标 | 夜间回归仅到结构级 |

完整表格见 `docs/pending-verification.deploy.md`。
