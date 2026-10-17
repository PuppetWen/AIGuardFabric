# AIGuardFabric 路线图与里程碑

> 本文件是开发进度的**唯一事实来源**。每个里程碑完成后更新本表与「交付记录」小节。
> 交付格式遵循提示词 §10：① 变更文件清单；② 本地无外网可执行的验证命令 + 预期输出；
> ③ 新增进 `pending-verification.md` 的阻塞项；④ 需要用户提供或授权的事项。
> 下表含早期里程碑证据；当前阶段一缺口及最新门禁以 [剩余工作清单](remaining-work-2026-09-22.md) 和 [需求核对记录](requirements-audit-2026-09-20.md) 为准。

## 里程碑总览

| 里程碑 | 目标 | 验收锚点 | 状态 |
|---|---|---|---|
| **M1** | 骨架：workspace + 全 crate + compose 起得来 + 健康检查 + CI + selfcheck | `docker compose config` 通过；`cargo check --workspace` 通过；`scripts/selfcheck.ps1` 0 阻断 | 🟢 已完成（compose 三件套 `config --quiet` 通过；selfcheck **34 通过/1 警告/0 阻断**；四个二进制 `agf-server`/`agf-ingest`/`agf-scheduler`/`agfctl` 均已实现） |
| **M2** | 认证/多租户/RBAC + 资产 CRUD + Agent 上报 + 拓扑图 | 登录→首登改密→资产上报→拓扑可见；跨租户访问被拒 | 🟢 已实现并实测（agf-auth 68 + agf-asset 69 单测；`agf-api` **78 个端点**含登录/资产/拓扑/GraphQL/WS，`apps/server` 完整装配；实测离线模式 `GET /healthz` 200、`/api/v1/openapi.json` = OpenAPI 3.1.0（76 paths）、admin 登录返回 `must_change_password:true` 且不发令牌）。**资源当前为进程内内存实现**（`TODO(api-persistence)`），PG 持久化链路待阶段二接真库验证 |
| **M3** | ingest：MCP/Syslog/Webhook/Kafka + 解析框架 + ≥5 厂商模板 + 事件查询 | 5 家厂商样本可解析入 events；原始日志可回放 | 🟢 解析与接入完成（**117 个厂商解析模板** / 25 个厂商目录 + 28 份样本 + agf-ingest 174 测试 + 回放与事件查询 API）；**采集面已实现**：Syslog TLS（RFC5425）、Kafka（纯 Rust `rskafka`）、Pulsar（**经 KoP 复用 Kafka 接收器**）、MQTT、SNMP Trap（v1/v2c + v3 USM `noAuthNoPriv`/`authNoPriv`）、JDBC（PostgreSQL/MySQL）、OTLP（**HTTP 三信号 logs + traces + metrics**；gRPC 只有 `LogsService`）、OSS-S3 拉取、**NATS JetStream 入向订阅**（durable 幂等 + 真 `ack_with(AckKind)`）、**CEL 派生字段**（模板 `derived` 段）、**默认列式 Parquet 冷归档**、**Rust 动态库插件**（`engine: plugin` 模板 + `AGF_INGEST_PLUGIN_DIR`，宿主加载器 `crates/agf-plugin` + 解析管线接线 `agf-ingest/src/engine/plugin.rs`）——`/readyz` 能力矩阵**四态**（`ready`/`not-wired`/`not-implemented`/`mock`）逐条如实（未配置即不启用，不降级为 Mock）；**仍未实现**：gRPC 侧 TraceService/MetricsService（PV-016，**10/10 已闭环**：插件项本轮接线完成，局限见 `README.md` §2.5 与 `docs/operations.md`） |
| **M4** | AI 网关：多厂商 + Mock 模式 + 密钥 + 计量 + 协议转换 + 流式 | 3 家厂商适配器 + Mock；无 Key 自动降级不报错 | 🟢 网关能力完成（协议转换/路由/三级降级/计量/精确缓存/内容过滤/Mock，agf-aigw 288 测试）；真实 Key 联调见 `pending-verification.md` PV-008 |
| **M5** | 风险：规则引擎 + 五大域 + 正负样本 + 告警 + 案件 | 提示词注入/凭证泄露/RAG 投毒各 ≥10 条规则，正负样本全绿 | 🟢 已完成（54 条规则覆盖 5 域，规则回归 **54/54 通过、正样本 111/111、负样本 113/113**；告警聚合/降噪/案件/SLA/通知/SOAR 剧本在 agf-correlate 实现，122 测试） |
| **M6** | 运行时：MCP 代理 + 策略 + 三级配额 + 黑名单 + 拦截审计 | 策略下发后危险工具调用被拦截并留审计 | 🟢 已完成（275 单测全绿：策略/Rego/CEL/三级配额/黑名单/审批/哈希链审计/防绕过自检） |
| **M7** | 红队：用例库 + 编排 + 报告 + CI 卡点 | 200+ 用例加载校验通过；战役产出报告含成功率与绕过路径 | 🟡 用例库 225 条、12/12 类目、公开 PoC 89 条（39.6%），`agfctl redteam verify` 已通过；真实 Agent 单轮/三轮哨兵和 MCP 单次/同工具两步/同端点双工具哨兵有本地回环与 CI 判定，真实已判定命中生成关联待审发现。任意或跨服务工具链、多 Agent 协作及客户真实 runner 验证仍待完成。 |
| **M8** | 阿里云：AgentTeams + 五适配器 + Mock + 自检页 | 无云凭据时全部走 Mock，主流程不受影响 | 🟢 Mock 路径达成（215 测试：五适配器 + Mock + 自检 + 断路器/重试）；真机联调见 PV-007 |
| **M9** | 商业化：审计防篡改 + 计费 + 白标 + Helm + 压测 + 加固 | 审计链校验通过；Helm lint 通过；prod compose 非 root/只读根 | 🟡 审计哈希链、计费/白标模型、Helm Chart（25 模板 ×3 values）、prod compose 加固均已落盘；**`helm lint` / `helm template` 已实测**（helm v3.16.4 装在项目内 `tools/bin/helm.exe`：`lint` 与 `lint --strict` 均 **0 chart failed**，三套 values 全部渲染成功——PV-011 已闭环）；压测属阶段二（PV-010） |
| **M10** | 文档：架构/威胁模型/适配器指南/运维手册/演示数据 | 文档齐备 + pending-verification 完整 | 🟢 文档齐备（README + architecture/threat-model/deployment/adapter-spec/operations/roadmap/acceptance + pending-verification 及分域明细） |

**测试总览（代码冻结后实测）**：`cargo test --workspace` = **2099 项全绿 / 0 失败**；
`cargo clippy --workspace --all-targets -- -D warnings` = 0 告警；`cargo fmt --all --check` = 无差异；
前端 `apps/web`：typecheck 通过、45 项 vitest 全绿、eslint 0 error、`pnpm run build` 成功（33 文件 / 4.3 MB，按 antd/charts/graph 分包）。

状态图例：⬜ 未开始 · 🟡 进行中 · 🟢 已完成 · 🔴 阻塞（原因见 `pending-verification.md`）

---

## M1 交付记录（骨架）

### ① 变更文件清单

```
Cargo.toml                      workspace 定义（17 个成员 + 统一 lint/依赖版本）
rust-toolchain.toml             固定 channel 1.97.1（不声明 components，避免 rustup 阻塞）
rustfmt.toml / deny.toml        格式与依赖合规门禁
.cargo/config.toml              构建产物重定向到 <root>/target（相对路径，可迁移）
.gitignore                      铁律 3：排除 data/ vendor/ models/ tools/ target/ 等
.env.example                    全部配置项样例（路径/端口/密钥/厂商开关）
docker-compose.yml              全栈编排（依赖 + 应用 + 可选 clickhouse/grafana profile）
docker-compose.dev.yml          开发覆盖：只起依赖
docker-compose.prod.yml         生产编排（非 root / 只读根 / 资源限制 / 备份 sidecar）
deploy/docker/Dockerfile        cargo-chef 多阶段 + distroless；web 用 nginx-unprivileged
deploy/docker/nginx.conf        控制台反代（SSE 不缓冲、安全响应头）
deploy/sql/migration_parts/       历史 0001 四分片 + RLS + 哈希链审计 + 种子数据
deploy/sql/migrations/            后续 SQLx 迁移版本
scripts/env.ps1                 统一环境初始化（路径纪律 + 缓存重定向）
scripts/selfcheck.ps1           零外部依赖自检（铁律 5）
Justfile                        常用任务入口
crates/agf-core/**              领域内核（35 模块，含单元测试）
crates/<其余 13 个 crate>/      骨架（lib.rs + Cargo.toml），按里程碑填充
apps/server|ingest|scheduler/   二进制骨架
```

### ② 本地验证命令与预期输出

```powershell
# 1) 环境自检（无需外网、无需 Docker）
& scripts\selfcheck.ps1
# 预期：25+ 项通过 / 若干警告（未配置密钥、Docker 未启动等）/ 0 项阻断
#       末尾输出「无阻断项：路径纪律与缓存重定向生效，未触碰 D:\Environment。」

# 2) compose 语法与变量校验（Docker 守护需运行）
docker compose config --quiet
# 预期：无输出（退出码 0）

# 3) 编译
cargo check --workspace --all-targets
# 预期：Finished `dev` profile，无 error

# 4) 领域内核单元测试
cargo test -p agf-core
# 预期：test result: ok. 150+ passed; 0 failed
```

### ③ 新增阻塞项

见 `docs/pending-verification.md` 的 PV-001 ~ PV-006（Docker 镜像拉取、cargo-deny 安装、
Playwright 浏览器、真实样本抓取、K8s Helm 校验、覆盖率工具）。

### ④ 需要用户提供/授权

- 确认 Docker Desktop 可长期运行（阶段二压测与真机联调需要）。
- 阶段二所需凭据（大模型 API Key / 阿里云 RAM Role / 各厂商设备账号）——**阶段一不需要**。

---

## 实现注记（踩坑记录）

| 现象 | 根因 | 处置 |
|---|---|---|
| `cargo` 调用卡住/超时 | `rust-toolchain.toml` 声明了 `components`（rust-src），rustup 每次进入目录都尝试同步 | 只固定 `channel`，组件按需手动装并登记 PV |
| 自检脚本中文乱码 | 文件 UTF-8 无 BOM，Windows PowerShell 5.1 按 ANSI 解码 | `scripts/*.ps1` 一律保存为 **UTF-8 with BOM** |
| dot-source 后函数全部未定义 | `env.ps1` 声明了 `param([switch]$Quiet)`，dot-source 时调用方的 param 块生效导致脚本被当作"带参数的脚本"处理并中断 | `env.ps1` **不用 param()**，改用环境变量 `AGF_ENV_QUIET` |
| 设置 `CARGO_HOME` 到项目内后 cargo 不可用 | rustup 代理二进制在 `$CARGO_HOME\bin`，指向空目录即找不到工具链 | 不覆盖 CARGO_HOME/RUSTUP_HOME；用 `build.target-dir` + `CARGO_INSTALL_ROOT` 实现产物落项目内 |
| `Measure-Object -Sum` 在严格模式抛异常 | 空集合返回的对象没有 `Sum` 属性 | 改为显式累加，避免属性探测 |
| 自检脚本改完又乱码 | 编辑工具按 UTF-8 **无 BOM** 回写文件 | 每次改完 `scripts/*.ps1` 都要重新写回 **UTF-8 with BOM**（已用字节头 `EF BB BF` 校验） |
| 容器启动即退出：`version 'GLIBC_2.38' not found` | builder 用 `rust:1.97-slim`（Debian **13 trixie**，glibc 2.41），运行镜像用 distroless `cc-debian12`（glibc 2.36） | 运行镜像改用 `gcr.io/distroless/cc-debian13:nonroot`；builder 与 runtime 的 Debian 代号必须成对 |
| `docker build` 上传几十 GB 上下文 | 仓库根的 `.dockerignore` 是**空文件**，`target/`（本机 58 GB）、`.cargo/registry` 全部进入构建上下文 | 补齐 `.dockerignore`：排除 `target/`、`.cargo/registry`、`data/`、`tools/`、`vendor/`、`models/`、`node_modules`、`dist`、`.git`、`tests/`、`docs/` |
| `pnpm install` 在容器里失败：`ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION` | Dockerfile 的依赖层只 COPY 了 `package.json` 与锁文件，漏了 `pnpm-workspace.yaml`——而 `minimumReleaseAgeExclude`/`allowBuilds` 声明在那里 | 依赖层一并 COPY `pnpm-workspace.yaml`，并把 `--frozen-lockfile=false` 收紧为 `--frozen-lockfile` |
| 绝对路径自检满屏误报 | 盘符正则 `[A-Za-z]:[\\/]` 把 URL 里的 `http://` 的 `p:` 当成盘符 | 用负向后顾 `(?<![A-Za-z0-9])[A-Za-z]:[\\/]` |
| 覆盖率门禁无法运行 | rustc 未装 `llvm-tools-preview`，而铁律 2 禁止往只读工具链装组件 | `coverage.ps1` 按 环境变量 → `.env` 的 `AGF_LLVM_BIN` → rustup sysroot → 本机只读 LLVM（NDK 自带 LLVM 21）四级发现；实测 LLVM 21 可处理 rustc 1.97.1（LLVM 22.1）的 `.profraw` |
| 覆盖率跑出"编译失败" | 多个 agent 并行改代码时跑全工作区编译，必然撞上 WIP | 覆盖率/门禁必须在**代码冻结后**跑，不要在并行编辑期间跑 |
| 覆盖率脚本报 `expected subcommand 'llvm-cov'` | 直接调用 `cargo-llvm-cov.exe` 时必须显式带 `llvm-cov` 子命令（cargo 调用 `cargo llvm-cov` 时正是这么传的） | 三条调用都改为 `& $tool llvm-cov …` |
| 覆盖率脚本在编译前就中断 | `lib.ps1` 设了 `$ErrorActionPreference='Stop'`，cargo-llvm-cov 每次都往 stderr 打一行 `info: … setting cfg(coverage) …`，被当成终止错误抛出 | 测量期间临时降为 `Continue`，改为显式判定 `$LASTEXITCODE` |
| 样例/规则/模板目录整体未被 git 跟踪 | `.gitignore` 的 `logs/` + `*.log` 连坐忽略了 `tests/fixtures/logs/`（既有 18 份样本、manifest、SOURCES.md 全部 untracked），全新克隆会让既有测试直接失败 | 追加目录级反向例外 `!tests/fixtures/logs/` + `!tests/fixtures/logs/**`；用 `git status --untracked-files=all` 复核 |
| `dotenvy` 报 `.env 解析失败: AIGuardFabric 智御矩阵` | `VITE_APP_TITLE` 的值含空格且未加引号 | 值加双引号；`.env` 与 `.env.example` 同步 |
| 容器内迁移报 `syntax error at or near "window"` | 历史 0001 迁移曾把 PostgreSQL 保留字 `window` 当列名用（`quotas.window` / `quota_usage.window`，含索引与 INSERT 列清单共 5 处；现见 `deploy/sql/migration_parts/`） | 5 处标识符统一加双引号 `"window"`；已用一次性 postgres 容器全量验证：**72 表 / 51 条 RLS 策略 / `events` 为 hypertable**，退出码 0 |
| 改了 SQL 但容器里还是旧的报错 | `crates/agf-storage/src/db.rs` 用 `sqlx::migrate!("../../deploy/sql/migrations")` **编译期内嵌**迁移，bind mount 对运行中的二进制无效 | 改迁移必须重建镜像；离线纯 SQL 初始化改用 `agfctl migrate --dir` |
| 迁移"表已建但版本表为空"的双写风险 | compose 曾把迁移目录挂到 `/docker-entrypoint-initdb.d`，与应用的 `sqlx::migrate!` 重复执行同一份 SQL | 去掉该挂载，**唯一权威路径 = 应用侧 sqlx 迁移**（记入 `_sqlx_migrations`） |
| `docker compose up -d` 报 `dependency failed to start: container agf-postgres is unhealthy` | postgres 首次初始化期间（跑 initdb 脚本）`pg_isready` 尚不可用，健康检查被判失败，compose 随即中止后续服务 | 等 postgres 初始化完成后重跑 `docker compose up -d` 即全部拉起（实测 8 个容器全部 healthy）；去掉 initdb 挂载后该竞态消失 |
| `docker pull minio/minio` 报 `repository does not exist` | MinIO 已从 Docker Hub 撤下官方镜像 | 镜像改为 `quay.io/minio/minio:latest` 与 `quay.io/minio/mc:latest`（compose / `.env.example` / helm values / 部署文档同步） |
| demo 第 6 步策略规则"形态未能解析" | 规则 DSL 解析正则要求正则字面量必须带 `i` 标志，而 fixtures 里有一条不带 | 正则改为 `/(.*)/(i?)\s*$`，`i` 可选并按是否带 `i` 决定大小写敏感性 |
| PowerShell 多行字符串替换 `.rs`/`.ps1` 时静默丢行 | `-replace`/`[string]::Replace` 对多行内容的 BOM/换行处理不可靠 | 多行改动一律用编辑工具或 Python 脚本（显式多行字面量），改完校验字节头与行数 |
| 重建 `agf-server` 后控制台全站 502 | nginx 的 `upstream` 块只在**启动时**解析一次主机名，容器重建换了 IP 后仍指向旧地址 | `deploy/docker/nginx.conf` 改用「Docker 内嵌 DNS（`resolver 127.0.0.11 valid=10s`）+ 变量 `proxy_pass`」，10s 内自动跟上（代价：失去 upstream keepalive） |
| 控制台调用 35 条路径后端压根没有 | 前端按自己的域模型写调用、后端按 §4.11 资源组命名，两边从未逐条对账（前端要 `/alicloud/self-check`、后端是 `/selfcheck`；要 `/ingest/sources`、后端是 `/sources`） | 新增 `scripts/verify-console-paths.py`：把「控制台调用 ↔ 真实注册路由」的契约变成**可复跑**检查（路径 + 形状 + 列表非空），并补齐缺失端点、别名指到既有处理器 |
| 后端一返回真数据，控制台页面就抛错 | 部分列表端点平台侧返回**分页信封**，而 `client.ts` 声明的是**裸数组**（此前只因后端 404 走 demo 兜底才"看起来正常"） | 逐条以 `client.ts` 为准修形状：`campaigns`/`cases`/`reports`/`ingest/sources`/`ingest/parsers` 改 `Paged<T>` + 页面取 `.items` |
| `endpoint_specs` 的路径前缀没法统一 | `EndpointSpec.path` 是 `&'static str`，运行期无法拼 `/api/v1`；且 `/overview` 与 `/healthz` 同为绝对形状、无法靠形状判断是否要加前缀 | 新模块的 35 条 spec 路径**统一写成完整路径**，与 platform 既有条目一致（子代理建议的 `Box::leak` 每次调用都会泄漏，未采用） |
| 演示数据灌了、列表还是空 | 列表页读的是 `ApiStore` 的**内存层**，而 `data/seed/*.json` 从来没有写入路径 | 新增 `seed.rs`（`AGF_SEED_FIXTURES` 开关，默认关；业务串 id 经 `deterministic_id` 映射 UUID 并重写跨表引用；坏数据只 warn 跳过） |
