# AIGuardFabric（智御矩阵）

面向 AI Agent、MCP、Skill 和模型端点的安全治理平台。包含 Rust 后端、React 控制台，以及资产发现、风险检测、告警案件、模型网关、规则策略、审计与受管运行时接口。

## 当前状态

这是本地自托管版的公开源码。已有 Windows 主机上的 Linux 容器部署和 11 项真实文本模型功能检查通过；这不代表所有性能、安全质量和云端集成指标通过。

- 最新 10k 负载记录仍未通过；当前版本未完成 1,000 并发查询验收。
- 12 小时持续稳定性验收已取消，没有长稳通过结论。
- 历史红队语义质量、安全 CI 尚未全部通过；视觉模型能力未验。
- 阿里云真实资源联调待验；本地模拟不能代替真实云验收。
- Windows/Linux/macOS 的统一部署入口使用 Linux 容器。Apple Silicon 采用 `linux/amd64` 仿真方案，不宣称已做 Mac 或原生 ARM64 实机验收。

## 在另一台机器部署

安装 Git，以及运行 Linux 容器的 Docker 和 Docker Compose：

- **Windows**：Docker Desktop，使用 WSL 2 或 Hyper-V 的 Linux 容器环境。
- **Ubuntu / 其他 Linux**：Docker Engine 与 Compose 插件，或 Docker Desktop。
- **macOS Intel / Apple Silicon**：Docker Desktop；当前应用镜像按 `linux/amd64` 运行。

部署命令及初始化、真实模型接入、停止/更新方法见 [跨平台部署说明](docs/portable-deployment.md)。原有 [部署说明](docs/deployment.md) 和 Helm 模板提供其他部署方式，但不代替新机器的实际验收。

获取源码后进入项目目录，选择对应命令启动真实模式的核心服务：

```powershell
# Windows PowerShell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy.ps1 -Live
```

```bash
# Ubuntu、其他 Linux、macOS
bash ./deploy.sh --live
```

打开 `http://localhost:8081`，管理员用户名为 `agfadmin`，初始随机密码保存在本机 `.env.portable` 的 `AGF_BOOTSTRAP_ADMIN_PASSWORD`。首次登录要求改密。重复执行不会重置凭据或数据。不带 `-Live` / `--live` 的默认入口是明确标记的 Mock 演示模式；`--live` 也不会自动配置真实模型、设备或云资源。

该入口部署本地自托管环境，`AGF_ENV` 保持 `dev`，真实模式只关闭 Mock。它没有为内置数据库配置生产 TLS；如需生产部署，应使用独立生产编排并配置数据库 TLS 与信任证书，源码中的生产安全检查保持不变。

首次源码构建会下载基础镜像、Rust/npm 依赖并编译，耗时和占用取决于机器与网络。模型权重、设备密钥及云账号不包含在源码中，不会随源码自动复制；真实模型需配置自己的兼容服务。

## 源码目录

| 路径 | 内容 |
| --- | --- |
| `apps/server`、`apps/ingest`、`apps/scheduler` | API、接入及调度服务 |
| `apps/web` | React 控制台 |
| `crates` | 核心、安全治理、网关、存储及适配器 |
| `sdk` | 接入 SDK |
| `rules`、`redteam`、`parsers` | 规则、红队用例与日志解析模板 |
| `deploy` | Docker、SQL、Helm 及部署配置 |
| `scripts`、`tests` | 开发脚本与测试源码/夹具 |
| `vendor/yara-x` | 构建需要的固定第三方源码，保留其许可证 |

开发工具链以 `rust-toolchain.toml`、`Cargo.toml` 和前端锁文件为准。部分历史开发/验收脚本使用 PowerShell，统一部署入口不要求在 Linux/macOS 安装这些开发工具。

## 数据与凭据

本仓库不包含现场 `.env`、数据库、模型权重、私密密钥、个人凭据、历史 Git 对象、构建缓存或现场验收原始记录。首次部署应生成自己的随机凭据；不要公开生成的配置、运行数据或模型密钥。测试夹具中的示例标识不代表可用生产账号。

项目声明采用 [Apache License 2.0](LICENSE)。第三方代码、字体与测试材料继续适用各自的许可证和来源说明。

## 参考

- [Docker Compose 安装](https://docs.docker.com/compose/install/)
- [Docker Desktop for Windows](https://docs.docker.com/desktop/setup/install/windows-install/)
- [Docker Engine for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
- [Docker Desktop for Mac](https://docs.docker.com/desktop/setup/install/mac-install/)
