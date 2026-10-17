# AIGuardFabric（智御矩阵）Helm Chart

AIGuardFabric AI 安全治理平台的 Kubernetes 部署单元。四个服务一套 Chart：`agf-server`（API /
控制台后端 / 迁移 / 引导管理员）、`agf-ingest`（日志与事件接入、解析归一）、`agf-scheduler`
（资产盘点 / 日志拉取 / 红队巡航 / 规则热更新 / 报表 / 归档）、`agf-web`（nginx-unprivileged
静态控制台 + `/api`、`/ws` 反代）。

数据面组件（PostgreSQL+TimescaleDB、Redis、NATS JetStream、MinIO、ClickHouse、Grafana）
作为**可选内置组件**提供，默认全部关闭 —— 生产指向外部托管实例。

> 事实来源（本 Chart 的每一项端口、环境变量、探针路径都以此为准，不凭假设）：
> `docker-compose.yml` / `docker-compose.prod.yml`、`deploy/docker/Dockerfile`、
> `deploy/docker/nginx.conf`、`.env.example`、`crates/agf-core/src/config.rs`。

---

## 1. 前置条件

| 项 | 要求 | 说明 |
|---|---|---|
| Kubernetes | `>= 1.27` | 依赖 `autoscaling/v2`（HPA）、`policy/v1`（PDB）、`networking.k8s.io/v1`（NetworkPolicy） |
| Helm | `>= 3.12` | 使用 `fail` / `tpl` 等能力；OCI registry 建议 3.13+ |
| 集群存储 | 至少一个 StorageClass | 证据卷 PVC + 可选内置组件持久卷 |
| metrics-server | HPA 需要 | 否则把 `hpa.*.enabled` 置 false |
| Prometheus Operator | 仅在 `serviceMonitor.enabled=true` 时需要 | 无 CRD 时保持 false，改用 Pod 注解抓取 |
| ingress-nginx 或阿里云 ALB Ingress | 仅在 `ingress.enabled=true` 时需要 | 注解默认按 nginx 编写 |
| 外部依赖 | PostgreSQL 16+TimescaleDB、Redis 7+、NATS 2.10+、S3 兼容对象存储 | 生产必须外部托管 |

---

## 2. 安装 / 升级 / 卸载

### 2.1 最小安装（演示，内置依赖，**不要用于生产**）

```bash
# 1) 准备私密值文件（不要入库；.helmignore 已排除 values-local.yaml）
cat > values-local.yaml <<'EOF'
secrets:
  pgPassword: "<用 openssl rand -base64 24 生成>"
  redisPassword: "<可选>"
  s3AccessKey: "agfminio"
  s3SecretKey: "<用 openssl rand -base64 24 生成>"
  jwtSecret: "<用 openssl rand -base64 48 生成，>=32 字节>"
  masterKeyBase64: "<用 openssl rand -base64 32 生成，恰好 32 字节 base64>"
  bootstrapAdminPassword: ""     # 留空 = 首启随机生成
  postgresAdminPassword: "<可选>"
  minioRootPassword: "<可选>"
  grafanaAdminPassword: "<可选>"
config:
  AGF_MOCK_MODE: "1"
postgresql:
  enabled: true
redis:
  enabled: true
nats:
  enabled: true
minio:
  enabled: true
EOF

# 2) 安装（内置依赖 + 演示模式）
helm upgrade --install agf ./deploy/helm/aiguardfabric \
  -n aiguardfabric --create-namespace \
  -f ./deploy/helm/aiguardfabric/values.yaml \
  -f values-local.yaml
```

### 2.2 生产安装（外部托管库 + 高可用）

```bash
helm upgrade --install agf ./deploy/helm/aiguardfabric \
  -n aiguardfabric --create-namespace \
  -f ./deploy/helm/aiguardfabric/values.yaml \
  -f ./deploy/helm/aiguardfabric/values-prod.yaml \
  -f values-local.yaml          # 只需在不用 existingSecret 时提供
```

### 2.3 气隙（离线）安装

```bash
# Chart 与镜像先在有网环境导出，再拷入内网导入私有 registry
helm upgrade --install agf ./aiguardfabric-0.1.0.tgz \
  -n aiguardfabric --create-namespace \
  -f ./deploy/helm/aiguardfabric/values-airgap.yaml
```

### 2.4 升级

```bash
# 只换镜像版本（发布流水线常用）
helm upgrade agf ./deploy/helm/aiguardfabric -n aiguardfabric \
  -f ./deploy/helm/aiguardfabric/values-prod.yaml \
  --set image.tag="$(git rev-parse --short HEAD)"

# 预演（强烈建议每次升级前执行）
helm upgrade agf ./deploy/helm/aiguardfabric -n aiguardfabric \
  -f ./deploy/helm/aiguardfabric/values-prod.yaml --dry-run=server

# 回滚
helm rollback agf -n aiguardfabric
```

**升级注意**：
- `templates/configmap.yaml` 与各 Deployment 都带 `aiguardfabric.io/config-revision`
  注解，配置变更会自动触发滚动更新。
- 证据 PVC 带 `helm.sh/resource-policy: keep`，`helm uninstall` **不会**删除证据数据。
- Secret 若由本 Chart 渲染，升级时会复用已有 Secret（Helm 语义）；换成
  `secrets.existingSecret` 后需自行清理旧的 Chart-managed Secret。

### 2.5 卸载

```bash
helm uninstall agf -n aiguardfabric

# 证据 PVC 因 resource-policy: keep 被保留，需手工确认后删除：
kubectl -n aiguardfabric get pvc
kubectl -n aiguardfabric delete pvc agf-evidence        # ⚠ 会丢证据，先确认已归档到对象存储
kubectl delete namespace aiguardfabric
```

---

## 3. 安全基线（默认强制，无开关可关）

| 控制项 | 值 | 实现位置 |
|---|---|---|
| 非 root 运行 | `runAsNonRoot: true`, `runAsUser/Group: 10001` | `podSecurityContext` / `containerSecurityContext`（与 Dockerfile `USER 10001:10001` 对齐） |
| 只读根文件系统 | `readOnlyRootFilesystem: true` | 同上；`/tmp` 用 `emptyDir`(Memory) 提供可写 |
| 禁止提权 | `allowPrivilegeEscalation: false`, `privileged: false` | 同上 |
| 能力集最小化 | `capabilities.drop: [ALL]` | 同上；Syslog 使用非特权端口 5514，无需 `NET_BIND_SERVICE` |
| seccomp | `seccompProfile: RuntimeDefault`（Pod + 容器双层） | 同上 |
| 资源配额 | 每服务显式 `requests`/`limits` | 各服务 `resources` |
| 优雅终止 | `terminationGracePeriodSeconds` + `preStop` | server 60s、ingest 45s、scheduler 60s、web 30s |
| Secret 外置 | `secrets.existingSecret` 优先；否则 `b64enc` 渲染 | `templates/secret.yaml` |
| 明文密钥防呆 | 关键密钥缺失时 `fail` 终止渲染 | `agf.validateSecrets` / `agf.validateJwtLength` |
| 网络最小化 | 默认拒绝 + 按需放行 | `templates/networkpolicy.yaml` |
| API 令牌不挂载 | `automountServiceAccountToken: false` | `templates/serviceaccount.yaml` |

### 3.1 web 组件的只读根例外（已显式处理）

nginx 官方镜像（含 `nginx-unprivileged`）启动时会写 `/etc/nginx/conf.d`（entrypoint 的
`envsubst` 模板处理）与 `/var/cache/nginx`（`proxy_temp` 等）。因此 `agf-web` 在**保留**
`readOnlyRootFilesystem: true` 的前提下，把这两个路径挂为受限 `emptyDir`
（`sizeLimit` 分别为 16Mi / 256Mi），避免磁盘被写满，也不牺牲根文件系统只读。

若改用构建期已完成 `envsubst`、且内置全部 temp 目录的自定义只读镜像，可删除
`templates/deployment-web.yaml` 中对应的两个 `volumeMounts`/`volumes` 项，实现完全只读根。

### 3.2 Secret 注入方式（推荐顺序）

**A（推荐，生产）** —— 指向外部托管 Secret：

```yaml
secrets:
  existingSecret: agf-prod-secrets
  # 既有 Secret 键名不一致时做重映射：
  existingSecretKeys:
    AGF_PG_PASSWORD: DB_PASSWORD
    AGF_JWT_SECRET: JWT_KEY
```

必需键清单（键名可用 `existingSecretKeys` 重映射）：

| Secret 键 | 必填 | 用途 / 约束 |
|---|---|---|
| `AGF_PG_PASSWORD` | ✅ | PostgreSQL 口令，`>=12` 字节，禁止弱口令 |
| `AGF_JWT_SECRET` | ✅ | JWT 签名密钥，`>=32` 字节（模板会校验长度） |
| `AGF_MASTER_KEY_BASE64` | ✅ | AES-256-GCM 主密钥，base64 编码 32 字节 |
| `AGF_S3_ACCESS_KEY` | ✅ | 对象存储 Access Key |
| `AGF_S3_SECRET_KEY` | ✅ | 对象存储 Secret Key |
| `AGF_REDIS_PASSWORD` | ⬜ | 非空时模板自动生成带口令的 `AGF_REDIS_URL` 并放 Secret |
| `AGF_CLICKHOUSE_PASSWORD` | ⬜ | ClickHouse 口令 |
| `AGF_BOOTSTRAP_ADMIN_PASSWORD` | ⬜ | 引导管理员口令，留空 = 首启随机生成 |
| `AGF_ALIYUN_ACCESS_KEY_ID` / `AGF_ALIYUN_ACCESS_KEY_SECRET` / `AGF_ALIYUN_STS_TOKEN` | ⬜ | 仅在 `AGF_ALIYUN_ENABLED=1` 时注入；STS 优先于 AK/SK |
| `AGF_GRAFANA_ADMIN_PASSWORD` | ⬜ | 内置 Grafana 管理员口令 |

**B（仅演示）** —— 在私密值文件里给 `secrets.*` 字面值，Helm 用 `b64enc` 渲染。
`values.yaml` 中这些字段**全部为空串**，且缺失时模板 `fail`，因此不可能误装出弱默认密钥。

### 3.3 `.helmignore` 已排除的文件

`values-local.yaml`、`values-*.local.yaml`、`secrets.yaml`、`*.secret.yaml`、`.env*` ——
防止私密值被 `helm package` 打进 `.tgz` 制品。

---

## 4. 网络与 PrivateLink（阿里云）

### 4.1 两种暴露方式

| 方式 | 适用 | 关键配置 |
|---|---|---|
| Ingress（公网或内网域名） | 控制台用户访问 | `ingress.enabled=true`，`ingress.tls.enabled=true` |
| PrivateLink 终端节点 | 跨 VPC 私网对接，**不经过公网** | `privateLink.enabled=true` + 云侧创建终端节点服务 |

### 4.2 PrivateLink 落地步骤

本 Chart 负责**平台侧最小前置条件**：渲染一个带阿里云 CCM 私网注解的
`LoadBalancer` Service（`<fullname>-server-privatelink`）。

```yaml
privateLink:
  enabled: true
  service:
    enabled: true
    apiPort: 8080
    annotations:
      # ★ 关键：私网类型 LB —— 公网 LB 不能作为 PrivateLink 终端节点服务的后端
      service.beta.kubernetes.io/alicloud-loadbalancer-address-type: intranet
      service.beta.kubernetes.io/alicloud-loadbalancer-health-check-flag: "on"
      service.beta.kubernetes.io/alicloud-loadbalancer-health-check-uri: "/healthz"
      service.beta.kubernetes.io/alicloud-loadbalancer-persistence-timeout: "300"
```

云侧（控制台或 Terraform，本 Chart 无法代劳）：

1. 用上一步 CCM 创建的**私网 CLB** 创建「终端节点服务（Endpoint Service）」。
2. **关闭**「自动接受连接」，改为白名单审批。
3. 白名单只加入客户 VPC 的终端节点 ID（`ep-xxxxxxxx`）。
4. 终端节点服务安全组**只放行 8080**，其余端口一律拒绝。
5. 客户端 VPC 创建「终端节点」并绑定，用私网域名访问
   `http://<ep-domain>:8080/api/v1/...`。

### 4.3 用 NetworkPolicy 把安全组白名单最小化

`templates/networkpolicy.yaml` 采用「默认拒绝 + 精确放行」三层结构：

1. `<fullname>-default-deny`：命名空间内所有 Pod 的入站/出站全部拒绝。
2. `<fullname>-allow-dns`：只放行到 kube-system/CoreDNS 的 53/tcp+udp。
3. 每服务 `-ingress` / `-egress`：只放行必要端口（API 8080、接入 8090/8091/5514、
   指标 9100、数据面 5432/6379/4222/9000/8123）。

配合方式：把 `networkPolicy.externalEndpoints.cidrs` 收敛为托管库实际网段，
`networkPolicy.allowPublicEgress` 保持 `false`（默认值）。这样即使安全组被放宽，
Pod 侧仍不会发起未授权出站。

```yaml
networkPolicy:
  enabled: true
  defaultDeny: true
  externalEndpoints:
    cidrs: ["10.0.0.0/8"]      # 按实际托管库/终端节点网段替换
  allowPublicEgress: false     # 生产保持 false；开启时模板自动屏蔽 169.254.169.254（云元数据）
```

> `allowPublicEgress=true` 时模板会在 `except` 中屏蔽 `169.254.169.254/32` 与
> `169.254.0.0/16`，防止 SSRF 读取云元数据凭据。

---

## 5. 参数表（values 参考）

### 5.1 全局

| 参数 | 默认 | 说明 |
|---|---|---|
| `nameOverride` | `""` | 覆盖 chart 名 |
| `fullnameOverride` | `""` | 覆盖 `<release>-<name>` |
| `global.imageRegistry` | `""` | 私有 registry 主机（气隙必填），最终地址 `<registry>/<repositoryPrefix>/<repo>:<tag>` |
| `global.imagePullSecrets` | `[{name: agf-registry-credentials}]` | 全局拉取密钥（可被服务级覆盖） |
| `global.productionMode` | `false` | 生产严格模式标记 |
| `image.repositoryPrefix` | `aiguardfabric` | 镜像仓库前缀（`0.0.0.0`） |
| `image.tag` | `""` | 留空 = `Chart.AppVersion`（`0.1.0`） |
| `image.pullPolicy` | `IfNotPresent` | 可被服务级覆盖 |
| `podSecurityContext` | 见文件 | Pod 级安全上下文（非 root / fsGroup / seccomp） |
| `containerSecurityContext` | 见文件 | 所有容器共用的加固片段 |
| `nodeSelector` / `tolerations` / `affinity` | `{}` / `[]` / `{}` | 全局调度约束 |
| `ports.*` | 见文件 | 集中端口定义，供 Deployment / NetworkPolicy / ServiceMonitor 复用 |

### 5.2 服务

| 参数 | 默认 | 说明 |
|---|---|---|
| `<svc>.enabled` | `true` | 是否部署该服务 |
| `<svc>.replicaCount` | server 2 / ingest 2 / scheduler 1 / web 2 | 副本数（scheduler 为 local-cron 时必须 1） |
| `<svc>.image.repository` | `agf-<svc>` | 镜像名（`agf-server` / `agf-ingest` / `agf-scheduler` / `agf-web`） |
| `<svc>.image.tag` | `""` | 覆盖全局 tag |
| `<svc>.imagePullSecrets` | `[]` | 覆盖全局拉取密钥 |
| `<svc>.env` | `{}` | 服务级非敏感环境变量（优先于 `config.*`） |
| `<svc>.extraEnv` | `[]` | 原样追加的 env 条目（可引用任意 ConfigMap/Secret/FieldRef） |
| `<svc>.extraEnvFrom` | `[]` | 附加的 `envFrom` |
| `<svc>.resources` | 见文件 | 每个服务的 requests/limits |
| `<svc>.livenessProbe` / `readinessProbe` / `startupProbe` | 见文件 | 支持 `type: tcp|http|exec`，字段与 K8s 探针同名 |
| `<svc>.terminationGracePeriodSeconds` | 30~60 | 优雅终止预算 |
| `<svc>.preStop` | 见文件 | distroless 无 shell，仅支持 `httpGet` |
| `<svc>.topologySpreadConstraints` / `affinity` | `[]` / `{}` | 高可用分散策略 |
| `web.apiUpstream` | `http://agf-server:8080` | nginx 反代上游（等价 compose 的 `AGF_API_UPSTREAM`） |
| `web.nginxConfigMap` | `""` | 用外部 ConfigMap 覆盖 `default.conf` |
| `server.evidenceVolume.enabled` | `true` | 是否给 server 挂 `/data` |

### 5.3 配置与密钥

| 参数 | 默认 | 说明 |
|---|---|---|
| `config.*` | 见 `values.yaml` | 非敏感环境变量，变量名与 `config.rs` 严格一致，渲染进 ConfigMap 后 `envFrom` 注入 |
| `extraConfig` | `{}` | 附加到 ConfigMap 的键值（覆盖同名 `config.*`） |
| `secrets.existingSecret` | `""` | **推荐**：外部 Secret 名；非空时不渲染 Secret |
| `secrets.existingSecretKeys` | `{}` | 键名重映射 |
| `secrets.pgPassword` / `jwtSecret` / `masterKeyBase64` / `s3SecretKey` | `""` | **必填**（除非用 `existingSecret`）；缺失即 `fail` |
| `secrets.*`（其余） | `""` | 可选密钥，见 §3.2 表格 |

### 5.4 可选内置组件

| 参数 | 默认 | 说明 |
|---|---|---|
| `postgresql.enabled` | `false` | TimescaleDB `latest-pg16`；`initdbConfigMap` 仅用于自定义初始化 SQL，应用迁移由服务执行 |
| `redis.enabled` | `false` | `redis:7.4-alpine`，与 compose 相同的 `appendonly` / `maxmemory` 参数 |
| `nats.enabled` | `false` | `nats:2.10-alpine`，JetStream + 监控 8222 |
| `minio.enabled` | `false` | S3 兼容；`minio.initBuckets` 一次性 Job 建 `agf-evidence`/`agf-raw-logs`/`agf-reports` |
| `clickhouse.enabled` | `false` | `24.8-alpine`，8123/9000 |
| `grafana.enabled` | `false` | `11.4.0`；预置项用外部 ConfigMap（`provisioning.*ExistingConfigMap`） |

> ⚠ 内置组件均为**演示/自测/离线演练**用途（单副本 StatefulSet，非生产级高可用）。
> 生产请使用对应 Operator 或云托管服务，并同步修改 `config.AGF_PG_HOST` 等指向托管端点。

### 5.5 高可用、入口与网络

| 参数 | 默认 | 说明 |
|---|---|---|
| `hpa.server.enabled` | `true` | `minReplicas 2` / `maxReplicas 10`，CPU 70% + 内存 80% |
| `hpa.ingest.enabled` | `true` | `minReplicas 2` / `maxReplicas 12`；`hpa.ingest.custom` 支持按 EPS 自定义指标 |
| `hpa.web.enabled` | `false` | 可选 |
| `hpa.scheduler.enabled` | `false` | 单副本语义，禁止扩缩 |
| `pdb.server/ingest/web.enabled` | `true` | `minAvailable: 1` |
| `pdb.scheduler.enabled` | `false` | 单副本 + `minAvailable=1` 会阻塞节点排空 |
| `ingress.enabled` | `false` | 启用后渲染 nginx 注解 + TLS + `configuration-snippet` 安全响应头 |
| `ingress.tls.enabled` / `secretName` | `false` / `agf-tls` | TLS 证书 |
| `ingress.certManager.enabled` | `false` | 用 cert-manager 自动签发 |
| `ingress.api.paths` | `/api`,`/ws`,`/healthz` | 路径与 `nginx.conf` 的反代前缀一致 |
| `privateLink.enabled` | `false` | 见 §4 |
| `networkPolicy.enabled` | `true` | 默认拒绝 + 按需放行 |
| `serviceMonitor.enabled` | `false` | 需 Prometheus Operator CRD |
| `volumes.evidence.*` | 50Gi / keep | 证据 PVC（`helm.sh/resource-policy: keep`） |
| `volumes.rules.configMapName` / `existingClaim` | `""` | `/app/rules` 只读挂载来源 |
| `extraManifests` | `[]` | 逃生舱，渲染任意额外清单 |

---

## 6. 服务与端口一览（与 compose 对齐）

| 服务 | 容器端口 | Service | 探针 | 备注 |
|---|---|---|---|---|
| `agf-server` | 8080 (api), 9100 (metrics) | `<fullname>-server` | readiness `GET /healthz`；liveness TCP | compose 健康检查同 URL |
| `agf-ingest` | 8090 (http), 8091 (mcp), 5514 tcp+udp (syslog), 9100 | `<fullname>-ingest` | readiness `GET /healthz:8090` | Syslog 用非特权端口 5514 |
| `agf-scheduler` | 9101 (health), 9100 (metrics) | `<fullname>-scheduler` | readiness `GET /healthz:9101` | 单副本；`AGF_SCHEDULER_BACKEND` 可切 SchedulerX3 |
| `agf-web` | 8080 (nginx) | `<fullname>-web`（对外 80） | `GET /` | nginx-unprivileged |

## 7. 可观测性

- **指标抓取**：默认给 Pod 打注解 `prometheus.io/scrape=true`、`port=9100`、`path=/metrics`
  （与 `AGF_PROMETHEUS_ENABLED=1` 联动）。有 Prometheus Operator 时置
  `serviceMonitor.enabled=true`。
- **抓取配置与告警规则**：仓库 `deploy/prometheus/prometheus.yml` 与 `alerts.yml`（≥8 条规则）。
- **仪表盘**：仓库 `deploy/grafana/dashboards/*.json`（4 个，可直接导入）。
- ⚠ **指标名待与实现对齐**：当前代码库尚未埋点（`crates/*` 内无 `counter!`/`histogram!` 调用），
  仪表盘与告警规则里的指标名是**约定占位名**，需在实现埋点后回归校准。
  已登记 `docs/pending-verification.deploy.md` 的 **PV-DEPLOY-002**。

## 8. 故障排查

```bash
# 渲染检查（本地，不需要集群）
helm lint deploy/helm/aiguardfabric
helm template agf deploy/helm/aiguardfabric -f deploy/helm/aiguardfabric/values-prod.yaml > /tmp/rendered.yaml

# Secret 校验失败（模板 fail）时，确认密钥来源：
#   Error: AIGuardFabric: 缺少密钥来源。请二选一：(A) 设置 secrets.existingSecret ... (B) ...
helm template agf deploy/helm/aiguardfabric --set secrets.existingSecret=foo   # 方式 A 通过

# Pod 起不来
kubectl -n aiguardfabric get pods -o wide
kubectl -n aiguardfabric describe pod <pod>          # 看探针失败 / 镜像拉取
kubectl -n aiguardfabric logs deploy/agf-server --tail=200
kubectl -n aiguardfabric get events --sort-by=.lastTimestamp

# 探针相关常见原因
#   readiness 失败：AGF_PG_PASSWORD 不对 → 数据库连不上 → /healthz 非 200
#   liveness 反复重启：只读根下 /tmp 未挂载（本 Chart 已挂 emptyDir）
#   agf-web CrashLoop：/var/cache/nginx 不可写（本 Chart 已挂 emptyDir）

# NetworkPolicy 排查（默认拒绝下"连不上"多半是没放行）
kubectl -n aiguardfabric get networkpolicy
kubectl -n aiguardfabric describe networkpolicy agf-server-egress

# PrivateLink Service 是否拿到私网 IP
kubectl -n aiguardfabric get svc agf-server-privatelink -o wide
```

## 9. 与 docker-compose 的对应关系

| compose 服务 | Chart 资源 | 一致性保证 |
|---|---|---|
| `postgres` | `postgresql.*`（可选 StatefulSet） | 同镜像、同 `-c` 参数（`shared_preload_libraries=timescaledb`、`max_connections=200`、`password_encryption=scram-sha-256`） |
| `redis` | `redis.*`（可选） | 同 `--appendonly yes --save "900 1" --maxmemory 512mb --maxmemory-policy allkeys-lru` |
| `nats` | `nats.*`（可选） | 同 `-js -sd /data -m 8222` |
| `minio` + `minio-init` | `minio.*` + 建桶 Job | 同三个桶名；证据桶 `anonymous set none` |
| `clickhouse` | `clickhouse.*`（可选） | 同 8123/9000 与 `CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1` |
| `grafana` | `grafana.*`（可选） | 同 11.4.0；`GF_USERS_ALLOW_SIGN_UP=false`、`GF_INSTALL_PLUGINS=""` |
| `agf-server` / `agf-ingest` / `agf-scheduler` / `agf-web` | 4 个 Deployment + Service | 同端口、同健康检查路径、同环境变量名（`config.rs` 校验） |

## 10. 已知边界与未验证项

- **未做 Helm 真实渲染**：本机无 `helm` 可执行文件，模板仅通过自定义结构性渲染器与
  YAML 解析校验，**未用 Helm 官方引擎渲染**。登记为 `docs/pending-verification.deploy.md`
  的 **PV-DEPLOY-001**。
- **指标名未对齐实现**：见 §7，登记为 **PV-DEPLOY-002**。
- **调度器健康端口 9101**：来自 compose 健康检查；`deploy/docker/Dockerfile` 仅 `EXPOSE`
  8080/8090/8091/9100/9101/5514，未逐一验证 9101 上是否真的提供 `/healthz`。
  登记为 **PV-DEPLOY-003**。
- **未在真实集群验证**：CRD 依赖（ServiceMonitor）、HPA 指标可用性、PrivateLink 注解与
  CCM 的实际行为均需在目标集群验证。登记为 **PV-DEPLOY-004**。
- **镜像仓库前缀**：`image.repositoryPrefix` 默认 `aiguardfabric`（与 compose 的
  `AGF_IMAGE_PREFIX` 一致），但 `.env.example` 未定义公共 registry 主机，实际地址需由发布
  流水线通过 `global.imageRegistry` 注入。
