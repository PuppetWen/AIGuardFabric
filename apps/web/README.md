# AIGuardFabric 智御矩阵 — Web Console

AI 安全治理平台的统一控制台：纳管 AI Agent / MCP 服务 / Skill / 模型 / 凭据，做风险检测、AI 红队与运行时拦截。

Dark-themed, bilingual (zh-CN default / en-US) SPA built with **Vite 7 + React 19 + TypeScript 5.7**.
It runs completely offline: with no backend reachable, every page renders from a built-in demo dataset
and the console shows a clear **“演示数据（后端未连接）”** banner.

---

## 1. 环境要求 / Requirements

| 工具 | 版本 |
| --- | --- |
| Node.js | ≥ 20.19（本仓库验证于 v24.18.0） |
| pnpm | ≥ 10（本仓库验证于 11.24.0） |

```bash
node -v
pnpm -v
```

## 2. 安装 / Install

```bash
cd apps/web
pnpm install
```

`pnpm install` 在 `apps/web/pnpm-lock.yaml` 生成并写入锁文件（请提交该文件）。

> ⚠️ **务必在 `apps/web` 目录内执行 `pnpm install`。**
> 目前仓库根目录没有 `package.json`，只有一份声明了 Node workspace 的 `pnpm-workspace.yaml`。
> 若在仓库根目录安装，pnpm 会把 `apps/web/node_modules` 里的依赖链接改写为指向根目录
> `node_modules/.pnpm` 的 junction；一旦之后清理根目录的 `node_modules`，这些 junction 就会
> 变成悬空链接，`tsc` / `vite` 会报 `Cannot find module`。此时修复方法是删除
> `apps/web/node_modules` 后在本目录重新执行 `pnpm install`。
> 待仓库补上根 `package.json` 后，本约束即可移除。

> **关于 `ERR_PNPM_IGNORED_BUILDS`**：pnpm 默认拦截依赖的安装脚本。`apps/web/pnpm-workspace.yaml`
> 已显式声明 `allowBuilds: { esbuild: false }` —— esbuild 的可执行文件由可选依赖
> `@esbuild/<platform>` 提供并在运行时解析，无需 postinstall，因此安装不会失败。

## 3. 开发 / Dev

```bash
pnpm run dev          # http://127.0.0.1:5173
```

默认后端地址为 `http://127.0.0.1:8080`。若 Rust 网关未启动，控制台会在每次请求超时后
自动切入演示数据（见第 5 节），页面依然完整可用。

## 4. 构建与校验 / Build & checks

```bash
pnpm run typecheck    # tsc --noEmit（app + node 两套 tsconfig）
pnpm run lint         # ESLint flat config，0 error（warning 允许）
pnpm run test         # vitest run
pnpm run build        # tsc -b && vite build → dist/
pnpm run preview      # 预览构建产物 http://127.0.0.1:4173
```

## 5. 代理与离线演示回退 / Proxy & offline demo fallback

### 5.1 代理配置

`vite.config.ts` 中的 dev-server 代理：

| 路径 | 目标 | 说明 |
| --- | --- | --- |
| `/api` | `VITE_API_BASE_URL` | HTTP API，`changeOrigin: true` |
| `/ws` | `VITE_API_BASE_URL` | WebSocket，`ws: true` |

后端地址解析优先级：`VITE_API_BASE_URL` → `AIGUARD_BACKEND_URL` → `http://127.0.0.1:8080`。

```bash
# .env.local
VITE_API_BASE_URL=http://127.0.0.1:8080
VITE_API_TIMEOUT_MS=2500
# VITE_FORCE_DEMO=true
```

环境变量在**构建时**注入（`import.meta.env`），修改后需重启 dev server / 重新构建。

### 5.2 离线回退是怎么工作的

全部网络访问集中在 **`src/api/client.ts`** 一个文件里：

```
页面 → useApiQuery(name, () => api.xxx())          只依赖 client.ts 暴露的类型化方法
         ↓
      callApi(path, demoFactory)                  唯一的请求出口
         ↓
   request() → fetch('/api/...')                  携带 Bearer token（来自 authStore）
         ↓  成功          ↓  失败：网络错误 / 超时 / 5xx / 404 / 非 JSON 响应体
    返回 live 数据      调用 demoFactory() → src/api/demo/*  内置数据集
         ↓                        ↓
   markLive()（清除演示标记）  markDemo(reason)（点亮演示标记）
                                 ↓
                     DemoModeBanner 订阅该标记并渲染提示条
```

- `src/api/demo/` 下的数据是**确定性**的：所有时间戳都从 `src/utils/time.ts` 的
  `DEMO_EPOCH` 推导，伪随机数用 `seeded()`，因此每次刷新、每次测试结果完全一致。
- 回退是**按请求**发生的，不是全局开关：后端部分可用时可以一部分页面实时、一部分页面演示。
- `VITE_FORCE_DEMO=true` 时完全跳过网络（做 UI 开发很有用），提示条会显示
  “演示数据（已通过 VITE_FORCE_DEMO 强制开启）”。
- 演示数据覆盖每个页面的关键路径：资产/依赖/暴露面扣分项、MCP 工具能力画像、Skill 白名单、
  模型路由与 Token 计量、G6 拓扑与外传路径、发现证据链与三件套、规则正负样本、红队战役与
  Markdown 报告、策略 Rego/CEL、拦截流水与三级配额、16 种日志协议、告警 SLA、案件看板与
  SOAR 时间线、适配器降级行为、AgentTeams 自检、**审计哈希链（含 1 条被篡改记录）**、报表与设置。

### 5.3 演示凭据

| 字段 | 值 |
| --- | --- |
| 租户 / tenant | `acme` |
| 用户名 | `admin` |
| 密码 | `Admin@12345` |
| MFA | 任意 6 位数字 |

使用上述密码登录会触发**首登强制改密**流程（新密码需满足密码策略：≥12 位且含大小写、数字、符号）。

## 6. 页面清单 / Page inventory

| 路由 | 页面 | 主要能力 |
| --- | --- | --- |
| `/login` | 登录 | 租户+用户名+密码+MFA、首登强制改密、演示凭据提示 |
| `/` | 总览大屏 | 5 张 KPI 卡（含迷你走势）、风险趋势折线、五大安全域分布、Top 风险资产、最近告警、适配器健康条 |
| `/assets` | 资产台账 | 类型/部门/数据分级/生命周期/暴露面过滤 + 分页 + 抽屉（画像/依赖/发现来源/暴露面扣分项） |
| `/agents` | Agent 管理 | flavor/host/纳管模式/在线状态与心跳 + 免改造纳管向导（Sidecar / SDK 注入 / 网关注册） |
| `/mcps` | MCP 管理 | transport/tools 数/影子 MCP/明文凭据标记 + 工具清单抽屉（能力画像 + 风险等级） |
| `/skills` | Skill 授权 | 授权状态流转（批准/拒绝/撤销）+ 出网白名单编辑（域名/路径） |
| `/models` | 模型网关 | 端点表（厂商/模型/本地/单价/优先级/降级）、Mock 模式提示、路由策略编辑、Token 与费用图表 + 计量明细 |
| `/topology` | 拓扑血缘 | @antv/g6 渲染 Agent→MCP→Tool→数据源→模型，节点按类型着色、影子资产高亮、点击侧面板、数据外传路径高亮 |
| `/findings` | 风险发现 | 等级/域/状态过滤 + 详情抽屉（证据链、三件套、调用链、修复建议、LLM 研判） |
| `/rules` | 检测规则 | 规则表（域/等级/灰度/版本状态）+ 正负样本测试 + 灰度滑块 + 启用开关 |
| `/redteam` | 红队中心 | 战役列表 + 发起向导（用例类别/目标/CI 卡点）+ 结果表（成功/绕过路径）+ Markdown 报告预览 |
| `/policies` | 策略中心 | 双模编辑器（表单 / Rego-CEL 代码 + 结构校验）+ 策略列表（动作/优先级/拦截点/dry-run）+ 签名校验状态 |
| `/runtime` | 运行时防护 | 拦截点状态（MCP 代理 / AI 网关 / 进程 Hook / 出网代理）、实时拦截流水、三级配额用量条、命令与域名黑名单 |
| `/ingest` | 接入管理 | 日志源列表（协议/模式/健康）+ 新增向导（16 种协议）+ 解析器列表 + 原始日志回放 |
| `/alerts` | 告警中心 | SLA 倒计时列、聚合计数、状态流转、批量处置、升级路由配置 |
| `/cases` | 案件中心 | 看板视图（按 state 分列）+ 时间线 + 处置动作（隔离/吊销/封禁/隔离样本/通知）+ SOAR 执行记录 |
| `/integrations` | 集成与适配器 | 适配器卡片（类别/能力/健康/Mock）+ 配置抽屉 + 未配置时的降级行为说明 |
| `/alicloud` | 阿里云 AgentTeams | 团队列表、成员/角色、编排 DAG、跨 Team 调用链、五服务（CMS/APIG/MSE/Privatelink/SchedulerX3）绑定、云环境自检（连通性/最小权限/配额余量） |
| `/audit` | 审计日志 | 表格 + 哈希链校验（结论与问题项）+ 敏感动作过滤 + 导出 |
| `/reports` | 报表 | 报表列表 + 生成向导（类型/时间窗/格式/计划）+ 预览 + 定时计划 |
| `/settings` | 设置 | 租户信息/白标、用户与角色、API Key、配额默认值、通知渠道、密码策略 |

## 7. 代码结构 / Source layout

```
apps/web/
├── index.html                 主题预置（避免亮色闪烁）
├── vite.config.ts             代理、分包、vitest 配置
├── eslint.config.js           ESLint flat config
├── pnpm-workspace.yaml        esbuild 构建脚本放行声明
├── tsconfig{,.app,.node}.json
└── src/
    ├── api/
    │   ├── client.ts          ★ 唯一出口：请求 + 演示数据回退 + React Query 封装
    │   ├── client.test.ts
    │   └── demo/              确定性演示数据集（platform/assets/runtime/models/
    │                          detection/security/reports/audit/health/topology）
    ├── app/                   AppProviders（antd ConfigProvider 暗色算法）、router、locale
    ├── components/            AppLayout、DemoModeBanner、GlobalSearch、NotificationBell、
    │                          PageHeader、Panel、Tags、DataState、MiniChart
    ├── locales/               zh-CN.ts（基准）、en-US.ts、i18n.ts、locales.test.ts（键齐平校验）
    ├── pages/                 20 个路由页面 + pages.offline.test.tsx（离线渲染冒烟）
    ├── stores/                authStore、uiStore（主题/语言/侧栏）、authStorage
    ├── styles/global.css      --agf-* 设计令牌（暗色默认 / 亮色覆盖）
    ├── types/domain.ts        ★ 与后端对齐的领域模型（severity/domain/asset/policy/quota/…）
    └── utils/                 severity、palette、labels、format(dayjs)、colors(WCAG)、
                               markdown、time（演示时钟）、aliyunFallback
```

## 8. 质量约束 / Quality guarantees

- **TypeScript**：`strict` + `noUnusedLocals` + `noUnusedParameters`；导出签名中无 `any`，无 `@ts-ignore`。
- **i18n**：所有可见文案走 `t()`；`locales.test.ts` 双向校验 `zh-CN` / `en-US` 键完全一致，
  且 `{{placeholder}}` 占位符一致。
- **可访问性**：暗色主题下正文/次级/三级文字、各严重等级与域徽标、健康度色板都在
  `utils/presentation.test.ts` 中按 WCAG AA 断言对比度（正文 ≥ 4.5:1，辅助元素 ≥ 3:1）。
- **响应式**：布局在 1280px 及以下自适应（侧栏默认收起，图表与表格横向滚动）。
- **测试**：45 个用例 —— 演示数据回退（网络错误 / 5xx / 非 JSON）、严重等级色映射、
  i18n 键齐平、策略动作标签、配额用量比、WCAG 对比度、审计哈希链校验、Markdown 转义、
  SLA 倒计时、以及 10 个页面的**离线渲染冒烟**。

## 9. 技术栈 / Stack

React 19 · TypeScript 5.7 · Vite 7 · react-router-dom 7 · @tanstack/react-query 5 · zustand 5 ·
antd 5（darkAlgorithm）· @ant-design/icons · i18next + react-i18next · @antv/g6 5 · dayjs ·
echarts 5 + echarts-for-react · vitest 3 + @testing-library/react。
