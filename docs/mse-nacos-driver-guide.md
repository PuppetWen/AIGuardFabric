# MSE Nacos v2 CAS 驱动

本驱动提供 `agf_alicloud::mse::config_cas` 固定协议能力，供[专用配置发布与显式回滚工作流](mse-config-publication-guide.md)使用。工作流于 2026-10-01 通过原生、独立 PostgreSQL、实际 Edge 浏览器验收并部署到主站点。验收使用自有 Mock 与字面 loopback，没有执行真实 MSE 云端写入。平台策略发布与云端内容发布分别记录；驱动的 `Accepted` 不表示外部应用已加载策略。

## 请求前准备

1. 由管理员明确选择 Nacos 引擎的 HTTPS **origin**，例如 `https://engine.example:8848`。不能填写阿里云控制台 OpenAPI 地址、用户名/密码、路径、查询参数或片段。驱动固定使用 `/nacos/v2/cs/config`，不会自动切换版本或修改来源。
2. 明确填写 namespace **ID**、group 和 data ID。公共命名空间使用空字符串，不能把显示名称 `public` 当 ID；其他 ID 按原始 UTF-8 编码传输，不裁剪或改名。
3. 在平台侧保存绑定的租户、账号、实例、模式和版本，并提供 `NacosSendGuard`。该守卫必须核对当前配置/权限、原会话、审批和执行领取事实。驱动不会代替业务工作流判断租户或保存幂等记录。
4. 用现有 RAM Role/STS 解析能力实现 `NacosCredentialProvider`。驱动只接受已解析的 `CloudCredential`，不会从任意用户 URL、环境变量或服务器响应取凭据。凭据取得后检查守卫，并再次核对凭据是否过期。

引擎侧 RAM 读取与写入授权须独立配置；控制台能查询实例不能证明引擎允许更新配置。参见 [MSE 配置中心细粒度授权](https://www.alibabacloud.com/help/en/mse/user-guide/fine-grained-authorization-in-configuration-centers)。

## 读取、比较和发布

调用 `query(&key, &guard)` 读取确切内容。驱动要求 HTTP 200、v2 JSON envelope、`code=0`、字符串 `data` 和唯一 `Content-MD5`；MD5 必须与原始内容的 UTF-8 字节一致。空内容有效，CRLF 与 LF 不等价。加密、beta、tag 及未验证内容会被拒绝。

以该观察的 MD5 作为 `publish(&key, &md5, &desired, &guard)` 的基线。请求使用 POST form 的 `namespaceId/group/dataId/content/type=json` 和 **`casMd5` 请求头**。这是供独立 JSON 配置目标使用的低层驱动；内容 JSON 语义、专属目标管理确认、预览和历史记录由上层专用发布工作流负责，调用方不能跳过这些步骤。

| 返回结果 | 准确含义 | 下一步 |
|---|---|---|
| `Accepted` | HTTP 200 + `code=0` + 布尔 `data=true` | 再次读取确切内容，分别记录写回执和当前内容证据 |
| `Conflict` | HTTP 500 + 精确 v2 错误码 `20005` | 保留草稿，重新读取并显式重新预览，不覆盖新内容 |
| `Rejected` | 已知权限/参数错误的严格 HTTP/code 组合 | 显示安全错误分类，修正授权或输入后重新准备 |
| `Uncertain` | 传输开始后超时、断线、重定向、截断、超限或未知协议 | 保留原领取事实，只观察；绝不自动重发写入 |

普通 HTTP 500、文本含“MD5/CAS”、HTTP 409 或未知错误 envelope 均不会猜测为 CAS 冲突。未知结果后当前内容恰好等于期望值，只能证明当前观察到该内容，不能反向证明本次写入回执成功。原 POST 的 request ID 不能因为超时或审计失败重新领取。

控制台 `UpdateNacosConfig` 的普通 `Md5` 参数只被官方文档描述为 MD5 值，不能作为已验证 CAS 承诺；旧 RPC 请求形态保持兼容。参见 [UpdateNacosConfig](https://www.alibabacloud.com/help/en/mse/developer-reference/api-mse-2019-05-31-updatenacosconfig) 与 [Nacos v2 Open API](https://nacos.io/en/docs/v2/guide/user/open-api/)。

## CAS 与回滚的边界

Nacos 2.4.3 服务端 `casMd5` 进入 `insertOrUpdateCas`。它是内容 MD5 比较的 **upsert**：目标被并发删除后仍可能创建，不能承诺“只更新已存在对象”。相同内容被改走又改回的 ABA、元数据/type 修改和客户端热加载都不在该 MD5 证据范围内。参见 [ConfigOperationService](https://github.com/alibaba/nacos/blob/2.4.3/config/src/main/java/com/alibaba/nacos/config/server/service/ConfigOperationService.java) 与 [ExternalConfigInfoPersistServiceImpl](https://github.com/alibaba/nacos/blob/2.4.3/config/src/main/java/com/alibaba/nacos/config/server/service/repository/extrnal/ExternalConfigInfoPersistServiceImpl.java)。

显式回滚从同租户/账号/实例/配置身份的可信加密历史复制内容，重新读取基线、重新预览并以新操作发布；不能倒退平台版本号或重放原操作。原历史正文归档后不再可回滚。自动离线补传、其他云适配器、外部消费者加载确认以及云端 stage 2 验证仍待实现。

## 签名与协议来源

本驱动只实现经典 RAM 签名：`resource` 为 group 或 namespace ID 与 group 的 `+` 连接；对 resource、十进制 Unix 毫秒时间戳的组合执行 HMAC-SHA1，再 Base64。请求头为 `Spas-AccessKey/timeStamp/Spas-Signature`，STS 时附带 `Spas-SecurityToken`。它不使用控制台 RPC 的 secret `&` 后缀，不支持 SDK 的 signature-region/v4 分支。

算法实际核对来源为官方 [nacos-sdk-nodejs aliyun_auth.ts](https://raw.githubusercontent.com/nacos-group/nacos-sdk-nodejs/master/packages/nacos-config/src/aliyun_auth.ts)，观察日期 2026-10-01。独立 Python 标准库生成的三组固定向量及选定源语句 SHA256 位于 `config_cas/fixtures/signing-vectors.json`；源语句规范化 UTF-8/LF 的 SHA256 为 `4A6BC38D5FEE2455FC96B40171C148BD5202E36EF12206D4799B65AE08C6C2DE`。

官方 [v2.6.3 发布](https://github.com/nacos-group/nacos-sdk-nodejs/releases/tag/v2.6.3) 的 commit 为 `a096ee55e88c13c0cacb69948d72d0c41be1e819`。浏览器缓存未能读取该 commit 的文件体，因而以上摘要只标识实际读取的 master 算法片段，不声称整份固定 commit 文件已验证。正式云端准入前应另补固定版本文件体的来源比对；不自动跟随上游签名或协议变更。

响应协议依据 Nacos 2.4.3 [ConfigControllerV2](https://github.com/alibaba/nacos/blob/2.4.3/config/src/main/java/com/alibaba/nacos/config/server/controller/v2/ConfigControllerV2.java) 与 [ConfigServletInner](https://github.com/alibaba/nacos/blob/2.4.3/config/src/main/java/com/alibaba/nacos/config/server/controller/ConfigServletInner.java)。服务端升级到其他协议需显式适配，不能把 HTML 登录页或不支持的 v1/v3 响应当成功。

## 上限、停机与验证

默认内容上限 256 KiB，解码后的响应上限 320 KiB；调用总预算最多 30 秒，包含取凭据、守卫等待、请求与完整响应读取。调用方可收紧上限，不能扩大。错误、Debug 和日志不得输出配置正文、密钥、STS token 或原始 provider body。

客户端禁用代理、重定向以及底层协议 NACK 重试，保留正常 TLS 证书验证。HTTP 只经显式 `literal_loopback_for_test()` 接受字面 loopback IP，不接受 `localhost` DNS 或局域网地址。[reqwest 0.12.28 retry::never](https://docs.rs/reqwest/0.12.28/src/reqwest/retry.rs.html) 用于关闭客户端默认协议重试。

若上层取消 driver future，已送请求无法撤回；业务领取不能删除或重新派发。上层须先保存操作状态，按原 ID 恢复安全观察，不能因 future 无返回值推断未送达。

驱动已通过父任务的 19 项原生测试（9 项纯协议测试、10 项真实自有随机 `127.0.0.1` 测试）及严格 Clippy。覆盖经典签名向量、空/Unicode/CRLF、MD5/特殊配置拒绝、一次 CAS 与持久回读、凭据/守卫超时、重定向、响应丢失/截断和限额。上层工作流的独立 SQL 15 项全部实际执行通过；第二轮实际 Edge 验收 8 步通过，验证发布、只读恢复、以新 UUID 回滚、确认归档及连接列表刷新。最终工作区 256 组、3509 项通过，前端 486 项通过（1 项既有条件跳过）。部署后的 55 项只读接口、29 个 SPA 地址、63 个资源和 8 个服务健康通过，生产 PostgreSQL 审计链 1926 条、0 违规。这些证据不包含真实云端写入或外部消费者加载，`consumerApplied` 仍为未知。
