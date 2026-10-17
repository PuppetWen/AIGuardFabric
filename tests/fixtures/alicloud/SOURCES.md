# 阿里云离线样本来源

核对日期：2026-09-20。用途：只下载公开协议定义和示例，生成本地假服务及离线 Mock 样本；没有使用真实云账号发起业务操作。

来源为阿里云 OpenAPI 官方元数据：

- [CMS 2019-01-01](https://api.aliyun.com/meta/v1/products/Cms/versions/2019-01-01/api-docs.json)
- [APIG 2024-03-27](https://api.aliyun.com/meta/v1/products/APIG/versions/2024-03-27/api-docs.json)
- [MSE 2019-05-31](https://api.aliyun.com/meta/v1/products/Mse/versions/2019-05-31/api-docs.json)
- [PrivateLink 2020-04-15](https://api.aliyun.com/meta/v1/products/Privatelink/versions/2020-04-15/api-docs.json)
- [SchedulerX3 2024-06-24](https://api.aliyun.com/meta/v1/products/SchedulerX3/versions/2024-06-24/api-docs.json)
- [AgentTeams 2026-06-05](https://api.aliyun.com/meta/v1/products/AgentTeams/versions/2026-06-05/api-docs.json)

`openapi-*.json` 从公开响应 schema/example 生成，不是真实账号响应录制。AgentTeams 为连贯演示补充了合成调整：团队、Worker 和任务名称关联到同一实例，列表为完整单页，NextToken 为空，TotalCount 与 Items 一致。这些调整不改变公开字段结构。

其他目录既有 fixtures 属于合成测试数据。Mock 标识必须保留，不能用其资源数、配额或连接状态代替真实检查。

签名与 STS 协议还参考 [ACS3 请求签名](https://help.aliyun.com/en/sdk/product-overview/v3-request-structure-and-signature) 和 [AssumeRole](https://www.alibabacloud.com/help/zh/ram/developer-reference/api-sts-2015-04-01-assumerole)。测试仅访问随机本地端口或读取固定样本。

工作负载身份参考官方 [ECS 元数据与 IMDSv2](https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata/) 与 [AssumeRoleWithOIDC](https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-assumerolewithoidc)。本地 wiremock 合成了元数据令牌、角色名和临时凭据，未访问真实元数据地址或读取部署端身份。

SchedulerX3 新增 OperateEnableJobs / OperateDisableJobs / OperateExecuteJob，仍来自上述 2024-06-24 官方元数据；Success、Code 和 RequestId 为合成本地响应。六服务目录现包含 50 个公开动作。HTTP 回调头依据 [官方 HTTP 任务说明](https://help.aliyun.com/en/schedulerx/schedulerx-xxljob/user-guide/http-tasks)，未访问真实云执行器。
