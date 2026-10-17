# PrivateLink 建链与验证 / Provisioning and verification

先准备已有的终端节点服务、VPC、交换机及安全组，并确认资源所在地域和维护负责人。
此流程不自动新建 VPC、安全组、服务资源、默认网络、路由或权限白名单。

1. 消费方选择明确的服务 ID、服务地域、VPC、1–10 个可用区及交换机、1–10 个安全组。
2. 跨地域时另填明确的带宽；同地域不填跨地域带宽。服务是否支持这些地域及带宽仍需厂商检查。
3. 检查资源与费用后，发起一次创建。原操作编号作为 `ClientToken`，一次操作只发送一次 POST。
4. 收到厂商回执只代表请求被接收。使用返回的终端节点 ID，观察节点属性、全部可用区及全部安全组。
5. 服务提供方使用自己的配置来源，单独审核并接受连接；消费方不会自动代用提供方凭据。
6. 等待观察到相同节点、服务、地域、VPC、交换机、安全组及实际状态。缺少页数/总数、字段、权限或来源时保持未知。
7. 从实际部署网络另做 DNS/TCP 探测，并按业务需求验证 TLS、认证及应用响应。

`Acknowledged` 是厂商 ACK；`Connected` 是云控制面的连接状态。这两者都不能单独证明业务可达。
结果 `Unknown` 时先读取原回执及云资源，不会自动重新派发。更换 UUID 也不应绕过未确认的写入风险。
租户、账号权限、来源修订或原操作期限失效时，未发出的动作应阻断；已发送的已知回执应保留。
创建与接受是两个独立动作，各自审核、各用自己的原编号。不得把创建 ACK 当作授权自动接受连接。

当前适配器提供上述精确请求及观察校验能力。控制台的持久意图、同事务审计、来源锁和操作入口
仍由 API 层负责；独立适配器测试通过不等于控制台接入、真实账号验证或现场网络验证已完成。
第一阶段不调用真实云账号；真实建链验收需要项目要求规定的第二阶段授权。

## English

Choose an existing endpoint service, its region, a VPC, 1–10 zones with explicit switches, and 1–10 security groups.
For cross-region creation, enter an explicit bandwidth. Review the selected resources and cost, then create once.
The original operation UUID is the client token. A provider ACK proves receipt, not completed provisioning.
Observe endpoint attributes and complete zone/group pages, including their totals, for the same resources.
The provider separately reviews and accepts the connection through its own configured source.
After control-plane observation, test DNS/TCP from the deployment network and test TLS/application authentication separately.
Unknown delivery is never automatically retried. Preserve the original receipt and investigate the original resource first.
The API layer must provide durable claims, tenant isolation, current authority, source locks and atomic audit.
Adapter tests alone do not establish console integration or live cloud/network acceptance.

## 官方契约 / Official contracts

- [CreateVpcEndpoint](https://www.alibabacloud.com/help/en/privatelink/developer-reference/api-privatelink-2020-04-15-createvpcendpoint)
- [EnableVpcEndpointConnection](https://www.alibabacloud.com/help/en/privatelink/developer-reference/api-privatelink-2020-04-15-enablevpcendpointconnection)

以上 API 为异步操作；HTTP 成功之后仍需读取节点和连接状态。
