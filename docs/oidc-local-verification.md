# OIDC 本地验收

此流程使用项目自带公开测试密钥和本机模拟身份服务，不连接企业账号。仅用于开发验收。

1. 运行开发版 API 与 Web；使用本地管理员登录测试租户。
2. 在项目根执行 `node tests/support/oidc_server.cjs`。服务只监听 `127.0.0.1:18082`。
3. “设置 → 企业登录”填写：Issuer `http://127.0.0.1:18082`、Client ID `console`、认证方式 `Client Secret Post`、Secret `local-test-secret`、回调 `http://127.0.0.1:8081/login/oidc/callback`。
4. 开启首次创建账号，默认角色只读，邮箱域名 `example.test`，保存并启用。
5. 在新的隐私浏览器窗口打开控制台，填写此租户标识，点击企业 SSO 登录；模拟身份中心会明确显示本地测试标识，点击“使用测试企业身份继续”。
6. 登录后确认账号是“企业测试员工”，无法修改企业登录配置；管理员可在账号管理调整该用户的角色或停用，下一次登录应按实际状态处理。
7. 在账号安全绑定 MFA、保存恢复码、退出后重新 SSO 登录并完成第二因素验证。重复使用恢复码应失败。

控制台端口不同，先设置 `AGF_TEST_OIDC_REDIRECT_URI` 为实际同源回调地址。跨电脑 SSH 联调时，可设置 `AGF_TEST_OIDC_BROWSER_ORIGIN` 为浏览器可达的本机端口转发地址；Issuer/token/JWKS 仍由 API 访问服务所在机器的回环地址。所有这些变量只供测试服务读取。

停止本测试 Node 进程即可关闭模拟身份中心。测试完成后停用测试租户的 OIDC 配置；不要把测试密钥或模拟账号配置用于生产。

自动化：`cargo test -p agf-api --test oidc_login --locked --offline` 使用动态回环端口和独立内存账号，覆盖真实 ES256 签名、错误签名/密钥/issuer/aud/azp/nonce/时间声明、PKCE、浏览器绑定、防重放、租户、账号状态、角色保留及强制 MFA。

协议依据：[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)、[PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)。真实企业身份中心的网络、注册参数和证书链按第二阶段逐租户联调。
