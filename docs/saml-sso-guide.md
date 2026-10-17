# 企业 SAML 2.0 登录接入

本指南适用于可导出 SAML 2.0 IdP 元数据 XML 的企业身份服务。平台仅支持 **SP 发起的浏览器登录**；不接受 IdP 主动推送登录。先在隔离或 Mock 环境完成测试，再接入真实企业身份服务。

1. 用有“设置写入”权限的管理员登录控制台，打开“设置 → SAML 2.0”。确认当前租户标识和浏览器实际使用的控制台域名。生产入口应为 HTTPS；仅 `127.0.0.1` / `::1` 等回环地址允许 HTTP。
2. 在 IdP 创建 SAML 应用。将表单显示的 **SP Entity ID / Metadata URL** 用作应用标识，把 **ACS URL** 用作回复地址。两个 URL 必须使用同一个控制台域名及当前租户路径。保存平台配置后，可点击“下载 SP 元数据”导入 IdP；平台会自动生成 SP 签名证书并加密保存私钥。
3. 在 IdP 中启用 **签名 AuthnRequest 验证** 和 **签名 SAML Response**。平台要求 Response 根元素的有效签名、正确的发行者、受众、接收地址、请求 ID、时间窗口和一次性 RelayState。IdP 可在已签名的 Response 内放置未单独签名的 Assertion。响应使用 HTTP-POST；登录请求使用 HTTP-Redirect。请先使用未加密的 Assertion；加密 Assertion 的兼容性需按具体 IdP 单独验收。
4. 在 IdP 配置稳定、不可变的 **NameID**。平台按“租户 + IdP Entity ID + NameID”绑定账号，不按邮箱合并已有本地管理员。可映射邮箱与显示名属性；默认属性名为 `email`、`displayName`。若设置允许邮箱域名，没有匹配邮箱的身份将被拒绝。
5. 从可信 IdP 管理界面复制完整 **IdP 元数据 XML**，粘贴到平台设置页。元数据必须包含 IdP Entity ID、HTTP-Redirect SSO 地址和签名证书。平台只使用管理员提交并保存在本租户的 XML，不在登录时自动访问元数据 URL 或接受未经审核的证书变更。
6. 首次试用建议开启“首次登录自动创建账号”，默认角色选“只读用户”。保存并启用后，打开登录页，填写租户标识并点击“SAML 企业登录”。在 IdP 完成身份验证后，浏览器返回本平台；若该账号启用了平台 MFA，还需输入验证码或恢复码。
7. 验证登录后的角色、租户、资源可见性和审计事件。分别测试错误签名、重复提交、错误租户、过期请求、停用平台账号、禁用 SAML 配置和平台 MFA。离线模拟 IdP 的自动化入口是 `cargo test -p agf-api --test saml_login`。

## 证书轮换与故障定位

- IdP 签名证书轮换时，从可信 IdP 管理界面重新复制元数据 XML 并保存。变更会生成新配置版本，使在途登录失效；用户须重新发起。
- 点击“轮换 SP 证书”后，立即从 SP 元数据 URL 获取新证书并更新 IdP。旧请求与旧证书不再可用；安排短维护窗口更稳妥。
- `SAML 登录事务无效或已使用`：检查是否在发起登录的同一标签页返回、是否超过 10 分钟、是否重复提交、租户或配置是否已变化。
- `SAML 身份验证未通过`：核对 IdP 元数据里的签名证书、Response 签名、Entity ID、SP Entity ID、ACS URL、时间同步和 HTTP-POST 绑定。不要在日志或工单中粘贴完整 SAMLResponse。
- `SAML 账号尚未纳管`：首次测试时启用自动创建；完成首次登录后，可关闭自动创建，已纳管成员仍可登录。平台不会按本地管理员邮箱隐式合并身份。

English quick path: Open **Settings → SAML 2.0**; create an IdP app with the displayed SP Entity ID and ACS URL; require signed AuthnRequests and signed Responses; paste trusted IdP metadata XML; use a persistent NameID and the viewer default role; save, enable, and sign in from **SAML enterprise sign-in**. Platform MFA remains in effect. Refresh pasted metadata for IdP certificate rotation; refresh SP metadata at the IdP after rotating the SP certificate.
