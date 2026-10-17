# 手机扫码登录

这是平台自己的跨设备登录：已登录的手机批准新浏览器登录。二维码只含租户和一次性请求编号，不含访问令牌、密码或 MFA 验证码。若企业身份服务本身提供扫码登录，可继续从平台的 OIDC 或 SAML 按钮跳转到该身份服务；厂商原生扫码需在真实身份服务中另行联调。

1. 先在手机上登录同一租户的控制台，并在“账号安全”启用**平台 MFA**。首次登录要求改密或要求先绑定 MFA 的受限会话不能批准二维码。手机和新浏览器都应使用可互访的同一个控制台域名；从手机无法访问电脑的 `localhost` 地址。
2. 在新浏览器登录页填写租户标识，点击“手机扫码登录”。页面显示二维码和可复制的手机确认链接，3 分钟后失效。不要在共享屏幕上长期展示二维码。
3. 用已登录的手机扫描。确认页面上的租户和当前账号，只有自己刚刚发起登录才输入当前平台 MFA 验证码或恢复码并点击“批准这次登录”。最多允许 5 次验证尝试；恢复码一经验证会被消费。
4. 返回新浏览器等待自动完成登录。平台重新签发只属于新浏览器的会话；手机原有会话不会被复制。用户被停用、平台 MFA 被关闭、租户不一致、错误浏览器绑定、重复提交或二维码过期时，登录被拒绝。若网络断开或页面关闭，重新生成二维码即可。
5. 在“审计”中检查手机批准和新浏览器登录记录。企业管理员可先用只读测试成员试运行，再逐步推广。

常见问题：

- 手机提示“请先启用平台 MFA”：回到“账号安全”完成绑定，再重新生成二维码。
- 手机提示租户不匹配：先在手机登录二维码显示的租户；平台超管切换工作租户不等于切换身份租户。
- 电脑提示已过期或无效：刷新二维码，不要重复使用旧截图或旧链接。
- 手机打不开链接：将电脑登录页改为手机也能访问的 HTTPS 域名或局域网地址，检查防火墙和反向代理。

English quick path: Sign in on the phone to the same tenant and enable platform MFA under **Account security**. On the new browser, enter the tenant and choose **Sign in with phone QR code**. Scan the three-minute code, verify the tenant and account, enter a current platform MFA or recovery code, and explicitly approve. The new browser receives its own session; the QR code never carries a token. Check audit events and regenerate the code if it expires.
