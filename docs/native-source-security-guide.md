# 日志接入的来源限制与双向 TLS / Source access controls

## 个人用户：先验证接入，再缩小来源范围

1. 打开“日志接入 → 接入日志源”，选择原生接收器，填写名称并选择解析模板。
2. Syslog 与 OTLP 的“允许的来源网段”每行填写一个 IPv4/IPv6 CIDR，例如 `192.168.1.0/24`、`2001:db8::/32`；单台 IPv4 使用 `/32`，IPv6 使用 `/128`，最多 64 条。留空表示不在此源限制 IP。
3. 保存后打开“接入指南”，复制当前租户与源 ID 的部署配置。发送一条测试日志，检查“累计保存”和解析结果。
4. 网络白名单针对接收器看到的直接连接地址。经过反向代理、Docker NAT 或负载均衡时可能是代理地址。`X-Forwarded-For`、`X-Real-IP`、OTLP resource 和日志正文中的地址均不能改变这一判断。不要把扩大白名单当作解决未知地址的办法，先核对网络拓扑。
5. 源配置保存后，下一条报文/批次立即读取新策略；已开始处理的批次可能完成。更新白名单不需要重启。UDP 没有拒绝回执，调整前暂停发送端，或选用支持重试的 OTLP。

## 企业用户：配置客户端证书

Syslog TLS 和 OTLP/gRPC 支持双向 TLS。OTLP/HTTP 是原生 HTTP 监听器，控制台只提供 CIDR，不能用伪造证书请求头启用 mTLS。HTTP 部署的入口 TLS 策略由可信网关独立负责。

1. 由企业 CA 签发服务端证书和客户端证书；服务端 SAN 包含客户端连接时使用的 DNS/IP，客户端证书包含 clientAuth 用途。私钥留在各自主机，不填写在控制台。
2. 只读挂载证书目录。例如 Compose 覆盖文件中的以下片段，须与现有配置合并，保留其他源 ID：

```yaml
services:
  agf-ingest:
    volumes:
      - ./certs/ingest:/run/ingest-certs:ro
    environment:
      AGF_SYSLOG_TLS_PORT: "6514"
      AGF_SYSLOG_TLS_CERT: /run/ingest-certs/server.crt
      AGF_SYSLOG_TLS_KEY: /run/ingest-certs/server.key
      AGF_SYSLOG_TLS_CLIENT_CA: /run/ingest-certs/client-ca.crt
    ports:
      - "6514:6514/tcp"
```

3. OTLP/gRPC 使用以下变量代替 Syslog 变量，并发布实际 gRPC 监听端口（通常 `4317:4317/tcp`）。日志、链路与指标共用监听器证书，但有各自的源绑定和白名单：

```text
AGF_INGEST_OTLP_GRPC_ENABLED=1
AGF_INGEST_OTLP_GRPC_TLS=1
AGF_INGEST_OTLP_GRPC_TLS_CERT=/run/ingest-certs/server.crt
AGF_INGEST_OTLP_GRPC_TLS_KEY=/run/ingest-certs/server.key
AGF_INGEST_OTLP_GRPC_TLS_CLIENT_CA=/run/ingest-certs/client-ca.crt
```

4. 在源编辑页开启“要求已验证的客户端证书”。此项不会替你生成、挂载或加载证书；未完成监听器配置的请求会被拒绝。指南生成的 Compose 会列出所需环境变量。
5. 重建/重启接收器以加载证书文件，查看 `/readyz` 的 listeners 与 notes。CA、私钥或证书错误时对应 TLS 监听器不启动；不会退回明文。仅配置服务端证书与密钥属于单向 TLS，不能满足源的客户端证书要求。
6. 给发送端配置服务端 CA、自己的客户端证书与私钥。先测试可信客户端，再测试不带证书、错误 CA 和白名单外的连接：后三者都不能增加已保存日志数。OTLP 的来源策略拒绝返回 HTTP 403 / gRPC PermissionDenied，握手拒绝则由 TLS 客户端报告。

提供客户端 CA 后，整个监听器强制验证证书，即便某个源关闭了 requireMtls 也不会放松 TLS 握手。证书更新需要重启接收器；源白名单和启停则动态生效。现有连接仍按握手时证书状态运行，证书撤销/轮换时应重启监听器终止旧连接。

Kafka、Pulsar、NATS、MQTT 与拉取接收器看到的是消息代理/上游服务，不能从消息中验证最初发布者的 IP。配置其账号、主题权限、TLS 及上游网络白名单；控制台拒绝为这些源保存无法执行的 CIDR/mTLS 限制。需要接入多个组织时分别部署租户采集实例与信任域。

## English quick start

Native Syslog and OTLP sources accept up to 64 IPv4/IPv6 CIDRs, one per line. Empty means unrestricted. The pipeline checks the actual socket address; forwarded headers and payload fields cannot override it. Include the network address as observed after any proxy or NAT. Saved policy is loaded on every batch, including existing connections and empty OTLP exports; an already running batch can finish.

For mutual TLS, configure a server certificate/key and client CA on Syslog TLS or OTLP/gRPC, mount all PEM paths read-only, restart the receiver, and then enable **Require a verified client certificate** in the source editor. The variable names and Compose example above are directly usable after replacing paths. Use an enterprise CA, correct server SANs, and clientAuth certificates. Validate a trusted sender and negative cases without a certificate, with an untrusted certificate, and outside the CIDR allowlist. Invalid TLS material prevents that listener from starting; check `/readyz`.

Supplying a client CA makes certificate verification mandatory for the whole listener. Disabling the source flag does not weaken that handshake. Restart to reload certificates and terminate connections when rotating/revoking credentials. OTLP/HTTP supports the CIDR control; its native listener does not trust certificate headers. Configure TLS at your gateway separately. Broker and pull sources require upstream access controls; unsupported per-source restrictions are rejected explicitly. Read-only users can view the guide and current settings but cannot edit, pause, delete or poll sources.

Implementation references: [tonic Request connection metadata](https://docs.rs/tonic/0.14.5/tonic/struct.Request.html), [rustls client certificate verification](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html).
