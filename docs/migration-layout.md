# 数据库迁移与历史 0001 分片

服务启动和 `agfctl migrate` 使用同一套内嵌 SQLx 迁移。历史版本 0001 原来是一个 1663 行的文件；现在按原始字节拆成 `deploy/sql/migration_parts/0001_init_01.sql` 至 `0001_init_04.sql`。程序按文件编号顺序拼接，不插入换行，也不修改 SQL。合并后的 SHA-384 是 `5de7ec35232cd1e5ce4ff653c17236ca93a25df6482b3660d37a96e84d483f42d9be9d2482fd98bc60028de7c373564d`，与已部署数据库 `_sqlx_migrations` 中版本 1 的校验和相同。其它版本仍在 `deploy/sql/migrations/`，以后只新增版本，不改 0001 分片。

| 分片 | 原文件行号 | 分片内行号 |
|---|---:|---:|
| `0001_init_01.sql` | 1–420 | 1–420 |
| `0001_init_02.sql` | 421–840 | 1–420 |
| `0001_init_03.sql` | 841–1260 | 1–420 |
| `0001_init_04.sql` | 1261–1663 | 1–403 |

个人和企业部署都使用 `docker compose up -d`，服务会自动迁移。需要在服务启动前手动迁移时，运行 `agfctl migrate`；程序已内嵌完整项目迁移，从任意工作目录执行都不需要携带 SQL 文件，但仍须通过项目 `.env`、进程环境变量或 `--url` 提供数据库连接信息。`agfctl migrate --dir deploy/sql/migrations` 也会识别项目默认目录并使用相同的内嵌 0001。`--dir` 指向其它位置时按 SQLx 常规规则读取该目录，使用者须提供完整的迁移集。不要把项目的 `deploy/sql/migrations/` 直接交给 `sqlx migrate run` 或 PostgreSQL `/docker-entrypoint-initdb.d`：该目录没有独立的 0001 文件。不要把四个分片分别作为 SQL 脚本执行。

核对已有库可以查询 `SELECT version, encode(checksum, 'hex') FROM _sqlx_migrations WHERE version = 1;`。运行 `agfctl migrate` 后，旧库应维持版本 1 的校验和并补齐新增迁移；新库应应用版本 1–19 并通过 `agfctl db check-schema`。`scripts/check-file-size.ps1` 现包含迁移和分片，所有受检源码文件必须不超过 500 行。生产执行前仍应先按[部署指南](deployment.md)备份数据库。

`agfctl db check-schema` 还检查所有含 `tenant_id` 的表：必须启用 RLS、保留预期的单一租户策略，运行角色不得是超级用户、不得拥有 BYPASSRLS 或直接登录权限，也不得通过表所有者身份绕过未强制 RLS 的表。命令在回滚事务中用两个租户标识验证策略函数；任一检查失败返回退出码 1，并列出异常表。该检查不能替代真实双租户业务 API 验收。

气隙交付使用 `agfctl airgap bundle --out <目录>`，清单必须同时包含 `deploy/sql/migrations/` 和 `deploy/sql/migration_parts/`。交付后运行 `agfctl airgap verify --dir <目录>` 检查文件哈希；运行数据库迁移仍使用随程序编译的 `agfctl migrate`，不要单独运行分片。
