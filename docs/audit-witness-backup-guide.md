# 审计见证部署、备份与恢复

本指南和脚本候选尚未执行真实数据库恢复或部署验收。见证是数据库外的持久数据，位于项目内 `AGF_DATA_DIR/audit-witnesses-v1`；清理编译、测试和历史镜像时必须保留生产见证。

## 首次部署

在项目根执行 `scripts/prepare-audit-data.ps1 -WhatIf` 核对路径，再执行 `scripts/prepare-audit-data.ps1`。路径从进程环境、`.env` 和既有 `scripts/env.ps1` 读取，必须位于项目内；编译、测试和缓存目录及链接/重解析路径会被拒绝。已有目录必须含精确 `.owner`，空的或其他归属的目录不能自动接管。本入口只创建归属标记，不生成检查点或可信见证。

`AGF_DATA_DIR` 也不能位于项目 `data/seed`、`data/uploads`、`data/fixtures` 或其子树，避免普通数据恢复覆盖实时见证。普通归档源逐层拒绝链接/重解析点，归档前后均检查，压缩包中任何 `audit-witnesses-v1` 路径段均拒绝。运维方仍须静止写入并控制目录ACL；这些检查不承诺防御有权限同时替换路径的恶意管理员。

标准及offline server镜像以 **10001:10001** 运行。Linux宿主须让这个用户拥有新建的见证目录及其中 `.owner`：目录0700，文件0600。初始化应由受控运维账号执行，随后只对这个已核实的目录及其文件设置10001:10001所有者；不能递归修改整个项目或清空已有见证。Windows须事先保护持久数据目录ACL，脚本继承该ACL。恢复到全新宿主后也必须检查这些权限。

两份Compose均把宿主持久目录绑定至server的 `/data/audit-witnesses-v1`，显式可写且 `create_host_path:false`；生产根文件系统仍只读。启动前必须准备目录，不能依赖Docker自动创建空目录。Helm的 `/data` 已由既有 evidenceVolume覆盖，必须启用持久PVC，禁止将审计部署在临时emptyDir。见证必须和数据库独立保存；仅备份数据库不能满足回滚检测要求。

## 备份合同

`scripts/backup.ps1 -Keep 0` 面向主Compose正在运行的PostgreSQL服务，优先读取实际Compose使用的AGF_PG_USER/AGF_PG_DB，并兼容旧POSTGRES_*配置；进程环境优先于.env。生产编排的外部托管数据库须另行协调其受控数据库备份，不能将本入口当作托管库sidecar验收。成功退出0才可使用产物。备份根为项目 `data/backup/yyyyMMdd-HHmmss-UUID/`，含 `.agf-backup-owner`、`agf.dump`、普通可选 `data-files.zip`、`MANIFEST.txt`、`README.txt`、`AUDIT-WITNESSES.json` 和最后创建的 `BACKUP-COMPLETE.json`。`-Keep 0`不清理任何历史备份。其他保留数只允许删除本版本具有精确归属和完成标记的备份，旧无标记包全部保留。

`AUDIT-WITNESSES.json` 的Version=1，State为PRESENT或ABSENT_UNINITIALIZED，Files为完整的Name/Length/Sha256数组，Fingerprint为该有序数组UTF8 JSON的SHA256，CreatedUtc为UTC时间。PRESENT时，`audit-witnesses-v1/`保存 `.owner`、各链JSON和空锁文件的原字节；文件名、4096文件上限和每个JSON16KiB上限均与受控见证布局核对。未知文件、暂存写入、链接或归属不符使备份失败。ABSENT_UNINITIALIZED明确不声称已有可信见证。

`BACKUP-COMPLETE.json` 的Version=2、Status=COMPLETE，并含CompletedUtc、WitnessState、大写WitnessManifestSha256、ManifestSha256、DatabaseDumpSha256及DatabaseDumpBytes。部署门禁必须核对该SHA、实际manifest及每个见证文件，不能仅凭目录名或控制台输出接受备份。不完整包保留供检查，不能用于部署回滚。

数据库导出前后及复制后核对同一见证完整集合；见证推进时备份明确失败，应静止审计写入后重试。`-SkipData`只跳过seed/uploads/fixtures，**仍保留见证**。归档SHA用于传输完整性，不构成签名信任。必须保护备份ACL及原平台主密钥；主密钥不写进这个备份。

## 恢复合同

先把可信备份完整复制到项目内受控目录。`scripts/restore.ps1 -BackupFile <备份目录> -WhatIf`会先只读核对文件清单、见证包、现有见证归属和可选普通数据ZIP路径。真实恢复保留既有交互确认和自动前置备份；本候选不执行任何真实恢复。

现场已有见证时，脚本始终保留现场原字节，**不使用旧备份覆盖或降低进度**。现场见证不存在时，脚本仅复制备份原字节到同数据目录下的独占暂存根，校验后原子移动至缺失目标；不重签、不创建虚构检查点、不覆盖并发出现的目标。暂存失败时保留原字节供核查，不能把残留目录当作可清理的编译内容。

现场已有目录但缺少备份中的任一链JSON时，数据库恢复前明确拒绝，不能把只有 `.owner` 的初始化目录当作已有链见证，也不会自动补链。全新宿主应先恢复到尚未初始化的目标，再执行 `prepare-audit-data.ps1` 验证；已有现场缺链时必须保留所有原字节另行核查，不能删除见证绕过拒绝。

无见证的旧包只在现场已有有效归属见证或显式 `-AllowUnanchoredLegacy` 时接受。该参数仅承认历史未锚定状态，不生成或伪造可信证明。普通数据ZIP只允许seed/uploads/fixtures，拒绝路径逃逸、链接和见证覆盖。

恢复期间应停止相关写入，恢复后使用**原可信主密钥**核验 `GET /api/v1/audit/verify` 与相关Agent链。数据库较旧而现场见证较新时，运行时应拒绝签名和允许结果；不能删除见证、重建检查点或换密钥让旧数据库通过。真正需要恢复更早业务状态时，须另行审查与保留完整的受信审计历史。PowerShell复制校验不会代替运行时HMAC/完整链验证。

仍待真实验收：同源Native全部门禁、独占SQL及其后实际备份/恢复演练、10001用户挂载写入、容器重启后见证保持与审计链验证。本地合成合同用例不等于这些验收通过。
