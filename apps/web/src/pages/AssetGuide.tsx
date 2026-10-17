import { Collapse, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

export function AssetGuide() {
  const { i18n } = useTranslation();
  const text = (zh: string, en: string) => i18n.language.startsWith('zh') ? zh : en;
  return <Collapse style={{marginBottom:16}} items={[{key:'inventory',label:text('资产接入、筛选与评审指南','Inventory, filtering and review guide'),children:<>
    <ol>
      <li>{text('无法自动采集时，点击“登记资产”，填写唯一资产标识、负责人、分级和用途。登记进入申请中，从详情发起评审，再进入试用和生产。若之后要自动归并，采集器应上报相同 fingerprint。',
        'For assets without automatic discovery, Register asset with a unique inventory key, owner, classification and purpose. The application starts in Requested; review it before Trial and Production. Later discovery merges when it reports the same fingerprint.')}</li>
      <li>{text('确认顶部租户。个人可使用自己的组织；企业按组织分配账号和采集凭据。在“操作指南 → 终端采集器”下载并上报，在“模型网关”和“MCP 管理”添加端点，云资源从“阿里云集成”盘点。',
        'Select the tenant first. Personal users can use their own organization; enterprises assign accounts and collection keys per organization. Upload discovery from Guide → Endpoint collector, add endpoints in Model gateway or MCP management, and inventory cloud resources in Alibaba Cloud.')}</li>
      <li>{text('输入名称、负责人或标签后按回车。类型、部门、分级、生命周期和暴露面可组合多选；同一项内为“任一”，不同项间为“同时满足”。部门支持直接输入。筛选自动回到第一页，风险排序作用于全部结果。',
        'Enter a name, owner or tag and press Enter. Combine type, department, classification, lifecycle and exposure filters. Values within a filter use OR; different filters use AND. Type a department if needed. Filtering returns to page one and risk sorting covers all results.')}</li>
      <li>{text('点击名称或详情查看画像、依赖和最近变更。有资产写权限的用户可用“更正资产资料”修改名称、负责人、部门和分级，并填写原因；“评审与生命周期”单独控制状态流转。生产资产需先进入变更中再重新评审；过期表单会拒绝覆盖。',
        'Open a name or Detail for the profile, dependencies and recent changes. Users with asset write permission can Edit asset details and record a reason; Review lifecycle controls status separately. Move production assets to Changing before reviewing them again. Stale forms cannot overwrite newer records.')}</li>
      <li>{text('确需从当前台账移除时，先将资产评审为“归档”或“拒绝”，再在详情选择“从当前台账移除”，输入准确名称和原因。历史与审计保留；仍在上报的相同指纹会重新出现。',
        'To remove a record from current inventory, review it into Archived or Rejected, then choose Remove from current inventory in its detail. Type the exact name and a reason. History and audit remain; the same fingerprint reappears if collection continues.')}</li>
      <li>{text('同一指纹重复采集会更新发现信息，保留人工评审结果。页面成功保存后即可在其他实例查看；离线演示的数据只在当前进程中。找不到资产时先重置筛选、确认租户及采集上报结果。',
        'Discovery with the same fingerprint refreshes observed data while retaining reviewed governance. Successful database writes are visible to other instances; offline demo data remains process-local. If an asset is missing, reset filters and check the tenant and collector upload result.')}</li>
    </ol>
    <Typography.Paragraph>{text('“每日资产检测”按 UTC 自动执行，服务停机后对比上次成功快照补做当日检测。首次建立基线不报漂移；同一天重复获取返回原记录。打开日期可查看前后值并进入资产详情。内容哈希变化需要人工核对，采集器须先上报 content_sha256。离线模式不提供每日检测。',
      'Daily inventory runs in UTC and catches up against the last successful snapshot after downtime. The first run establishes a baseline; repeated requests on the same day return that record. Open a date for before/after values and asset links. Content hash changes require review and a collector reporting content_sha256. Daily inventory is unavailable offline.')}</Typography.Paragraph>
    <Typography.Paragraph>{text('生命周期维护台账状态。停用应用、回收权限和删除源数据应在相应管理入口执行。',
      'Lifecycle review updates inventory state. Stop applications, revoke access and remove source data in their respective management screens.')}</Typography.Paragraph>
    <Typography.Paragraph>{text('Windows 采集器同时观察 Skill 入口文件及整个目录，包括脚本、隐藏文件、名称和空目录。详情显示接收时间、完整文件数、字节数或不可用原因。首次目录观察建立基线；后续变化需人工核对。读取失败时上次完整观察仍单独保留，用于恢复后的比较。单文件 4 MiB、总量 64 MiB、4096 个文件、8192 项、16 层；不沿符号链接或目录联接读取。修复显示原因后重新采集。这不是实时或原子快照，不包含 ACL、权限及 NTFS 备用数据流。',
      'The Windows collector observes the manifest and whole Skill directory, including scripts, hidden files, names and empty directories. Detail shows receipt time, complete file/byte counts or an unavailable reason. The first directory observation establishes a baseline; later changes need review. A failed scan retains the historical complete observation for comparison after recovery. Limits: 4 MiB per file, 64 MiB total, 4096 files, 8192 entries and 16 levels. Links and junctions are not followed. Correct the displayed cause and collect again. This is not live monitoring or an atomic snapshot; ACLs, permissions and NTFS alternate data streams are excluded.')}</Typography.Paragraph>
    <Typography.Paragraph>{text('“风险分”只显示已保存的风险评分，没有评分显示“未知”，不会用暴露面分数代替；已测量的 0 分仍显示 0。“暴露面”依明确的网络位置显示，不能从分数推断联网范围，可筛选“未知”补充核对。“未处置发现”统计当前组织已保存的待复核、代码复核和已验证发现，不含已修复、误报和已删除项。没有发现读取权限时显示未知；0 只表示当前没有此类已保存发现，不证明已经扫描或安全。',
      'Risk score shows a saved risk assessment; missing scores stay Unknown and measured zero stays 0. Exposure points do not determine network reachability: use the Unknown exposure filter to find missing network metadata. Open findings counts saved pending, code-reviewed and verified findings in this organization, excluding fixed, false-positive and deleted records. Without findings read access the count is Unknown. Zero does not prove the asset has been scanned or is safe.')}</Typography.Paragraph>
    <Link to="/guide">{text('打开平台接入指南','Open platform onboarding guide')}</Link>
  </>}]} />;
}
