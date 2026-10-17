import { Alert, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

export default function MseInventoryGuide() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Space direction="vertical" size={8}>
    <Typography.Paragraph>{text('在阿里云连接选择 MSE → 配置。填写地域和实例 ID，明确选择默认命名空间或指定命名空间 ID；默认发送 namespace_id 空字符串。未选择不是默认。保存后打开本页，先使用 Mock 验证流程。',
      'Open the MSE cloud connection → Configure. Enter the region and instance ID and explicitly choose Default namespace or a specific namespace ID. Default sends an empty namespace_id; no selection is not the default. Save, open this page and verify the flow with Mock first.')}</Typography.Paragraph>
    <Typography.Paragraph>{text('查看清单和原请求只需 alicloud:read，不调用云端。连接配置需 alicloud:write。新盘点、取消和本地归档需 alicloud:read、alicloud:write、assets:write。真实凭据仅需厂商 ListAnsServices 只读权限；真实盘点须人工确认范围。',
      'Viewing inventory and original receipts requires alicloud:read and does not contact cloud. Connection configuration requires alicloud:write. Inventory, cancellation and local archive require alicloud:read, alicloud:write and assets:write. Provider credentials need read-only ListAnsServices permission; confirm the scope explicitly before a live inventory.')}</Typography.Paragraph>
    <Typography.Paragraph>{text('点击一次完整盘点后保存原请求 UUID。断线、超时或失败时点击“读取原请求回执”，不要重复提交。正在运行可显式取消，取消不撤回已发送的只读页。关闭页面不取消请求；可在最近50条记录或原编号输入框恢复。核对终态后点“准备新盘点”才使用新编号。409 时先刷新本地清单、读取原请求，核对范围或取消旧请求。',
      'After starting one full inventory, retain its request UUID. On disconnection, timeout or failure use Read original request receipt; do not resubmit. Cancel a running request explicitly; an already-sent read page cannot be recalled. Closing the page does not cancel it. Restore from the recent 50 records or the request ID input. After checking a terminal receipt, Prepare new inventory uses a new ID. On HTTP 409 refresh local inventory, read the original receipt and check the scope or cancel the old request.')}</Typography.Paragraph>
    <Alert showIcon type="info" message={text('最多20页、每页100项、2000项、110秒；仅按公开接口完成分页，不承诺云端多页强一致。未知计数、地址、协议、运行环境、网络区域和授权仍显示未知。Mock 或发布成功不证明授权。',
      'At most 20 pages, 100 entries per page, 2000 services and 110 seconds. Complete pagination does not establish a strongly consistent cloud snapshot. Missing counts, endpoint, protocol, runtime, network zone and authorization remain unknown. Mock or successful publication does not establish authorization.')} />
    <Typography.Paragraph>{text('发布保留人工名称、类型、负责人、标签、分类和生命周期；云清单未出现的服务只标记未观察，不删除。通过资产链接补充治理。台账上限512次请求/4MiB；选择已终态且可归档的记录，核对数量后显式归档。租约过期但未终态需先取消；归档不改云、资产或最新快照，原编号仍可读取且永不再次派发。停用配置后仍可查询、取消和归档。',
      'Publication preserves manual names, types, owners, labels, classification and lifecycle. Unlisted services become unobserved and are not deleted. Use asset links to complete governance. The active ledger holds 512 requests/4 MiB. Select archivable terminal records and confirm the count explicitly. Cancel an expired but nonterminal request first. Archive changes neither cloud, assets nor the latest snapshot; the original ID stays readable and never dispatches again. Reads, cancellation and archive remain available after disabling the configuration.')}</Typography.Paragraph>
    <Typography.Paragraph>{text('范围摘要表示当前配置来源，不是已验证的 RAM 账号。换版本/账号/实例/命名空间/模式后旧回执保留来源，旧快照不会显示为新范围清单。失败时不自动发送新盘点或自动归档。',
      'The scope digest represents configured credentials, not a verified RAM account. Old receipts retain their source after version/account/instance/namespace/mode changes; old snapshots do not appear as the new scope. Failures never trigger automatic new inventory or archive.')}</Typography.Paragraph>
    <Link to="/assets">{text('打开资产台账', 'Open asset inventory')}</Link>
  </Space>;
}
