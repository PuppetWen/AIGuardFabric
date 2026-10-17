import { Collapse, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
export function SkillGuide() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Collapse style={{ marginBottom: 16 }} items={[{ key: 'review',
    label: text('Skill 评审、白名单与多人维护指南', 'Skill review, allowlists and collaborative editing'),
    children: <>
      <ol>
        <li>{text('确认顶部组织。个人用户可从资产台账登记 Skill；企业由采集器发现或提交申请，指定负责人和数据分级。搜索、审批状态筛选、名称和风险排序作用于全部记录，可翻页查看。',
          'Select the organization. Individuals can register a Skill in inventory; enterprises can discover it or submit an application with ownership and classification. Search, review filters, name/risk sorting and pagination cover all records.')}</li>
        <li>{text('“查看 / 评审”显示实际生命周期，只提供合法下一步。申请中 → 评审中 → 试用 → 生产。自动发现进入试用，仍待批准；生产资产先进入变更中再重新批准。填写负责人、分级及评审说明后保存。',
          'View / review shows the actual lifecycle and legal next steps: Requested → Under review → Trial → Production. Discovery starts in Trial and still requires approval. Production changes go through Changing before approval. Enter the owner, classification and review note.')}</li>
        <li>{text('“查看声明”维护域名和绝对路径白名单，支持含空格的 Windows 路径。每类最多 100 条，按回车添加；保存两个空列表会清空声明。归档和拒绝为终态，白名单只读。',
          'View declaration edits domain and absolute-path allowlists, including Windows paths with spaces. Press Enter to add up to 100 entries per list; two empty lists clear the declaration. Archived and Rejected are final, with read-only allowlists.')}</li>
        <li>{text('多人编辑或采集更新导致版本变化时，保存返回冲突并保留草稿。可核对当前记录，明确确认后加载最新版本，再修改保存。只读角色可查看，不能保存；切换组织或账号会关闭原编辑窗口。',
          'If another edit or collection changes the revision, a conflict retains the draft. Compare the record, confirm loading the latest version, then edit and save again. Read-only roles can inspect but cannot save. Switching organization or account closes the previous editor.')}</li>
      </ol>
      <Typography.Paragraph>{text('批准、拒绝和归档显示实际认证操作人及时间；旧数据没有历史证据时保持未知。台账审批与声明白名单不自动执行安装、进程停止、凭据回收或出网拦截。需在对应端点和运行时策略中配置并验证实际控制效果。',
        'Approval, rejection and archival show the authenticated actor and recorded time; older records without evidence stay Unknown. Inventory review and declared allowlists do not install software, stop processes, revoke credentials or enforce egress automatically. Configure and verify actual controls in the endpoint and runtime policies.')}</Typography.Paragraph>
    </>,
  }]} />;
}

