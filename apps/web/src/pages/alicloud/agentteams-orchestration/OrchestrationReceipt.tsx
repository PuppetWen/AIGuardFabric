import { Alert, Button, Descriptions, Input, Space, Typography } from 'antd';
import { useText, uuid } from './text';
import type { OrchestrationFlow } from './useOrchestration';

export function OrchestrationReceipt({ flow }: { flow: OrchestrationFlow }) {
  const t = useText(), value = flow.receipt;
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{t('查询原编排请求回执', 'Read the original orchestration request receipt')}</Typography.Title>
    <Input aria-label={t('原编排请求 UUID', 'Original orchestration request UUID')} value={flow.requestId} disabled={flow.writeLocked}
      placeholder="UUID" onChange={event => flow.changeRequest(event.target.value)} />
    <Button loading={flow.reading} disabled={!uuid(flow.requestId) || flow.reading} onClick={() => void flow.readReceipt()}>
      {t('读取原回执（GET，不重新同步）', 'Read the original receipt (GET, no repeat sync)')}
    </Button>
    {flow.recovery && <>
      <Alert type={flow.recovery.phase === 'committed' ? 'info' : 'warning'} message={`${t('原请求状态', 'Original request state')}: ${flow.recovery.phase}`}
        description={t('发送结果未知时保留原 UUID 和内容并锁定写入。404 不能证明请求未提交；只能继续读取原回执。已提交或明确拒绝后才可人工开始新动作。',
          'An unknown outcome retains the original UUID and content and locks writes. A 404 cannot prove the request was not committed; keep reading its receipt. Start a new action manually only after a committed receipt or an explicit rejection.')} />
      <Button disabled={flow.busy || flow.reading || !['committed', 'rejected'].includes(flow.recovery.phase)} onClick={flow.beginNew}>
        {t('明确开始新动作（保留草稿基线）', 'Start a new action explicitly (keep draft baseline)')}
      </Button>
    </>}
    {value && <Descriptions title={t('不可变原始回执', 'Immutable original receipt')} column={1} items={[
      { key: 'id', label: 'UUID', children: value.requestId }, { key: 'team', label: 'Team', children: value.teamName },
      { key: 'status', label: t('本地提交', 'Local commit'), children: value.status },
      { key: 'version', label: t('原提交版本', 'Original committed revision'), children: value.version },
      { key: 'config', label: t('原配置版本', 'Original configuration revision'), children: value.source.configurationVersion },
      { key: 'hash', label: t('请求摘要', 'Request digest'), children: value.bodyHash },
      { key: 'local', label: t('原本地节点数', 'Original local node count'), children: value.localNodeCount ?? t('未知', 'Unknown') },
      { key: 'receiver', label: t('原接收端节点数', 'Original receiver node count'), children: value.receiverNodeCount ?? t('未知', 'Unknown') },
      { key: 'durability', label: t('持久边界', 'Durability boundary'), children: value.durable ? t('数据库跨实例', 'Database across instances') : t('当前进程内存', 'Current process memory') },
      { key: 'provider', label: t('厂商调用', 'Vendor call'), children: t('未调用', 'Not called') },
      { key: 'consumer', label: t('消费者执行', 'Consumer execution'), children: t('未知', 'Unknown') },
    ]} />}
  </Space>;
}
