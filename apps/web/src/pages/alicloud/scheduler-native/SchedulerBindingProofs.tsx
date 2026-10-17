import { useState } from 'react';
import { Alert, Button, Descriptions, Space, Table, Tag, Typography } from 'antd';
import type { Binding, BindingReason, BoundJob, SchedulerKind, SourceTarget } from './types';
import { useSchedulerText } from './text';

const REASONS: Record<BindingReason, readonly [string, string]> = {
  proof_unavailable: ['未提供可信采用证明', 'Trusted adoption proof is unavailable'],
  app_changed: ['观察到应用身份改变', 'Observed application identity changed'],
  job_missing: ['完整观察未找到所选任务', 'Selected job is absent from the complete observation'],
  job_disabled: ['观察到任务明确停用', 'Job was explicitly observed disabled'],
  job_not_http: ['观察到任务为已知非 HTTP 类型', 'Job was observed as a documented non-HTTP type'],
  job_type_unknown: ['任务类型未知', 'Job type is unknown'],
  job_status_unknown: ['任务启用状态未知', 'Job enabled status is unknown'],
};

export function SchedulerBindingProofs({ binding, reading, onRead }: {
  binding: Binding; reading: boolean; onRead: (id: string) => void;
}) {
  const t = useSchedulerText(), [open, setOpen] = useState<SchedulerKind | null>(null);
  const detail = binding.items.find(item => item.kind === open);
  const flag = (value: boolean | null) => value === null ? t('未知', 'Unknown') : value ? t('是', 'Yes') : t('否', 'No');
  const source = (value: SourceTarget) => `${value.region} · ${value.clusterId} · ${value.appName} · v${value.configurationVersion} · ${value.scopeId}`;
  const reason = (item: BoundJob) => item.reason && REASONS[item.reason] ? `${item.reason} · ${t(...REASONS[item.reason])}` : t('无 / 未提供', 'None / not provided');
  return <section aria-label={t('已保存关联与采用证明', 'Saved associations and adoption proofs')}>
    <Space direction="vertical" style={{ width: '100%' }}>
      <Typography.Title level={5}>{t('已保存的逐任务资格', 'Saved per-job qualifications')}</Typography.Title>
      <Descriptions size="small" column={2} items={[
        { key: 'revision', label: t('当前 CAS / 原采用版本', 'Current CAS / original adoption revision'), children: `CAS ${binding.version} · adoption ${binding.adoptionVersion}` },
        { key: 'status', label: t('总体关联状态', 'Overall association status'), children: binding.status },
        { key: 'current', label: t('总体当前关联（非回调授权）', 'Overall current association (not callback authorization)'), children: flag(binding.current) },
        { key: 'enabled', label: t('本地关联启用', 'Local association enabled'), children: flag(binding.locallyEnabled) },
        { key: 'source', label: t('来源 / 配置版本仍一致', 'Source / configuration version still matches'), children: flag(binding.sourceCurrent) },
        { key: 'verified', label: t('资格证明已认证', 'Qualification proof authenticated'), children: flag(binding.qualificationVerified) },
      ]} />
      <Typography.Paragraph>{t('总体 current=false 不代表每个 Job 都失去资格；请逐项检查。资格只描述本地可信证明，不证明回调授权已接入、云任务启用、部署就绪或实际运行。',
        'Overall current=false does not mean every job lost its qualification; review each item. Qualification describes a trusted local proof, not enforced callbacks, current cloud enablement, deployed readiness or execution.')}</Typography.Paragraph>
      {!binding.evidenceFresh && <Alert type="info" message={t('原观察的 300 秒采用窗口已过；已保存的资格不会因此过期',
        'The original 300-second adoption window elapsed; saved qualifications do not expire because of this')} />}
      {!binding.qualificationVerified && <Alert type="warning" message={t('旧关联没有可信证明：unverified。读取新正面证据不会自动获得资格，须重新观察并明确采用、保存。',
        'A legacy association without a trusted proof is unverified. Reading positive evidence does not grant qualification; explicitly reobserve, adopt and save.')} />}
      {!binding.sourceCurrent && <Alert type="warning" message={t('来源或配置版本已变化；保留的证明描述原来源，不授权当前来源。请重新完整观察后明确采用。',
        'Source or configuration version changed; retained proofs describe the original source, not authorization for the current source. Explicitly adopt after a new complete observation.')} />}
      <Table<BoundJob> size="small" rowKey="kind" pagination={false} dataSource={binding.items} columns={[
        { title: t('已保存任务 / 执行器', 'Saved kind / executor'), render: (_, item) => `${item.kind} → ${item.runtimeName}` },
        { title: 'JobId', dataIndex: 'jobId' },
        { title: t('本地资格', 'Local qualification'), render: (_, item) => <Tag color={item.eligibility === 'eligible' ? 'green' : item.eligibility === 'revoked' ? 'red' : 'gold'}>{item.eligibility}</Tag> },
        { title: t('原因', 'Reason'), render: (_, item) => reason(item) },
        { title: t('证据', 'Evidence'), render: (_, item) => <Button onClick={() => setOpen(open === item.kind ? null : item.kind)}>{t('查看资格证据', 'View qualification evidence')}</Button> },
      ]} />
      {detail && <section aria-label={t(`关联证明 ${detail.kind}`, `Association proof ${detail.kind}`)}>
        <Space direction="vertical" style={{ width: '100%' }}>
          {detail.eligibility !== 'eligible' && <Alert type="warning" message={t('此项须明确重新采用：即使最新完整证据显示任务已恢复，也不会自动恢复原资格。',
            'This item requires explicit readoption: even positive latest evidence does not automatically restore its qualification.')} />}
          <Descriptions size="small" column={1} title={t('资格决定（保留原撤销 / 未验证决定）', 'Qualification decision (original revocation / unverified decision retained)')} items={[
            { key: 'reason', label: t('资格 / 原因', 'Qualification / reason'), children: `${detail.eligibility} · ${reason(detail)}` },
            { key: 'observation', label: t('决定观察编号', 'Decision observation ID'), children: detail.decisionObservationId ?? t('未知', 'Unknown') },
            { key: 'at', label: t('决定时间', 'Decision time'), children: detail.decisionAt ?? t('未知', 'Unknown') },
          ]} />
          {detail.adoptedProof ? <>
            <Descriptions size="small" column={1} title={t('原始采用证明（不依赖归档正文）', 'Original adoption proof (independent of archived body)')} items={[
              { key: 'proof', label: t('证明 ID / 原采用版本', 'Proof ID / original adoption revision'), children: `${detail.adoptedProof.proofId} · ${detail.adoptedProof.adoptionVersion}` },
              { key: 'observation', label: t('原采用观察编号', 'Original adopted observation ID'), children: detail.adoptedProof.observationId },
              { key: 'at', label: t('原观察时间', 'Original observation time'), children: detail.adoptedProof.observedAt },
              { key: 'source', label: t('原采用来源', 'Originally adopted source'), children: source(detail.adoptedProof.sourceTarget) },
              { key: 'origin', label: t('原 RPC 地址 / 模式', 'Original RPC origin / mode'), children: `${detail.adoptedProof.sourceTarget.rpcOrigin} / ${detail.adoptedProof.sourceTarget.transportMode}` },
              { key: 'fingerprint', label: t('原来源指纹', 'Original source fingerprint'), children: detail.adoptedProof.sourceTarget.fingerprint },
              { key: 'app', label: t('原采用 AppId / JobId', 'Originally adopted AppId / JobId'), children: `${detail.adoptedProof.appId} / ${detail.adoptedProof.jobId}` },
              { key: 'evidence', label: t('采用时启用 / HTTP', 'Enabled / HTTP at adoption'), children: `${flag(detail.adoptedProof.enabled)} / ${flag(detail.adoptedProof.httpJob)}` },
            ]} />
            <Button disabled={reading} onClick={() => onRead(detail.adoptedProof!.observationId)}>{t('读取原采用观察（仅 GET）', 'Read original adopted observation (GET only)')}</Button>
          </> : <Alert type="info" message={t('原始采用证明未提供，资格未验证', 'Original adoption proof unavailable; qualification unverified')} />}
          <Typography.Paragraph>{t('下方是针对原采用来源的最新完整存储证据；GET 不读取云。它与资格决定独立，正面证据不撤销原负面决定。',
            'Below is the latest complete stored evidence for the adopted source; GET does not read cloud. It is separate from the qualification decision; positive evidence does not undo the original negative decision.')}</Typography.Paragraph>
          {detail.currentEvidence ? <>
            <Descriptions size="small" column={1} title={t('最近完整存储证据', 'Latest complete stored evidence')} items={[
              { key: 'observation', label: t('最新证据观察编号', 'Latest evidence observation ID'), children: detail.currentEvidence.observationId },
              { key: 'at', label: t('最新证据时间', 'Latest evidence time'), children: detail.currentEvidence.observedAt },
              { key: 'source', label: t('证据来源', 'Evidence source'), children: source(detail.currentEvidence.sourceTarget) },
              { key: 'origin', label: t('证据 RPC 地址 / 模式', 'Evidence RPC origin / mode'), children: `${detail.currentEvidence.sourceTarget.rpcOrigin} / ${detail.currentEvidence.sourceTarget.transportMode}` },
              { key: 'fingerprint', label: t('证据来源指纹', 'Evidence source fingerprint'), children: detail.currentEvidence.sourceTarget.fingerprint },
              { key: 'app', label: 'AppId', children: detail.currentEvidence.appId },
              { key: 'present', label: t('最新证据中找到 Job', 'Job present in latest evidence'), children: flag(detail.currentEvidence.jobPresent) },
              { key: 'kind', label: t('类型 / HTTP / 启用', 'Kind / HTTP / enabled'), children: `${detail.currentEvidence.jobKind ?? t('未知', 'Unknown')} / ${flag(detail.currentEvidence.httpJob)} / ${flag(detail.currentEvidence.enabled)}` },
            ]} />
            <Button disabled={reading} onClick={() => onRead(detail.currentEvidence!.observationId)}>{t('读取最新证据观察（仅 GET）', 'Read latest evidence observation (GET only)')}</Button>
          </> : <Typography.Text>{t('未提供最新完整证据；未知不能解释为停用或零任务', 'Latest complete evidence unavailable; unknown does not mean disabled or zero jobs')}</Typography.Text>}
        </Space>
      </section>}
    </Space>
  </section>;
}
