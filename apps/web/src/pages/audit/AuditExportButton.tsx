import { useState } from 'react';
import { Button, message } from 'antd';
import { ExportOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

import { callApi } from '@/api/transport';
import { useAuthStore } from '@/stores/authStore';
import type { AuditEntry, Paged } from '@/types/domain';
import { downloadText } from '@/utils/download';

interface AuditFilters {
  keyword?: string;
  actor?: string;
  outcome?: string;
  sensitive_only?: boolean;
}

/** Export the full filtered chain in stable sequence order, not just the visible page. */
export function AuditExportButton({ filters }: { filters: AuditFilters }) {
  const { t, i18n } = useTranslation();
  const [busy, setBusy] = useState(false);

  const exportRows = async () => {
    setBusy(true);
    const session = useAuthStore.getState();
    const tenantId = session.tenant?.id;
    const sessionGeneration = session.sessionGeneration;
    try {
      const rows = new Map<string, AuditEntry>();
      let total = 0;
      for (let page = 1; page === 1 || (page - 1) * 200 < total; page += 1) {
        const current = useAuthStore.getState();
        if (current.tenant?.id !== tenantId || current.sessionGeneration !== sessionGeneration) {
          throw new Error(i18n.language.startsWith('zh')
            ? '登录会话或租户已切换，请重新导出'
            : 'Session or tenant changed; restart the export');
        }
        const response = await callApi<Paged<AuditEntry>>('/api/v1/audit', () => {
          throw new Error('Audit export requires a connected server');
        }, {
          noFallback: true,
          query: { ...filters, page, pageSize: 200, sortBy: 'sequence', sortOrder: 'asc' },
        });
        if (page === 1) total = response.data.total;
        for (const row of response.data.items) rows.set(row.id, row);
      }
      if (rows.size !== total) {
        throw new Error(i18n.language.startsWith('zh')
          ? '导出期间审计数据发生变化，请重试'
          : 'Audit data changed during export; please retry');
      }
      downloadText(`audit-${new Date().toISOString().replace(/[:.]/g, '-')}.json`, JSON.stringify({
        generatedAt: new Date().toISOString(),
        tenantId,
        filters,
        total,
        items: [...rows.values()],
      }, null, 2));
    } catch (error) {
      void message.error(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  return <Button aria-label={t('audit.exportAll')} icon={<ExportOutlined />} loading={busy} onClick={() => void exportRows()}>
    {t('audit.exportAll')}
  </Button>;
}
