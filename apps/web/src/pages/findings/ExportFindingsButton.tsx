import { useState } from 'react';
import { Button, message } from 'antd';
import { ExportOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { callApi } from '@/api/transport';
import { findingQuery } from '@/api/findingQuery';
import type { Finding, Paged } from '@/types/domain';
import { downloadText } from '@/utils/download';
import { useAuthStore } from '@/stores/authStore';

export function ExportFindingsButton({ filter }: { filter: { severity: string[]; domain: string[]; status: string[] } }) {
  const { t, i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const [busy, setBusy] = useState(false);
  const exportRows = async () => {
    setBusy(true);
    const tenant = useAuthStore.getState().tenant;
    try {
      const rows = new Map<string, Finding>();
      let expected = 0;
      for (let page = 1; page === 1 || page <= Math.ceil(expected / 200); page += 1) {
        if (useAuthStore.getState().tenant !== tenant) throw new Error(zh ? '空间已切换，请在当前空间重新导出' : 'Workspace changed; restart the export');
        const response = await callApi<Paged<Finding>>('/api/v1/findings', () => { throw new Error('Export unavailable'); }, {
          noFallback: true, query: findingQuery(filter, { page, pageSize: 200, sortBy: 'createdAt', sortOrder: 'asc' }),
        });
        if (page === 1) expected = response.data.total;
        for (const row of response.data.items) rows.set(row.id, row);
      }
      if (useAuthStore.getState().tenant !== tenant || rows.size !== expected) {
        throw new Error(zh ? '导出期间数据或空间发生变化，请重试' : 'Data or workspace changed during export; please retry');
      }
      downloadText(`findings-${new Date().toISOString().replace(/[:.]/g, '-')}.json`, JSON.stringify({
        generatedAt: new Date().toISOString(), tenant, filters: filter, total: rows.size, items: [...rows.values()],
      }, null, 2));
    } catch (reason) { void message.error(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  };
  return <Button icon={<ExportOutlined />} loading={busy} onClick={() => void exportRows()}>{t('findings.export')}</Button>;
}
