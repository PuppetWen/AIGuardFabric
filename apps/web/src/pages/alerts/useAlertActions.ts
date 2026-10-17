import { useEffect, useRef, useState } from 'react';
import { message } from 'antd';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '@/api/client';
import type { AlertStatus } from '@/types/domain';
import { useAuthStore } from '@/stores/authStore';

function identity() { const auth = useAuthStore.getState(); return `${auth.tenant?.id}:${auth.sessionGeneration}`; }

/** Each selected alert has an independent persisted result; failed IDs remain selected. */
export function useAlertActions(refresh: () => Promise<unknown>, select: (ids: string[]) => void) {
  const { i18n } = useTranslation();
  const cache = useQueryClient();
  const active = useRef(false);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const [busy, setBusy] = useState(false);
  const [failures, setFailures] = useState<string[]>([]);
  const update = async (ids: string[], status: AlertStatus) => {
    if (active.current || !ids.length) return;
    active.current = true; setBusy(true); setFailures([]);
    const startedFor = identity();
    const current = () => mounted.current && startedFor === identity();
    const failed: string[] = []; const errors: string[] = [];
    try {
      for (let offset = 0; offset < ids.length; offset += 5) {
        if (!current()) return;
        const group = ids.slice(offset, offset + 5);
        const results = await Promise.allSettled(group.map(id => api.updateAlertStatus(id, status)));
        if (!current()) return;
        results.forEach((result, index) => {
          if (result.status === 'rejected') {
            failed.push(group[index]); errors.push(`${group[index]}: ${String(result.reason)}`);
          }
        });
      }
      select(failed); setFailures(errors);
      const succeeded = ids.length - failed.length;
      if (succeeded) {
        void message.success(i18n.language.startsWith('zh') ? `已保存 ${succeeded} 条告警状态` : `${succeeded} alert state changes saved`);
        await refresh();
        await cache.invalidateQueries({ queryKey: ['agf', 'linked-alert'] });
      }
    } finally { active.current = false; setBusy(false); }
  };
  return { busy, failures, update };
}
