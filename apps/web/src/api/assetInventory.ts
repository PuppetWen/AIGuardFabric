import { callApi } from './client';

export type InventoryRun = {
  id: string; date: string; baselineDate?: string; initialBaseline: boolean; snapshotCount: number;
  completedAt: string; summary: { total: number; added: number; removed: number; modified: number; risky: number };
};
export type InventoryHistory = {
  items: InventoryRun[]; total: number; automaticEnabled: boolean; canWrite: boolean;
};
const emptyHistory: InventoryHistory = { items: [], total: 0, automaticEnabled: false, canWrite: false };
export const inventoryHistory = (page = 1) => callApi('/api/v1/assets/inventory', () => emptyHistory,
  { noFallback: true, query: { page } });

