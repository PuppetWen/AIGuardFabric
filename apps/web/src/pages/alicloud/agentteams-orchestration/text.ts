import { useTranslation } from 'react-i18next';
export function useText() { const { i18n } = useTranslation(); return (cn: string, en: string) => i18n.language.startsWith('zh') ? cn : en; }
export const failure = (error: unknown) => error instanceof Error ? error.message : 'Request failed / 请求失败';
export const uuid = (value: string) => /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export const revision = (value: number) => Number.isSafeInteger(value) && value >= 0;
