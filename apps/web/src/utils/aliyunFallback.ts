import type { SelfCheckItem } from '@/types/domain';

/**
 * Colour lookup for self-check categories.
 *
 * Kept out of `utils/palette.ts` because these colours are used by exactly one
 * page and would otherwise inflate the shared palette module.
 */
export const ADAPTER_CATEGORY_FALLBACK: Record<SelfCheckItem['category'], string> = {
  connectivity: '#3d8bfd',
  'least-privilege': '#f0cc6a',
  quota: '#12a594',
};
