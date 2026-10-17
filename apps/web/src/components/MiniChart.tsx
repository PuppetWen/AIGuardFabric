import ReactECharts from 'echarts-for-react';
import type { EChartsOption } from 'echarts';

import { useUiStore } from '@/stores/uiStore';

/**
 * Thin wrapper around `echarts-for-react` that keeps the chart palette in sync
 * with the active theme (ECharts needs concrete colours, not CSS variables).
 */
export interface MiniChartProps {
  option: EChartsOption;
  height?: number | string;
  className?: string;
  onEvents?: Record<string, (params: unknown) => void>;
}

export function MiniChart({ option, height = 240, className, onEvents }: MiniChartProps) {
  const theme = useUiStore((state) => state.theme);
  return (
    <ReactECharts
      className={className ?? 'agf-echart'}
      style={{ height }}
      option={option}
      theme={theme === 'dark' ? 'dark' : undefined}
      notMerge
      lazyUpdate
      opts={{ renderer: 'canvas' }}
      onEvents={onEvents}
    />
  );
}

/** Axis / grid colours for the active theme. */
export function useChartTokens() {
  const theme = useUiStore((state) => state.theme);
  const dark = theme === 'dark';
  return {
    text: dark ? '#a7b3c7' : '#46536b',
    textStrong: dark ? '#e8edf6' : '#101725',
    grid: dark ? '#223047' : '#e2e8f4',
    tooltipBg: dark ? '#182233' : '#ffffff',
    tooltipBorder: dark ? '#26324a' : '#d5dced',
    areaTop: dark ? 'rgba(95, 168, 255, 0.34)' : 'rgba(26, 95, 208, 0.26)',
    areaBottom: dark ? 'rgba(95, 168, 255, 0.02)' : 'rgba(26, 95, 208, 0.02)',
  };
}

/** Compact inline sparkline used inside KPI tiles. */
export function Sparkline({
  data,
  color,
  height = 44,
  width = 128,
}: {
  data: number[];
  color: string;
  height?: number;
  width?: number;
}) {
  const option: EChartsOption = {
    animation: false,
    grid: { left: 0, right: 0, top: 4, bottom: 0 },
    xAxis: { type: 'category', show: false, boundaryGap: false, data: data.map((_, index) => index) },
    yAxis: { type: 'value', show: false, scale: true },
    tooltip: { show: false },
    series: [
      {
        type: 'line',
        data,
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 1.6, color },
        areaStyle: { color, opacity: 0.14 },
      },
    ],
  };
  return (
    <ReactECharts
      style={{ width, height }}
      option={option}
      notMerge
      lazyUpdate
      opts={{ renderer: 'canvas' }}
    />
  );
}

export default MiniChart;
