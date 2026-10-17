import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';

import type { EChartsOption } from 'echarts';
import { Col, Row } from 'antd';

import { MiniChart, useChartTokens } from '@/components/MiniChart';
import { Panel } from '@/components/Panel';
import type { ModelUsageAggregate } from '@/types/domain';
import { compactNumber, formatCny } from '@/utils/format';

interface UsageChartsProps {
  usage: ModelUsageAggregate[];
}

/** Token-volume and cost breakdown charts for the selected window. */
export function UsageCharts({ usage }: UsageChartsProps) {
  const { t } = useTranslation();
  const tokens = useChartTokens();

  const trendOption = useMemo<EChartsOption>(() => {
    const rows = [...usage].sort((a, b) => b.inputTokens + b.outputTokens - (a.inputTokens + a.outputTokens));
    return {
      grid: { left: 54, right: 20, top: 30, bottom: 46 },
      tooltip: {
        trigger: 'axis',
        backgroundColor: tokens.tooltipBg,
        borderColor: tokens.tooltipBorder,
        textStyle: { color: tokens.textStrong, fontSize: 12 },
      },
      legend: {
        bottom: 0,
        textStyle: { color: tokens.text, fontSize: 11 },
        icon: 'roundRect',
        itemWidth: 10,
        itemHeight: 10,
      },
      xAxis: {
        type: 'category',
        data: rows.map((row) => row.model),
        axisLabel: { color: tokens.text, fontSize: 10, rotate: 22, interval: 0 },
        axisLine: { lineStyle: { color: tokens.grid } },
      },
      yAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: tokens.grid, type: 'dashed' } },
        axisLabel: {
          color: tokens.text,
          fontSize: 11,
          formatter: (value: number) => compactNumber(value),
        },
      },
      series: [
        {
          name: t('models.usage.input'),
          type: 'bar',
          stack: 'tokens',
          barMaxWidth: 26,
          itemStyle: { color: '#3d8bfd' },
          data: rows.map((row) => row.inputTokens),
        },
        {
          name: t('models.usage.output'),
          type: 'bar',
          stack: 'tokens',
          barMaxWidth: 26,
          itemStyle: { color: '#12a594' },
          data: rows.map((row) => row.outputTokens),
        },
      ],
    };
  }, [t, tokens, usage]);

  const costOption = useMemo<EChartsOption>(() => {
    const rows = [...usage].sort((a, b) => b.costCny - a.costCny);
    return {
      grid: { left: 54, right: 20, top: 20, bottom: 46 },
      tooltip: {
        trigger: 'axis',
        backgroundColor: tokens.tooltipBg,
        borderColor: tokens.tooltipBorder,
        textStyle: { color: tokens.textStrong, fontSize: 12 },
        valueFormatter: (value) => formatCny(Number(value), 6),
      },
      xAxis: {
        type: 'category',
        data: rows.map((row) => row.model),
        axisLabel: { color: tokens.text, fontSize: 10, rotate: 22, interval: 0 },
        axisLine: { lineStyle: { color: tokens.grid } },
      },
      yAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: tokens.grid, type: 'dashed' } },
        axisLabel: { color: tokens.text, fontSize: 11, formatter: (value: number) => `¥${value}` },
      },
      series: [
        {
          name: t('models.usage.cost'),
          type: 'bar',
          barMaxWidth: 26,
          itemStyle: {
            color: {
              type: 'linear',
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: '#f0cc6a' },
                { offset: 1, color: '#f26b2c' },
              ],
            },
          },
          data: rows.map((row) => row.costCny),
        },
      ],
    };
  }, [t, tokens, usage]);

  return (
    <Row gutter={[14, 14]}>
      <Col xs={24} xl={14}>
        <Panel title={t('models.usage.trend')}>
          <MiniChart option={trendOption} height={280} />
        </Panel>
      </Col>
      <Col xs={24} xl={10}>
        <Panel title={t('models.usage.cost')}>
          <MiniChart option={costOption} height={280} />
        </Panel>
      </Col>
    </Row>
  );
}
