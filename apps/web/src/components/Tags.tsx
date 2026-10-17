import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

import { Tooltip } from 'antd';

import type { AdapterHealth, ExposureSurface, PolicyAction, Severity } from '@/types/domain';

import { HEALTH_HEX, POLICY_ACTION_HEX } from '@/utils/palette';
import { SEVERITY_STYLE } from '@/utils/severity';
import { policyActionKey } from '@/utils/labels';

/** Severity chip with a colour dot; colours are contrast-checked in tests. */
export function SeverityTag({ severity, withLabel = true }: { severity: Severity; withLabel?: boolean }) {
  const { t } = useTranslation();
  const style = SEVERITY_STYLE[severity];
  return (
    <span
      className="agf-chip"
      style={{ background: style.bg, borderColor: style.border, color: style.dark }}
      data-severity={severity}
    >
      <span className="agf-severity-dot" style={{ background: style.hex }} />
      {withLabel ? t(`severity.${severity}`) : null}
    </span>
  );
}

/** Adapter / intercept point health chip. */
export function HealthTag({ health, withLabel = true }: { health: AdapterHealth; withLabel?: boolean }) {
  const { t } = useTranslation();
  const hex = HEALTH_HEX[health];
  return (
    <span className="agf-chip" style={{ background: `${hex}26`, borderColor: `${hex}73`, color: hex }}>
      <span className="agf-severity-dot" style={{ background: hex }} />
      {withLabel ? t(`health.${health}`) : null}
    </span>
  );
}

/** Policy action chip. */
export function ActionTag({ action }: { action: PolicyAction }) {
  const { t } = useTranslation();
  const hex = POLICY_ACTION_HEX[action];
  return (
    <span className="agf-chip" style={{ background: `${hex}26`, borderColor: `${hex}73`, color: hex }}>
      {t(policyActionKey(action))}
    </span>
  );
}

/** Exposure-surface chip; wider exposure renders in a warmer colour. */
export function ExposureTag({ exposure }: { exposure: ExposureSurface }) {
  const { t } = useTranslation();
  const hex = EXPOSURE_COLOR[exposure];
  return (
    <span className="agf-chip" style={{ background: `${hex}26`, borderColor: `${hex}73`, color: hex }}>
      {t(`assets.exposure.${exposure}`)}
    </span>
  );
}

const EXPOSURE_COLOR: Record<ExposureSurface, string> = {
  unknown: '#8892a4',
  'public-internet': '#ff8b90',
  partner: '#ffab7a',
  intranet: '#8fbaff',
  isolated: '#3dd68c',
};

/** Plain neutral chip for enum-ish labels the page already translated. */
export function Chip({ color, children, title }: { color: string; children: ReactNode; title?: string }) {
  const body = (
    <span className="agf-chip" style={{ background: `${color}22`, borderColor: `${color}66`, color }}>
      {children}
    </span>
  );
  return title ? <Tooltip title={title}>{body}</Tooltip> : body;
}

/** Small inline meter (0..1) with the value as accessible text. */
export function Meter({
  ratio,
  color,
  label,
  valueText,
}: {
  ratio: number;
  color: string;
  label?: ReactNode;
  valueText: ReactNode;
}) {
  const clamped = Math.min(1, Math.max(0, ratio));
  return (
    <div className="agf-meter">
      <div className="agf-meter__head">
        <span>{label}</span>
        <span className="agf-mono">{valueText}</span>
      </div>
      <div
        role="progressbar"
        aria-valuenow={Math.round(clamped * 100)}
        aria-valuemin={0}
        aria-valuemax={100}
        style={{
          height: 6,
          borderRadius: 4,
          background: 'var(--agf-divider)',
          overflow: 'hidden',
        }}
      >
        <div style={{ width: `${clamped * 100}%`, height: '100%', background: color }} />
      </div>
    </div>
  );
}

export default SeverityTag;
