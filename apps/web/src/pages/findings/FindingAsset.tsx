import { Link } from 'react-router-dom';
import type { Finding } from '@/types/domain';
import { EventEvidenceLink } from '@/components/EventEvidenceLink';

export function FindingAsset({ finding }: { finding: Finding }) {
  if (finding.target?.startsWith('event:')) return <EventEvidenceLink reference={finding.target} />;
  if (finding.assetId && finding.canReadAsset) return <Link to={'/assets/' + finding.assetId}>{finding.assetName}</Link>;
  return <span>{finding.assetName}</span>;
}
