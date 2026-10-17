import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it } from 'vitest';
import i18n from '@/locales/i18n';
import PrivateLinkReferenceGraph from './PrivateLinkReferenceGraph';
import { privatelinkGraph } from './privatelinkFixtures';

beforeEach(async () => { await i18n.changeLanguage('en-US'); });
afterEach(async () => { cleanup(); await act(async () => { await i18n.changeLanguage('zh-CN'); }); });
const mount = (graph = privatelinkGraph(), canReadAssets = true) => render(<MemoryRouter>
  <PrivateLinkReferenceGraph graph={graph} canReadAssets={canReadAssets} />
</MemoryRouter>);
const evidence = () => screen.getByLabelText('Selected PrivateLink node evidence');

it('uses the returned cross-region identity, API edges and unknown security-group region without inferring authorization', () => {
  const graph = privatelinkGraph();
  // Even a malformed reference DTO cannot turn a child reference into a platform asset.
  graph.nodes[1].assetId = 'unexpected-reference-asset';
  mount(graph); fireEvent.click(screen.getByRole('button', { name: 'eps-owned' }));
  expect(within(evidence()).getByText('cn-shanghai')).toBeInTheDocument();
  expect(within(evidence()).getByText('Unknown / Unknown')).toBeInTheDocument();
  expect(within(evidence()).getByText('Reference only')).toBeInTheDocument();
  expect(within(evidence()).queryByRole('link')).not.toBeInTheDocument();
  expect(within(evidence()).getByText('GetVpcEndpointAttribute')).toBeInTheDocument();
  expect(within(evidence()).queryByText('ListVpcEndpointSecurityGroups')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'sg-owned' }));
  expect(within(evidence()).getByText('Unknown')).toBeInTheDocument();
  expect(within(evidence()).getByText('ListVpcEndpointSecurityGroups')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'ep-owned' }));
  expect(within(evidence()).getByRole('link', { name: 'Open endpoint asset' })).toHaveAttribute('href', '/assets/00000000-0000-4000-8000-000000000043');
});

it('pages nodes and adjacent evidence independently and bounds the diagram to eight actual edges', () => {
  const graph = privatelinkGraph(); graph.nodes = graph.nodes.slice(0, 1); graph.edges = [];
  for (let index = 0; index < 51; index++) {
    graph.nodes.push({ id: `zone:${index}`, kind: 'zone', cloudId: `zone-${index}`, region: null, assetId: null, referenceOnly: true });
    graph.edges.push({ from: 'endpoint:ep-owned', to: `zone:${index}`, relation: 'has_zone',
      evidenceAction: 'ListVpcEndpointZones', observedAt: '2026-10-01T00:01:00Z' });
  }
  mount(graph);
  const nodes = screen.getByRole('button', { name: 'ep-owned' }).closest('.ant-table-wrapper')! as HTMLElement;
  expect(within(nodes).queryByRole('button', { name: 'zone-50' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'ep-owned' }));
  const edges = within(evidence()).getByRole('columnheader', { name: 'Evidence API' }).closest('.ant-table-wrapper')! as HTMLElement;
  expect(within(edges).queryByText('ep-owned / zone-50')).not.toBeInTheDocument();
  expect(evidence().querySelectorAll('svg[role="img"] line')).toHaveLength(8);
  fireEvent.click(within(edges).getByTitle('2'));
  expect(within(edges).getByText('ep-owned / zone-50')).toBeInTheDocument();
  expect(within(nodes).getByRole('button', { name: 'ep-owned' })).toBeInTheDocument();
  fireEvent.click(within(nodes).getByTitle('2'));
  expect(within(nodes).getByRole('button', { name: 'zone-50' })).toBeInTheDocument();
  expect(within(edges).getByText('ep-owned / zone-50')).toBeInTheDocument();
});

it('shows no platform asset link without assets read permission while retaining actual reference evidence', () => {
  mount(privatelinkGraph(), false); fireEvent.click(screen.getByRole('button', { name: 'ep-owned' }));
  expect(within(evidence()).getByText('Asset viewing requires assets:read')).toBeInTheDocument();
  expect(within(evidence()).queryByRole('link')).not.toBeInTheDocument();
  expect(within(evidence()).getByText('GetVpcEndpointAttribute')).toBeInTheDocument();
});
