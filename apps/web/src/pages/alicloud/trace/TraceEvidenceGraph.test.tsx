import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import i18n from '@/locales/i18n';
import TraceEvidenceGraph from './TraceEvidenceGraph';
import { traceFixture, traceUuid } from './traceFixtures';

beforeEach(async () => { await i18n.changeLanguage('en-US'); });
afterEach(async () => { await i18n.changeLanguage('zh-CN'); });
describe('Bounded, conservative Trace relationship evidence', () => {
  it('renders only50actual UUID nodes, distinguishes total from visibility and can select a filtered node', () => {
    const data = traceFixture(2000);
    render(<TraceEvidenceGraph graph={data.graph} total={2001} truncated />);
    expect(screen.getByText(/Visible 50 \/ filtered 2000 \/ returned 2000 nodes/)).toHaveTextContent('window total events 2001');
    expect(screen.getAllByRole('button', { name: /^10000000-0000-4000-8000-/ })).toHaveLength(50);
    expect(screen.queryByRole('button', { name: traceUuid(51) })).not.toBeInTheDocument();
    expect(screen.getByText(/window exceeds the 2000-node cap/)).toBeInTheDocument();
    fireEvent.change(screen.getByRole('textbox', { name: 'Filter Trace nodes' }), { target: { value: traceUuid(2000) } });
    expect(screen.getByText(/Visible 1 \/ filtered 1 \/ returned 2000 nodes/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: traceUuid(2000) }));
    const selected = screen.getByRole('region', { name: 'Selected Trace node evidence' });
    expect(within(selected).getByText('external-event-2000')).toBeInTheDocument();
    expect(within(selected).getByText(/No verified adjacent parent edge/)).toBeInTheDocument();
    expect(within(selected).queryByText(/parent_span_id =/)).not.toBeInTheDocument();
  });
  it('shows only real returned parent evidence and neighbor selection uses actual audit UUIDs', () => {
    const data = traceFixture(2);
    render(<TraceEvidenceGraph graph={data.graph} total={2} truncated={false} />);
    fireEvent.click(screen.getByRole('button', { name: traceUuid(1) }));
    const selected = screen.getByRole('region', { name: 'Selected Trace node evidence' });
    expect(within(selected).getByText('parent_span_id = span-1')).toBeInTheDocument();
    expect(within(selected).getByText(/Visible adjacent parent edges 1 \/ 1/)).toBeInTheDocument();
    fireEvent.click(within(selected).getByRole('button', { name: traceUuid(2) }));
    expect(within(screen.getByRole('region')).getByText('external-event-2')).toBeInTheDocument();
    expect(screen.getByText(/Only parent_span_id evidence forms an edge/)).toHaveTextContent('not a complete tree');
  });
  it('renders missing, duplicate and cycle issues as reported conflict without fabricating a tree', () => {
    const data = traceFixture(3);
    data.graph.status = 'conflict'; data.graph.edges = [];
    data.graph.nodes[0].resolution = 'conflict';
    data.graph.issues = ['duplicate_span', 'cycle', 'missing_parent'].map(kind => ({ nodeId: traceUuid(1),
      spanId: 'span-1', parentSpanId: 'missing-span', kind: kind as 'duplicate_span' | 'cycle' | 'missing_parent', status: 'conflict' }));
    render(<TraceEvidenceGraph graph={data.graph} total={3} truncated={false} />);
    fireEvent.click(screen.getByRole('button', { name: traceUuid(1) }));
    const selected = screen.getByRole('region');
    expect(within(selected).getByText('Duplicate span')).toBeInTheDocument();
    expect(within(selected).getByText('Cycle')).toBeInTheDocument();
    expect(within(selected).getByText('Missing parent')).toBeInTheDocument();
    expect(within(selected).queryByText(/parent_span_id =/)).not.toBeInTheDocument();
    expect(within(selected).getByText(/Unknown; Mock does not establish authorization/)).toBeInTheDocument();
  });
  it('bounds a high-fanout selected node to50adjacent edges and pages the rest separately', () => {
    const data = traceFixture(61);
    data.graph.edges = data.graph.nodes.slice(1).map(node => ({ fromNodeId: traceUuid(1), toNodeId: node.id,
      parentSpanId: 'span-1', evidence: 'parent_span_id' }));
    render(<TraceEvidenceGraph graph={data.graph} total={61} truncated={false} />);
    fireEvent.click(screen.getByRole('button', { name: traceUuid(1) }));
    const selected = screen.getByRole('region');
    expect(within(selected).getAllByText('parent_span_id = span-1')).toHaveLength(50);
    expect(within(selected).getByText(/Visible adjacent parent edges 50 \/ 60/)).toBeInTheDocument();
    fireEvent.click(within(screen.getByLabelText('Trace adjacent edge pagination')).getByTitle('2'));
    expect(within(selected).getAllByText('parent_span_id = span-1')).toHaveLength(10);
    expect(within(selected).getByText(/Visible adjacent parent edges 10 \/ 60/)).toBeInTheDocument();
  });
});
