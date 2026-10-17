import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render as renderPage, screen, waitFor } from '@testing-library/react';

import type { TopologyGraph } from '@/types/domain';
import TopologyPage from './TopologyPage';

const graphMocks = {
  construct: vi.fn(),
  render: vi.fn(),
  draw: vi.fn(),
  fitView: vi.fn(),
  layout: vi.fn(),
  destroy: vi.fn(),
  on: vi.fn(),
  updateEdgeData: vi.fn(),
  updateNodeData: vi.fn(),
};

const query = {
  data: { data: { nodes: [], edges: [], egressPaths: [] } as TopologyGraph },
  isLoading: false,
  error: null,
  refetch: vi.fn(),
};

vi.mock('@/api/client', () => ({ api: { topology: vi.fn() }, useApiQuery: () => query }));
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
vi.mock('@antv/g6', () => ({
  Graph: class {
    constructor() { graphMocks.construct(); }
    render = graphMocks.render;
    draw = graphMocks.draw;
    fitView = graphMocks.fitView;
    layout = graphMocks.layout;
    destroy = graphMocks.destroy;
    on = graphMocks.on;
    updateEdgeData = graphMocks.updateEdgeData;
    updateNodeData = graphMocks.updateNodeData;
  },
}));

function pendingRender() {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

beforeEach(() => {
  for (const mock of Object.values(graphMocks)) mock.mockReset();
  for (const method of ['render', 'draw', 'fitView', 'layout'] as const) {
    graphMocks[method].mockResolvedValue(undefined);
  }
  query.data = { data: { nodes: [
    { id: 'agent', label: 'Agent', type: 'agent', riskScore: 0, shadow: false, detail: '' },
    { id: 'model', label: 'Model', type: 'model', riskScore: 0, shadow: false, detail: '' },
  ], edges: [
    { id: 'egress', source: 'agent', target: 'model', kind: 'invokes', egress: true, calls24h: 1 },
  ], egressPaths: [['agent', 'model']] } };
});

describe('topology graph lifecycle', () => {
  it('shows an asynchronous rendering failure instead of an unhandled rejection', async () => {
    graphMocks.render.mockRejectedValueOnce(new Error('Canvas renderer unavailable'));
    renderPage(<TopologyPage />);
    expect(await screen.findByText('Canvas renderer unavailable')).toBeInTheDocument();
    expect(graphMocks.draw).not.toHaveBeenCalled();
  });

  it('waits for rendering before applying the latest highlight and fitting the graph', async () => {
    const pending = pendingRender();
    graphMocks.render.mockReturnValueOnce(pending.promise);
    renderPage(<TopologyPage />);
    await waitFor(() => expect(graphMocks.render).toHaveBeenCalledOnce());
    fireEvent.click(screen.getByRole('button', { name: /topology.action.highlightEgress/ }));
    fireEvent.click(screen.getByRole('button', { name: /topology.action.fit/ }));
    expect(graphMocks.draw).not.toHaveBeenCalled();
    expect(graphMocks.fitView).not.toHaveBeenCalled();
    await act(async () => pending.resolve());
    await waitFor(() => expect(graphMocks.draw).toHaveBeenCalledOnce());
    expect(graphMocks.fitView).toHaveBeenCalledOnce();
    expect(graphMocks.updateEdgeData).toHaveBeenLastCalledWith([
      expect.objectContaining({ id: 'egress', style: expect.objectContaining({ lineWidth: 3.4 }) }),
    ]);
  });

  it('shows asynchronous highlight failures', async () => {
    graphMocks.draw.mockRejectedValueOnce(new Error('Canvas draw failed'));
    renderPage(<TopologyPage />);
    expect(await screen.findByText('Canvas draw failed')).toBeInTheDocument();
  });

  it.each([
    ['fitView', 'topology.action.fit'],
    ['layout', 'topology.action.reload'],
  ] as const)('shows asynchronous %s failures', async (method, label) => {
    graphMocks[method].mockRejectedValueOnce(new Error(`${method} failed`));
    renderPage(<TopologyPage />);
    await waitFor(() => expect(graphMocks.draw).toHaveBeenCalledOnce());
    fireEvent.click(screen.getByRole('button', { name: new RegExp(label) }));
    expect(await screen.findByText(`${method} failed`)).toBeInTheDocument();
  });

  it('ignores failures from the previous graph after a data refresh', async () => {
    const pending = pendingRender();
    graphMocks.render.mockReturnValueOnce(pending.promise);
    const view = renderPage(<TopologyPage />);
    await waitFor(() => expect(graphMocks.render).toHaveBeenCalledOnce());
    query.data = { data: { ...query.data.data, nodes: [...query.data.data.nodes] } };
    view.rerender(<TopologyPage />);
    await waitFor(() => expect(graphMocks.render).toHaveBeenCalledTimes(2));
    await act(async () => pending.reject(new Error('Old graph failed')));
    expect(screen.queryByText('Old graph failed')).not.toBeInTheDocument();
    expect(graphMocks.destroy).toHaveBeenCalledOnce();
    expect(graphMocks.draw).toHaveBeenCalledOnce();
  });

  it('handles a rejected render after unmount without drawing on a destroyed graph', async () => {
    const pending = pendingRender();
    graphMocks.render.mockReturnValueOnce(pending.promise);
    const view = renderPage(<TopologyPage />);
    await waitFor(() => expect(graphMocks.render).toHaveBeenCalledOnce());
    view.unmount();
    await act(async () => pending.reject(new Error('Graph was destroyed')));
    expect(graphMocks.destroy).toHaveBeenCalledOnce();
    expect(graphMocks.draw).not.toHaveBeenCalled();
  });

  it('reports synchronous graph construction failures', async () => {
    graphMocks.construct.mockImplementationOnce(() => { throw new Error('No canvas context'); });
    renderPage(<TopologyPage />);
    expect(await screen.findByText('No canvas context')).toBeInTheDocument();
  });
});
