import { render, screen, waitFor } from '@testing-library/react';

import { GsnGraph } from './GsnGraph';

const layoutMock = jest.fn();
const loadMock = jest.fn();

jest.mock('@hpcc-js/wasm', () => ({
  Graphviz: {
    load: () => loadMock(),
  },
}));

describe('GsnGraph', () => {
  beforeEach(() => {
    layoutMock.mockReset();
    loadMock.mockReset();
    loadMock.mockResolvedValue({
      layout: (...args: unknown[]) => layoutMock(...args),
    });
  });

  it('renders Graphviz SVG output when the wasm module succeeds', async () => {
    layoutMock.mockResolvedValue('<svg xmlns="http://www.w3.org/2000/svg"><text>GSN</text></svg>');

    render(<GsnGraph dot={'digraph Demo { a -> b; }'} data-testid="gsn-graph" />);

    await waitFor(() => {
      const container = screen.getByTestId('gsn-graph');
      expect(container.querySelector('svg')).not.toBeNull();
    });

    expect(loadMock).toHaveBeenCalledTimes(1);
    expect(layoutMock).toHaveBeenCalledWith('digraph Demo { a -> b; }', 'svg', 'dot');
  });

  it('shows a fallback message when the wasm renderer fails to load', async () => {
    layoutMock.mockRejectedValueOnce(new Error('failed to load wasm'));

    render(<GsnGraph dot={'digraph Broken {}'} data-testid="gsn-graph" />);

    const fallbackMessage = await screen.findByText(
      'GSN grafiği görselleştirilemedi. Lütfen daha sonra tekrar deneyin.'
    );

    expect(fallbackMessage).toBeInTheDocument();
    expect(screen.getByTestId('gsn-graph')).toHaveTextContent('failed to load wasm');
  });
});
