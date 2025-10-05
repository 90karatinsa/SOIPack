import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';

type RenderStatus = 'idle' | 'loading' | 'ready' | 'error';

let graphvizModulePromise: Promise<typeof import('@hpcc-js/wasm')> | null = null;
type GraphvizModule = typeof import('@hpcc-js/wasm');
type GraphvizInstance = Awaited<ReturnType<GraphvizModule['Graphviz']['load']>>;

let graphvizInstancePromise: Promise<GraphvizInstance> | null = null;

const loadGraphvizModule = () => {
  if (!graphvizModulePromise) {
    graphvizModulePromise = import('@hpcc-js/wasm');
  }
  return graphvizModulePromise;
};

const loadGraphvizInstance = async (): Promise<GraphvizInstance> => {
  if (!graphvizInstancePromise) {
    graphvizInstancePromise = loadGraphvizModule().then((module) => module.Graphviz.load());
  }
  return graphvizInstancePromise;
};

export interface GsnGraphProps {
  dot: string;
  className?: string;
  fallbackMessage?: ReactNode;
  loadingMessage?: ReactNode;
  ['data-testid']?: string;
}

const DEFAULT_LOADING_MESSAGE = 'GSN grafiği yükleniyor…';
const DEFAULT_FALLBACK_MESSAGE = 'GSN grafiği görselleştirilemedi. Lütfen daha sonra tekrar deneyin.';

export function GsnGraph({
  dot,
  className,
  fallbackMessage = DEFAULT_FALLBACK_MESSAGE,
  loadingMessage = DEFAULT_LOADING_MESSAGE,
  'data-testid': dataTestId,
}: GsnGraphProps) {
  const [status, setStatus] = useState<RenderStatus>('idle');
  const [svgMarkup, setSvgMarkup] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    let isCancelled = false;

    const renderGraph = async () => {
      setStatus('loading');
      setSvgMarkup(null);
      setErrorMessage(null);

      try {
        const graphviz = await loadGraphvizInstance();
        const svg = await graphviz.layout(dot, 'svg', 'dot');
        if (!isCancelled) {
          setSvgMarkup(svg);
          setStatus('ready');
        }
      } catch (error) {
        if (isCancelled) {
          return;
        }
        const message = error instanceof Error ? error.message : String(error);
        setErrorMessage(message);
        setStatus('error');
      }
    };

    if (dot.trim().length === 0) {
      setStatus('error');
      setSvgMarkup(null);
      setErrorMessage('Graphviz DOT içeriği bulunamadı.');
      return () => {
        isCancelled = true;
      };
    }

    void renderGraph();

    return () => {
      isCancelled = true;
    };
  }, [dot]);

  if (status === 'error') {
    return (
      <div className={className} data-testid={dataTestId} role="alert">
        <p>{fallbackMessage}</p>
        {errorMessage ? <pre className="mt-2 whitespace-pre-wrap text-xs">{errorMessage}</pre> : null}
      </div>
    );
  }

  if (status !== 'ready' || !svgMarkup) {
    return (
      <div className={className} data-testid={dataTestId} role="status">
        {loadingMessage}
      </div>
    );
  }

  return (
    <div
      className={className}
      data-testid={dataTestId}
      role="img"
      aria-label="GSN graph"
      dangerouslySetInnerHTML={{ __html: svgMarkup }}
    />
  );
}

export default GsnGraph;
