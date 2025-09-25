import type { JSX } from 'react';

export type View = 'upload' | 'compliance' | 'traceability' | 'risk' | 'timeline';

interface NavigationTabsProps {
  activeView: View;
  onChange: (view: View) => void;
  disabled: boolean;
}

const viewLabels: Record<View, string> = {
  upload: 'Yükleme & Çalıştırma',
  compliance: 'Uyum Matrisi',
  traceability: 'İzlenebilirlik',
  risk: 'Risk Kokpiti',
  timeline: 'Zaman Çizelgesi'
};

const viewIcons: Record<View, JSX.Element> = {
  upload: (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="h-5 w-5">
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5V8.25M3 16.5a2.25 2.25 0 002.25 2.25H18.75A2.25 2.25 0 0021 16.5M3 16.5L8.25 11.25M21 16.5V8.25M21 16.5L15.75 11.25M15.75 11.25L12 7.5m0 0L8.25 11.25M12 7.5V3" />
    </svg>
  ),
  compliance: (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="h-5 w-5">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  traceability: (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="h-5 w-5">
      <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 8.25h9M7.5 12h9m-9 3.75h9M4.5 4.5l15 15" />
    </svg>
  ),
  risk: (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="h-5 w-5">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M4.5 3.75l2.25 16.5L12 18l5.25 2.25 2.25-16.5m-6.75 11.25V9M9 13.5l3-3 3 3"
      />
    </svg>
  ),
  timeline: (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="h-5 w-5">
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 12h18M12 3v18m6-11.25l-3 3 3 3m-12-6l3 3-3 3" />
    </svg>
  )
};

export function NavigationTabs({ activeView, onChange, disabled }: NavigationTabsProps) {
  return (
    <div className="flex flex-wrap gap-2 rounded-2xl border border-slate-800 bg-slate-900/70 p-2 text-sm text-slate-300 shadow-lg shadow-slate-950/30 backdrop-blur">
      {(Object.keys(viewLabels) as View[]).map((view) => {
        const isActive = activeView === view;
        return (
          <button
            key={view}
            type="button"
            onClick={() => onChange(view)}
            disabled={disabled}
            className={`inline-flex items-center gap-2 rounded-xl px-4 py-2 font-semibold transition focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-900 ${
              isActive
                ? 'bg-brand text-white shadow shadow-brand/30 focus:ring-brand'
                : 'text-slate-300 hover:bg-slate-800 focus:ring-brand/40'
            } ${disabled ? 'cursor-not-allowed opacity-50' : ''}`}
          >
            {viewIcons[view]}
            {viewLabels[view]}
          </button>
        );
      })}
    </div>
  );
}
