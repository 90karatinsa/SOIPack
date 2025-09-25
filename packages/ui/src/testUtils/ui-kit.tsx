import type { ReactNode } from 'react';

export function Alert({ title, description, children }: { title: ReactNode; description?: ReactNode; children?: ReactNode }) {
  return (
    <div data-testid="alert">
      <strong>{title}</strong>
      {description && <p>{description}</p>}
      {children}
    </div>
  );
}

export function Badge({ children }: { variant?: string; children?: ReactNode }) {
  return <span>{children}</span>;
}

export function Button({ children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button {...props}>{children}</button>;
}

export function Card({ title, description, children }: { title?: ReactNode; description?: ReactNode; children?: ReactNode }) {
  return (
    <section>
      {title && <header>{title}</header>}
      {description && <p>{description}</p>}
      {children}
    </section>
  );
}

export function DateTimePicker({ value, onChange }: { value: unknown; onChange: (next: unknown) => void }) {
  return (
    <input
      type="datetime-local"
      value={typeof value === 'object' && value && 'iso' in (value as Record<string, unknown>) ? (value as { iso: string }).iso : ''}
      onChange={(event) => onChange({ ...(value as Record<string, unknown>), iso: event.target.value })}
    />
  );
}

export function EmptyState({ title, description }: { title: ReactNode; description?: ReactNode }) {
  return (
    <div>
      <h3>{title}</h3>
      {description && <p>{description}</p>}
    </div>
  );
}

export function Form({ children }: { form: unknown; onSubmit: (values: unknown) => void; children: ReactNode }) {
  return <form>{children}</form>;
}

export function FormField({ input }: { input: (props: { name: string; value: unknown; onChange: (value: unknown) => void; id: string; error?: boolean }) => ReactNode }) {
  return <div>{input({ name: 'field', value: '', onChange: () => undefined, id: 'field' })}</div>;
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} />;
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  breadcrumb?: Array<{ label: ReactNode; href?: string }>;
  actions?: ReactNode;
}) {
  return (
    <header>
      <h2>{title}</h2>
      {description && <p>{description}</p>}
      {actions && <div>{actions}</div>}
    </header>
  );
}

export function Pagination() {
  return <nav />;
}

export function Select() {
  return <select />;
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={className ?? ''} data-testid="skeleton" />;
}

export function Table({ columns, rows }: { columns: Array<{ key: string; title: ReactNode }>; rows: Array<Record<string, ReactNode>> }) {
  return (
    <table>
      <thead>
        <tr>
          {columns.map((column) => (
            <th key={column.key}>{column.title}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row, index) => (
          <tr key={index}>
            {columns.map((column) => (
              <td key={column.key}>{row[column.key]}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

interface TabsProps {
  value: string;
  onValueChange: (value: string) => void;
  children: ReactNode;
}

function TabsRoot({ children }: TabsProps) {
  return <div>{children}</div>;
}

TabsRoot.List = function TabsList({ children }: { children: ReactNode }) {
  return <div>{children}</div>;
};

TabsRoot.Trigger = function TabsTrigger({ children }: { value: string; children: ReactNode }) {
  return <button type="button">{children}</button>;
};

TabsRoot.Content = function TabsContent({ children }: { value: string; children: ReactNode }) {
  return <div>{children}</div>;
};

export const Tabs = TabsRoot as unknown as {
  (props: TabsProps): JSX.Element;
  List: typeof TabsRoot.List;
  Trigger: typeof TabsRoot.Trigger;
  Content: typeof TabsRoot.Content;
};

export function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} />;
}

export function Toolbar({ children }: { children: ReactNode }) {
  return <div>{children}</div>;
}

export function useToast() {
  return {
    notify: () => undefined,
  };
}
