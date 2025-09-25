declare module '@bora/ui-kit' {
  import * as React from 'react';

  export const Alert: React.FC<{
    title: string;
    description?: React.ReactNode;
    variant?: 'info' | 'warning' | 'error' | string;
    children?: React.ReactNode;
  }>;
  export const Badge: React.FC<{ variant?: string; children?: React.ReactNode }>;
  export const Button: React.FC<
    React.ComponentPropsWithoutRef<'button'> & { variant?: string; size?: string }
  >;
  export const Card: React.FC<{ title?: React.ReactNode; description?: React.ReactNode; children?: React.ReactNode }>;
  export const DateTimePicker: React.FC<{ value: unknown; onChange: (value: unknown) => void }>;
  export const EmptyState: React.FC<{ title: React.ReactNode; description?: React.ReactNode }>;
  export const Form: React.FC<{ form: unknown; onSubmit: (values: unknown) => void; children: React.ReactNode }>;
  export const FormField: React.FC<{
    control: unknown;
    name: string;
    label?: React.ReactNode;
    input: (props: {
      name: string;
      value: unknown;
      onChange: (value: unknown) => void;
      id: string;
      error?: boolean;
    }) => React.ReactNode;
  }>;
  export const Input: React.FC<React.ComponentPropsWithoutRef<'input'> & { invalid?: boolean }>;
  export const PageHeader: React.FC<{
    title: React.ReactNode;
    description?: React.ReactNode;
    breadcrumb?: Array<{ label: React.ReactNode; href?: string }>;
    actions?: React.ReactNode;
  }>;
  export const Pagination: React.FC<unknown>;
  export const Select: React.FC<unknown>;
  export const Skeleton: React.FC<{ className?: string }>;
  export const Table: React.FC<{ columns: Array<{ key: string; title: React.ReactNode }>; rows: Array<Record<string, React.ReactNode>> }>;
  export const Tabs: React.FC<{ value: string; onValueChange: (value: string) => void; children: React.ReactNode }> & {
    List: React.FC<{ children: React.ReactNode }>;
    Trigger: React.FC<{ value: string; children: React.ReactNode }>;
    Content: React.FC<{ value: string; children: React.ReactNode }>;
  };
  export const Textarea: React.FC<React.ComponentPropsWithoutRef<'textarea'> & { invalid?: boolean }>;
  export const Toolbar: React.FC<{ children: React.ReactNode }>;
  export const useToast: () => { notify: (options: { title: React.ReactNode; description?: React.ReactNode }) => void };
}
