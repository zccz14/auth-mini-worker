import type { HTMLAttributes } from 'react';
import { cn } from '@/lib/cn';

export function Alert({ className, variant = 'default', ...props }: HTMLAttributes<HTMLDivElement> & { variant?: 'default' | 'destructive' }) {
  return (
    <div
      role="alert"
      className={cn(
        'rounded-lg border px-4 py-3 text-sm',
        variant === 'destructive'
          ? 'border-destructive/40 bg-destructive/10 text-destructive'
          : 'border-border bg-secondary/50 text-secondary-foreground',
        className,
      )}
      {...props}
    />
  );
}
