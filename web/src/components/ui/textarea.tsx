import * as React from 'react';
import { cn } from '@/lib/cn';

export const Textarea = React.forwardRef<
  HTMLTextAreaElement,
  React.TextareaHTMLAttributes<HTMLTextAreaElement>
>(({ className, ...props }, ref) => {
  return (
    <textarea
      ref={ref}
      className={cn(
        'flex min-h-24 w-full rounded-md border border-slate-200 bg-white px-3 py-2 text-sm leading-6 text-slate-950 shadow-sm outline-none ring-offset-background placeholder:text-slate-400 focus-visible:ring-2 focus-visible:ring-slate-950',
        className,
      )}
      {...props}
    />
  );
});

Textarea.displayName = 'Textarea';
