import type { ReactNode } from 'react';

export interface PanelProps {
  title?: ReactNode;
  extra?: ReactNode;
  className?: string;
  /** Apply the standard 16px inner padding. */
  padded?: boolean;
  children: ReactNode;
}

/** Bordered surface used for every block of content on a page. */
export function Panel({ title, extra, className, padded = true, children }: PanelProps) {
  return (
    <section className={['agf-panel', padded ? 'agf-panel--pad' : '', className ?? ''].join(' ').trim()}>
      {title || extra ? (
        <div className="agf-panel__title">
          <div>{title}</div>
          <div>{extra}</div>
        </div>
      ) : null}
      {children}
    </section>
  );
}

export default Panel;
