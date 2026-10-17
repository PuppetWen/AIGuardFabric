import type { ReactNode } from 'react';

import { Panel } from './Panel';
import { PageHeader } from './PageHeader';

/** Standard page chrome: title, subtitle, actions, and a content panel. */
export function Page({ title, subtitle, actions, children }: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <>
      <PageHeader title={title} subtitle={subtitle} actions={actions} />
      {children}
    </>
  );
}

export { Panel };
