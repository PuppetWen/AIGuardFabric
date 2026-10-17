import type { ReactNode } from 'react';

export interface PageHeaderProps {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}

/** Page title bar shared by every route. */
export function PageHeader({ title, subtitle, actions }: PageHeaderProps) {
  return (
    <header className="agf-page-header">
      <div className="agf-page-header__main">
        <h1 className="agf-page-header__title">{title}</h1>
        {subtitle ? <p className="agf-page-header__subtitle">{subtitle}</p> : null}
      </div>
      {actions ? <div className="agf-page-header__actions">{actions}</div> : null}
    </header>
  );
}

export default PageHeader;
