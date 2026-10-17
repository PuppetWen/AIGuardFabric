import { Component, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Result } from 'antd';

interface BoundaryProps {
  children: ReactNode;
  onReload: () => void;
  resetKey?: string;
  renderError: (error: unknown, retry: () => void, reload: () => void, reloading: boolean) => ReactNode;
}

class ErrorBoundary extends Component<BoundaryProps, { failed: boolean; error: unknown; reloading: boolean }> {
  state = { failed: false, error: undefined as unknown, reloading: false };
  private reloadStarted = false;

  static getDerivedStateFromError(error: unknown) {
    return { failed: true, error };
  }

  componentDidUpdate(previous: Readonly<BoundaryProps>) {
    if (this.state.failed && previous.resetKey !== this.props.resetKey) {
      this.reloadStarted = false;
      this.setState({ failed: false, error: undefined, reloading: false });
    }
  }

  private reload = () => {
    if (this.reloadStarted) return;
    this.reloadStarted = true;
    this.setState({ reloading: true });
    this.props.onReload();
  };

  render() {
    return this.state.failed
      ? this.props.renderError(this.state.error, () => this.setState({ failed: false }), this.reload, this.state.reloading)
      : this.props.children;
  }
}

function isChunkLoadError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.name === 'ChunkLoadError' || [
    /Failed to fetch dynamically imported module/i,
    /error loading dynamically imported module/i,
    /Importing a module script failed/i,
    /Loading (?:CSS )?chunk \S+ failed/i,
    /Unable to preload CSS for/i,
  ].some(pattern => pattern.test(error.message));
}

/** Keep navigation usable if an individual page fails to render. */
export function PageErrorBoundary({ children, resetKey, onReload = () => window.location.reload() }: {
  children: ReactNode; resetKey?: string; onReload?: () => void;
}) {
  const { t, i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  return (
    <ErrorBoundary resetKey={resetKey} onReload={onReload} renderError={(error, retry, reload, reloading) => isChunkLoadError(error)
      ? <Result status="error" title={zh ? '页面资源未能加载' : 'Page resources could not be loaded'}
        subTitle={zh ? '网站可能已更新，或网络连接暂时中断。确认网络后重新加载当前页面。'
          : 'The site may have been updated or the connection interrupted. Check your connection and reload this page.'}
        extra={<Button type="primary" disabled={reloading} onClick={reload}>
          {reloading ? (zh ? '正在重新加载…' : 'Reloading…') : (zh ? '重新加载页面' : 'Reload page')}
        </Button>} />
      : <Result status="error" title={t('layout.pageError')} subTitle={t('layout.pageErrorHint')}
        extra={<Button onClick={retry}>{t('common.retry')}</Button>} />
    }>
      {children}
    </ErrorBoundary>
  );
}
