import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import { AppProviders } from './app/AppProviders';
import { AppRouter } from './app/router';
import './styles/global.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The demo fallback resolves instantly; a short stale time keeps the
      // console responsive without hammering a live backend.
      staleTime: 15_000,
      retry: 0,
      refetchOnWindowFocus: false,
    },
  },
});

const container = document.getElementById('root');
if (!container) {
  throw new Error('#root container is missing from index.html');
}

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AppProviders>
        <AppRouter />
      </AppProviders>
    </QueryClientProvider>
  </StrictMode>,
);
