import { currentToken, useAuthStore } from '@/stores/authStore';

import { API_BASE_URL, API_TIMEOUT_MS, FORCE_DEMO } from './config';
import { camelizeDeep } from './contract';
import { adaptResponse } from './adapters';
import { sessionToken } from './session';
import { markDemo, markLive, type ApiResult } from './dataSource';

/* ------------------------------------------------------------------ */
/* Transport                                                           */
/* ------------------------------------------------------------------ */

export class ApiRequestError extends Error {
  readonly status: number;
  readonly code: string;
  /** Whether this failure should trigger the demo fallback. */
  readonly fallbackable: boolean;

  constructor(message: string, status: number, code: string, fallbackable = true) {
    super(message);
    this.name = 'ApiRequestError';
    this.status = status;
    this.code = code;
    this.fallbackable = fallbackable;
  }
}

export function sessionChangedError(): ApiRequestError {
  return new ApiRequestError(
    '组织或登录状态已改变，请重新打开页面、核对内容后再操作 / Your organization or sign-in changed. Reopen this page and retry.',
    409, 'session_changed', false,
  );
}

function captureRequestScope() {
  const before = useAuthStore.getState();
  const tenantId = before.tenant?.id;
  const tenantSlug = before.tenant?.slug;
  const generation = before.sessionGeneration;
  return {
    tenantId,
    assertCurrent() {
      const current = useAuthStore.getState();
      if (current.tenant?.id !== tenantId || current.tenant?.slug !== tenantSlug || current.sessionGeneration !== generation) {
        throw sessionChangedError();
      }
    },
  };
}

interface RequestOptions {
  /** Preserve keys in domain maps such as ECS fields and user log payloads. */
  opaqueKeys?: readonly string[];
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  query?: Readonly<Record<string, unknown>>;
  /** Skip the demo fallback and surface transport failures to the caller. */
  noFallback?: boolean;
  signal?: AbortSignal;
  timeoutMs?: number;
  /**
   * 显式指定本次请求的 Bearer 令牌。
   *
   * 用于**尚未建立会话**的场景——典型是首登强制改密：此时只有一次性的
   * `change_token`，认证态还没写进 authStore，走默认的 `currentToken()` 会拿不到令牌。
   */
  token?: string;
}

function buildQuery(query?: Record<string, unknown>): string {
  if (!query) {
    return '';
  }
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') {
      continue;
    }
    if (key === 'sortOrder') continue;
    const wireKey = ({ pageSize: 'page_size', keyword: 'q', sortBy: 'sort' } as Record<string, string>)[key] ?? key;
    if (key === 'sortBy') {
      const field = String(value).replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
      params.append(wireKey, `${query.sortOrder === 'desc' ? '-' : ''}${field}`);
    } else if (Array.isArray(value)) {
      for (const item of value) {
        params.append(wireKey, String(item));
      }
    } else {
      params.append(wireKey, String(value));
    }
  }
  const text = params.toString();
  return text ? `?${text}` : '';
}

function joinUrl(path: string): string {
  const base = API_BASE_URL.replace(/\/$/, '');
  return `${base}${path}`;
}

/**
 * 尽力读出 RFC 9457（`application/problem+json`）里的可读原因。
 *
 * 后端大多数错误响应带 `{type,title,status,detail}`；但**登录失败是例外**——为了避免
 * 账号枚举，认证失败返回空体的 401。因此这里读不到就返回空串，由
 * [`describeHttpFailure`] 给出面向用户的兜底文案。
 */
async function readProblemDetail(response: Response): Promise<string> {
  try {
    const text = await response.text();
    if (!text) {
      return '';
    }
    const parsed = JSON.parse(text) as { detail?: unknown; title?: unknown; message?: unknown };
    for (const key of ['detail', 'title', 'message'] as const) {
      const value = parsed[key];
      if (typeof value === 'string' && value.trim()) {
        return value.trim();
      }
    }
    return '';
  } catch {
    return '';
  }
}

/**
 * 把 HTTP 失败翻译成用户看得懂的一句话。
 *
 * 之前直接抛 `HTTP 401 for /api/v1/auth/login`，用户在界面上只能看到这串技术串，
 * 完全不知道是"口令不对"还是"服务没起来"。现在按状态码给中文原因，并附上服务端 detail。
 */
function describeHttpFailure(status: number, path: string, detail: string): string {
  const friendly = (() => {
    switch (status) {
      case 400:
        return '请求被拒绝（参数或格式不合法）';
      case 401:
        return path.includes('/auth/login')
          ? '账号或口令不正确（若为首次登录，请使用部署端 .env 中 AGF_BOOTSTRAP_ADMIN_PASSWORD 的初始口令）'
          : '登录状态已失效，请重新登录';
      case 403:
        return '请求被权限或安全策略拒绝';
      case 404:
        return '资源或接口不存在，请核对地址和当前租户';
      case 409:
        return '当前状态存在冲突，请刷新并核对后再操作';
      case 412:
        return '尚未满足操作条件';
      case 429:
        return '请求过于频繁，已被限流';
      default:
        return status >= 500 ? '服务端错误' : '请求失败';
    }
  })();
  const suffix = detail ? `：${detail}` : '';
  return `${friendly}（HTTP ${status} ${path}）${suffix}`;
}

/**
 * 探测后端是否可用（登录页用它决定展示"演示凭据"还是"平台账号"提示）。
 *
 * 走同源的 `/healthz`（nginx 已反代到 `agf-server`），因此不需要认证、也不会产生 401 噪音。
 */
export async function probeBackend(timeoutMs = 3_000): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(joinUrl('/healthz'), {
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    return response.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Perform one HTTP call. Throws `ApiRequestError` for anything that is not a
 * 2xx JSON response.
 */
async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, query, signal, timeoutMs = API_TIMEOUT_MS, token: explicitToken, opaqueKeys } = options;
  const publicAuth = /^\/api\/v1\/auth\/(?:login|refresh|oidc\/|ldap\/login|saml\/|qr\/(?:start|status|complete)(?:$|\/))/.test(path);
  const scope = captureRequestScope();
  const assertScope = () => {
    if (!publicAuth) scope.assertCurrent();
  };
  // Keep the selected tenant, URL and body from invocation, including while token refresh waits.
  const serializedBody = body === undefined ? undefined : JSON.stringify(body);
  const requestUrl = joinUrl(`${path}${buildQuery(query)}`);
  const token = explicitToken ?? (publicAuth ? currentToken() : await sessionToken());
  assertScope();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const abort = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener('abort', abort, { once: true });
  }

  const headers: Record<string, string> = { Accept: 'application/json' };
  if (serializedBody !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  if (scope.tenantId && !publicAuth && !explicitToken) {
    headers['X-AGF-Tenant'] = scope.tenantId;
  }

  try {
    const response = await fetch(requestUrl, {
      method,
      headers,
      body: serializedBody,
      signal: controller.signal,
      credentials: 'same-origin',
    });

    if (!response.ok) {
      // Preserve the original 401 result; expireSession already protects a newer login.
      if (response.status !== 401) assertScope();
      if (response.status === 401 && token && !publicAuth && !explicitToken) {
        useAuthStore.getState().expireSession(token);
      }
      const fallbackable = response.status >= 500 || response.status === 404;
      const detail = await readProblemDetail(response);
      if (response.status !== 401) assertScope();
      throw new ApiRequestError(
        describeHttpFailure(response.status, path, detail),
        response.status,
        `http_${response.status}`,
        fallbackable,
      );
    }

    assertScope();
    const text = await response.text();
    assertScope();
    if (!text) {
      return undefined as T;
    }
    try {
      return adaptResponse(path, camelizeDeep(JSON.parse(text), opaqueKeys)) as T;
    } catch {
      throw new ApiRequestError(
        `Non-JSON response for ${path}`,
        response.status,
        'invalid_json',
        true,
      );
    }
  } catch (error) {
    if (error instanceof ApiRequestError) {
      throw error;
    }
    assertScope();
    const aborted = error instanceof DOMException && error.name === 'AbortError';
    throw new ApiRequestError(
      aborted ? `Request timed out after ${timeoutMs}ms` : `Network error for ${path}`,
      aborted ? 408 : 0,
      aborted ? 'timeout' : 'network',
      true,
    );
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
  }
}

/**
 * The single entry point used by the whole console.
 *
 * `fallback` is a synchronous producer for the demo dataset. It is only invoked
 * when the live call fails (or when demo mode is forced), which keeps the demo
 * data out of the hot path for connected deployments.
 */
export async function callApi<T>(
  path: string,
  fallback: () => T,
  options: RequestOptions = {},
): Promise<ApiResult<T>> {
  const started = Date.now();

  if (FORCE_DEMO && !options.noFallback) {
    markDemo('VITE_FORCE_DEMO=true');
    return { data: fallback(), meta: { source: 'demo', elapsedMs: 0, reason: 'forced', at: started } };
  }

  try {
    const data = await request<T>(path, options);
    markLive();
    return { data, meta: { source: 'live', elapsedMs: Date.now() - started, at: started } };
  } catch (error) {
    const apiError =
      error instanceof ApiRequestError
        ? error
        : new ApiRequestError('Unexpected client error', 0, 'unknown', true);
    if (options.noFallback || currentToken() || (options.method && options.method !== 'GET') || !apiError.fallbackable) {
      throw apiError;
    }
    markDemo(apiError.code);
    return {
      data: fallback(),
      meta: {
        source: 'demo',
        elapsedMs: Date.now() - started,
        reason: apiError.message,
        at: started,
      },
    };
  }
}

/** Binary downloads use the same tenant and authentication boundary as JSON requests. */
export async function downloadArtifact(path: string, filename: string): Promise<void> {
  const scope = captureRequestScope();
  const token = await sessionToken();
  scope.assertCurrent();
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (scope.tenantId) headers['X-AGF-Tenant'] = scope.tenantId;
  const response = await fetch(joinUrl(path), { headers, credentials: 'same-origin', signal: AbortSignal.timeout(API_TIMEOUT_MS) });
  if (!response.ok) {
    if (response.status !== 401) scope.assertCurrent();
    if (response.status === 401 && token) useAuthStore.getState().expireSession(token);
    const detail = await readProblemDetail(response);
    if (response.status !== 401) scope.assertCurrent();
    throw new Error(describeHttpFailure(response.status, path, detail));
  }
  scope.assertCurrent();
  const artifact = await response.blob();
  scope.assertCurrent();
  const url = URL.createObjectURL(artifact);
  const link = document.createElement('a');
  link.href = url; link.download = filename.replace(/[<>:"/\\|?*]/g, '_');
  document.body.appendChild(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
