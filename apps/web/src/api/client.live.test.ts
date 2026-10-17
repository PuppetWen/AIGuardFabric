// @vitest-environment node
// 必须用 Node 环境：jsdom 的 global（AbortController / 缺少 fetch）与 undici 不兼容，
// 会让真实请求直接抛错（实测表现是被客户端兜成 "Network error for /api/v1/auth/login"）。
import { describe, expect, it, vi } from 'vitest';

/**
 * **联调回归（opt-in）**：拿真实的 `agf-server` 校验控制台 API 客户端的契约。
 *
 * 为什么单独放一个文件：默认的 `pnpm test` 必须在**无后端**时可跑，所以这里用
 * `AGF_LIVE_API=1` 开关跳过。运行方式（compose 栈已起）：
 *
 * ```powershell
 * cd apps\web
 * $env:AGF_LIVE_API='1'
 * $env:AGF_LIVE_API_BASE='http://127.0.0.1:8080'
 * $env:AGF_LIVE_PASSWORD='<.env 里的 AGF_BOOTSTRAP_ADMIN_PASSWORD>'
 * $env:AGF_LIVE_NEW_PASSWORD='<改密后的新口令，仅首登需要>'
 * pnpm exec vitest run src/api/client.live.test.ts
 * ```
 *
 * 它验证的是**本项目真实踩过的坑**：后端全量 snake_case（`page_size` /
 * `must_change_password` / `tokens.access_token`）、首登只发一次性 `change_token`、
 * 改密要 `Authorization: Bearer <change_token>` + `{new_password}`。
 */
const LIVE = process.env.AGF_LIVE_API === '1';
const BASE = process.env.AGF_LIVE_API_BASE ?? 'http://127.0.0.1:8080';
const PASSWORD = process.env.AGF_LIVE_PASSWORD ?? '';
const NEW_PASSWORD = process.env.AGF_LIVE_NEW_PASSWORD ?? '';

type LoginFn = typeof import('@/api/client').api.login;
type LoginResult = Awaited<ReturnType<LoginFn>>;

/** 登录并吞掉可预期的失败（口令不对 / 账号锁定），便于幂等地尝试多个口令。 */
async function tryLogin(login: LoginFn, password: string): Promise<LoginResult | null> {
  try {
    return await login({ tenantSlug: 'default', username: 'admin', password });
  } catch {
    return null;
  }
}

describe.skipIf(!LIVE)('live agf-server contract', () => {
  it('登录 → （首登）改密 → 重新登录 → 带令牌读列表', async () => {
    expect(PASSWORD, '需要 AGF_LIVE_PASSWORD').not.toBe('');
    vi.stubEnv('VITE_API_BASE_URL', BASE);
    vi.stubEnv('VITE_API_TIMEOUT_MS', '15000');
    const { api, API_BASE_URL } = await import('@/api/client');
    expect(API_BASE_URL).toBe(BASE);

    // 幂等：先用"改密后口令"试一次（重复运行时不至于每次再改一遍），失败再回落到引导口令。
    // 注意服务端的登录失败锁定策略——反复用错口令会把账号锁成 403，届时
    // `docker compose restart agf-server` 即可（认证存储是进程内的，重启回到引导态）。
    let login = await tryLogin(api.login, NEW_PASSWORD || '__unset__');
    if (!login || login.data.mustChangePassword) {
      login = await tryLogin(api.login, PASSWORD);
    }
    expect(login, '两种口令都登录失败（检查服务是否在跑 / 账号是否被锁定）').not.toBeNull();
    const session = login as NonNullable<typeof login>;
    expect(session.meta.source, `应命中真实后端而不是 demo 兜底（reason=${session.meta.reason}）`).toBe('live');
    expect(session.data.token, '登录必须拿到可用令牌').not.toBe('');

    let active = session;
    if (active.data.mustChangePassword) {
      expect(NEW_PASSWORD, '首登需要 AGF_LIVE_NEW_PASSWORD 才能闭环').not.toBe('');
      const changed = await api.changePassword({
        token: active.data.token,
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
      });
      expect(changed.meta.source).toBe('live');
      expect(changed.data.status).toBe('ok');
      const relogin = await tryLogin(api.login, NEW_PASSWORD);
      expect(relogin, '改密后应能用新口令登录').not.toBeNull();
      active = relogin as NonNullable<typeof relogin>;
      expect(active.meta.source).toBe('live');
    }

    expect(active.data.mustChangePassword).toBe(false);
    expect(active.data.user.username).toBe('admin');
    expect(active.data.user.role).toBe('owner');

    // 与真实登录页一致：登录成功后把会话写进 authStore，后续请求才会带 Bearer 头
    // （不写就必然 401——这正是"能登录但页面全 401"的成因，实测踩过）。
    const { useAuthStore } = await import('@/stores/authStore');
    useAuthStore.getState().setSession({
      token: active.data.token,
      tenant: active.data.tenant,
      displayName: active.data.user.displayName,
      role: active.data.user.role,
      mustChangePassword: false,
    });

    const assets = await api.assets({}, { pageSize: 5 });
    expect(assets.meta.source).toBe('live');
    expect(Array.isArray(assets.data.items)).toBe(true);
    // `page_size` → `pageSize`：不做键名整形时这里会是 undefined（列表分页直接失灵）
    expect(typeof assets.data.pageSize).toBe('number');

    const findings = await api.findings({}, { pageSize: 5 });
    expect(findings.meta.source).toBe('live');
    expect(Array.isArray(findings.data.items)).toBe(true);
  }, 60_000);
});
