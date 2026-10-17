import type { LoginRequest, LoginResponse, PasswordPolicy, Tenant, User } from '@/types/domain';

/* ------------------------------------------------------------------ */
/* 后端契约适配：snake_case → camelCase，登录/改密响应整形              */
/* ------------------------------------------------------------------ */

/**
 * 把后端 JSON 的 snake_case 键递归转成前端类型使用的 camelCase。
 *
 * 为什么需要：平台 API 全量使用 snake_case（`page_size` / `risk_score` /
 * `must_change_password` / `tokens.access_token`），而控制台的 domain 类型是 camelCase。
 * 不做转换时列表分页字段读不到、表格单元格全空，首登改密也会被静默跳过。
 * 数组与嵌套对象一并处理；值本身（含自由文本与 base64）不改动。
 */
export function camelizeDeep(value: unknown, opaqueKeys: readonly string[] = []): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => camelizeDeep(item, opaqueKeys));
  }
  if (value !== null && typeof value === 'object') {
    const source = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(source)) {
      const camel = key.replace(/_([a-z0-9])/g, (_m, c: string) => c.toUpperCase());
      out[camel] = opaqueKeys.includes(key) ? item : camelizeDeep(item, opaqueKeys);
    }
    return out;
  }
  return value;
}

/** API 登录响应（camelize 之后的形状），字段与 `crates/agf-api/src/routes/auth.rs` 对应。 */
export interface RawLoginResponse {
  passwordPolicy?: PasswordPolicy;
  roles?: string[];
  mfaEnrollmentRequired?: boolean;
  mustChangePassword?: boolean;
  changeToken?: string;
  tokens?: { accessToken?: string; refreshToken?: string } | null;
  user?: {
    id?: string;
    tenantId?: string;
    username?: string;
    displayName?: string;
    email?: string;
    state?: string;
    isSuperadmin?: boolean;
    roles?: string[];
    mfaEnabled?: boolean;
    lastLoginAt?: string;
  };
}

/**
 * 把 API 的登录响应整形成控制台 domain 的 `LoginResponse`。
 *
 * 入参容忍**原始 snake_case JSON**（函数内部先 camelize；已 camel 的键再转一次是幂等的），
 * 这样单测可以直接喂后端真实响应原文。
 */
export function adaptLoginResponse(rawInput: unknown, payload: LoginRequest): LoginResponse {
  const raw = camelizeDeep(rawInput) as RawLoginResponse;
  const rawUser = raw.user ?? {};
  const firstLogin = raw.mustChangePassword === true;
  // 首登只给一次性 change_token（用它调改密）；正常登录才给会话令牌。
  const token = firstLogin
    ? (raw.changeToken ?? '')
    : (raw.tokens?.accessToken ?? raw.changeToken ?? '');
  const role = mapRole(raw.roles ?? rawUser.roles ?? [], rawUser.isSuperadmin === true);
  const nowIso = new Date().toISOString();
  return {
    token,
    refreshToken: firstLogin || raw.mfaEnrollmentRequired ? undefined : raw.tokens?.refreshToken,
    passwordPolicy: raw.passwordPolicy,
    mfaEnrollmentRequired: raw.mfaEnrollmentRequired === true,
    mustChangePassword: firstLogin,
    user: {
      id: rawUser.id ?? '',
      tenantId: rawUser.tenantId ?? '',
      username: rawUser.username ?? payload.username,
      displayName: rawUser.displayName || rawUser.username || payload.username,
      email: rawUser.email ?? '',
      role,
      mfaEnabled: rawUser.mfaEnabled === true,
      mustChangePassword: firstLogin,
      lastLoginAt: rawUser.lastLoginAt ?? nowIso,
      status: rawUser.state === 'locked' || rawUser.state === 'disabled' ? rawUser.state : 'active',
    } as User,
    tenant: {
      version: 0,
      id: rawUser.tenantId ?? '',
      slug: payload.tenantSlug || 'default',
      name: '默认租户',
      plan: 'enterprise',
      region: 'cn-hangzhou',
      whiteLabel: { productName: 'AIGuardFabric 智御矩阵', logoText: 'AGF', primaryColor: '#1677ff' },
      quotaDefaults: {
        version: 0,
        tenantTokensPerDay: 0,
        agentTokensPerHour: 0,
        sessionTokensPerTurn: 0,
        maxConcurrentSessions: 0,
      },
      createdAt: nowIso,
    } as Tenant,
  };
}

/** 改密响应（`crates/agf-api/src/routes/auth.rs::change_password` 的真实形状）。 */
export interface ChangePasswordResponse {
  status: string;
  mustChangePassword?: boolean;
  message?: string;
}

/** `/ingest/replay` 的真实响应（snake_case；`request()` 已 camelize）。 */
export interface RawReplayResponse {
  rawLogs?: Array<{ payload?: string | null; decodeError?: string | null }>;
  replayed?: number;
  newlyParsed?: number;
  failed?: number;
  parserUsed?: Record<string, number>;
}

/** 平台角色（`superadmin`/`tenant-admin`/`soc-analyst`…）→ 控制台角色枚举。 */
function mapRole(roles: string[], isSuperadmin: boolean): User['role'] {
  if (isSuperadmin || roles.includes('superadmin')) {
    return 'owner';
  }
  const table: Record<string, User['role']> = {
    'tenant-admin': 'admin',
    'soc-analyst': 'analyst',
    'redteam-engineer': 'responder',
    'asset-owner': 'viewer',
    auditor: 'auditor',
    viewer: 'viewer',
  };
  for (const role of roles) {
    const mapped = table[role];
    if (mapped) {
      return mapped;
    }
  }
  return 'viewer';
}
