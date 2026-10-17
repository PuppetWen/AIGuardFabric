import { callApi } from './transport';
import { adaptLoginResponse } from './contract';
import type { LoginRequest, LoginResponse } from '@/types/domain';

export interface OidcSettings {
  revision: string | null;
  enabled: boolean; name: string; issuer: string; clientId: string;
  clientAuth: 'client_secret_basic' | 'client_secret_post' | 'none';
  clientSecret?: string; credentialConfigured: boolean; redirectUri: string;
  autoProvision: boolean; defaultRole: string; emailDomains: string[]; discovered: boolean;
}
export interface OidcFlow {
  tenantSlug: string; state: string; binding: string; createdAt: number;
}
const unavailable = (): never => { throw new Error('企业登录需要连接后端'); };
const flowBody = (flow: OidcFlow) => ({ tenant_slug: flow.tenantSlug, state: flow.state, binding: flow.binding });
export const OIDC_STORAGE_KEY = 'agf-oidc-flow';
export const SAML_STORAGE_KEY = 'agf-saml-flow';
export const ssoApi = {
  settings: () => callApi<OidcSettings>('/api/v1/settings/identity/oidc', unavailable, { noFallback: true }),
  save: (v: OidcSettings, expectedRevision: string | null) => callApi<OidcSettings>('/api/v1/settings/identity/oidc', unavailable, {
    method: 'PUT', noFallback: true, timeoutMs: 20000, body: { expected_revision: expectedRevision,
      enabled: v.enabled, name: v.name,
      issuer: v.issuer, client_id: v.clientId, client_auth: v.clientAuth, client_secret: v.clientSecret,
      redirect_uri: v.redirectUri, auto_provision: v.autoProvision, default_role: v.defaultRole, email_domains: v.emailDomains },
  }),
  start: (tenantSlug: string) => callApi<{ authorizationUrl: string; state: string; binding: string; redirectUri: string }>(
    '/api/v1/auth/oidc/start', unavailable, { method: 'POST', noFallback: true, body: { tenant_slug: tenantSlug } }),
  exchange: (flow: OidcFlow, code: string) => callApi<{ mfaRequired: boolean }>('/api/v1/auth/oidc/exchange', unavailable,
    { method: 'POST', noFallback: true, timeoutMs: 30000, body: { ...flowBody(flow), code } }),
  complete: async (flow: OidcFlow, mfaCode?: string) => {
    const response = await callApi<unknown>('/api/v1/auth/oidc/complete', unavailable,
      { method: 'POST', noFallback: true, body: { ...flowBody(flow), mfa_code: mfaCode } });
    return adaptLoginResponse(response.data, { tenantSlug: flow.tenantSlug, username: '', password: '' });
  },
  ldapSettings: () => callApi<LdapSettings>('/api/v1/settings/identity/ldap', unavailable, { noFallback: true }),
  saveLdap: (v: LdapSettings, expectedRevision: string | null) => callApi<LdapSettings>('/api/v1/settings/identity/ldap', unavailable, {
    method: 'PUT', noFallback: true, body: { expected_revision: expectedRevision, enabled: v.enabled,
      name: v.name, auto_provision: v.autoProvision, default_role: v.defaultRole,
      bind_password: v.bindPassword, config: { url: v.config.url, start_tls: v.config.startTls,
        base_dn: v.config.baseDn, bind_dn: v.config.bindDn, user_filter: v.config.userFilter,
        id_attribute: v.config.idAttribute, email_attribute: v.config.emailAttribute,
        name_attribute: v.config.nameAttribute, ca_pem: v.config.caPem } },
  }),
  ldapLogin: async (payload: LoginRequest) => {
    const response = await callApi<unknown>('/api/v1/auth/ldap/login', unavailable, {
      method: 'POST', noFallback: true, body: { tenant_slug: payload.tenantSlug,
        username: payload.username, password: payload.password, mfa_code: payload.mfaCode },
    });
    return { ...response, data: adaptLoginResponse(response.data, payload) as LoginResponse };
  },
  samlSettings: () => callApi<SamlSettings>('/api/v1/settings/identity/saml', unavailable, { noFallback: true }),
  saveSaml: (v: SamlSettings, expectedRevision: string | null, rotateSigningKey = false) =>
    callApi<SamlSettings>('/api/v1/settings/identity/saml', unavailable, {
      method: 'PUT', noFallback: true, body: { expected_revision: expectedRevision,
        enabled: v.enabled, name: v.name, idp_metadata_xml: v.idpMetadataXml,
        sp_entity_id: v.spEntityId, acs_url: v.acsUrl, auto_provision: v.autoProvision,
        default_role: v.defaultRole, email_domains: v.emailDomains,
        email_attribute: v.emailAttribute, name_attribute: v.nameAttribute,
        rotate_signing_key: rotateSigningKey },
    }),
  samlStart: (tenantSlug: string) => callApi<{ authorizationUrl: string; state: string; binding: string; redirectUri: string }>(
    '/api/v1/auth/saml/start', unavailable, { method: 'POST', noFallback: true, body: { tenant_slug: tenantSlug } }),
  samlStatus: (flow: SamlFlow) => callApi<{ mfaRequired: boolean }>('/api/v1/auth/saml/status', unavailable,
    { method: 'POST', noFallback: true, body: { tenant_slug: flow.tenantSlug, state: flow.state, binding: flow.binding } }),
  samlComplete: async (flow: SamlFlow, mfaCode?: string) => {
    const response = await callApi<unknown>('/api/v1/auth/saml/complete', unavailable, {
      method: 'POST', noFallback: true, body: { tenant_slug: flow.tenantSlug, state: flow.state,
        binding: flow.binding, mfa_code: mfaCode },
    });
    return adaptLoginResponse(response.data, { tenantSlug: flow.tenantSlug, username: '', password: '' });
  },
  qrStart: (tenantSlug: string) => callApi<{ state: string; binding: string; expiresAt: number }>(
    '/api/v1/auth/qr/start', unavailable, { method: 'POST', noFallback: true, body: { tenant_slug: tenantSlug } }),
  qrStatus: (flow: QrFlow) => callApi<{ status: 'pending' | 'approved'; expiresAt: number }>(
    '/api/v1/auth/qr/status', unavailable, { method: 'POST', noFallback: true,
      body: { tenant_slug: flow.tenantSlug, state: flow.state, binding: flow.binding } }),
  qrComplete: async (flow: QrFlow) => {
    const response = await callApi<unknown>('/api/v1/auth/qr/complete', unavailable, {
      method: 'POST', noFallback: true,
      body: { tenant_slug: flow.tenantSlug, state: flow.state, binding: flow.binding },
    });
    return adaptLoginResponse(response.data, { tenantSlug: flow.tenantSlug, username: '', password: '' });
  },
  qrPreview: (tenantSlug: string, state: string) => callApi<{ status: string; expiresAt: number; userName: string }>(
    `/api/v1/auth/qr/${encodeURIComponent(tenantSlug)}/${encodeURIComponent(state)}/preview`,
    unavailable, { noFallback: true }),
  qrApprove: (tenantSlug: string, state: string, mfaCode: string) => callApi<{ approved: boolean }>(
    `/api/v1/auth/qr/${encodeURIComponent(tenantSlug)}/${encodeURIComponent(state)}/approve`,
    unavailable, { method: 'POST', noFallback: true, body: { mfa_code: mfaCode } }),
};

export interface SamlFlow { tenantSlug: string; state: string; binding: string; createdAt: number }
export interface QrFlow { tenantSlug: string; state: string; binding: string; expiresAt: number }

export interface SamlSettings {
  revision: string | null;
  enabled: boolean; name: string; idpMetadataXml: string; idpEntityId: string;
  spEntityId: string; acsUrl: string; autoProvision: boolean; defaultRole: string;
  emailDomains: string[]; emailAttribute: string; nameAttribute: string;
  signingCertificate: string;
}

export interface LdapSettings {
  revision: string | null;
  enabled: boolean;
  name: string;
  credentialConfigured: boolean;
  bindPassword?: string;
  autoProvision: boolean;
  defaultRole: string;
  config: {
    url: string; startTls: boolean; baseDn: string; bindDn: string; userFilter: string;
    idAttribute: string; emailAttribute: string; nameAttribute: string; caPem: string;
  };
}
