// Typed client for the Certower REST API. Authentication uses the
// HttpOnly session cookie set by /auth/login, so no token is kept in JS.

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public body?: unknown,
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch("/api/v1" + path, {
    method,
    credentials: "same-origin",
    headers: body !== undefined || method !== "GET" ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : method !== "GET" ? "{}" : undefined,
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const data = text ? safeJSON(text) : undefined;
  if (!res.ok) {
    const err = (data as { error?: { code?: string; message?: string } } | undefined)?.error;
    throw new ApiError(res.status, err?.code ?? "error", err?.message ?? res.statusText, data);
  }
  return (data ?? text) as T;
}

function safeJSON(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body),
  del: (path: string) => request<void>("DELETE", path),
};

// ------------------------------------------------------------------ types

export interface User {
  id: string;
  email: string;
  displayName: string;
  isSuperuser: boolean;
  disabled: boolean;
  createdAt: string;
}

export interface RoleBinding {
  id: string;
  orgId: string;
  projectId?: string;
  role: string;
  userId?: string;
  serviceAccountId?: string;
  oidcGroup?: string;
  createdAt: string;
}

export interface Me {
  type: "user" | "service_account";
  user?: User;
  bindings: RoleBinding[];
}

export interface Organization {
  id: string;
  slug: string;
  name: string;
  createdAt: string;
}

export interface Project {
  id: string;
  orgId: string;
  slug: string;
  name: string;
  createdAt: string;
}

export interface Policy {
  allowedNames: string[] | null;
  allowedIssuers: string[] | null;
  allowedKeyTypes: string[] | null;
  allowWildcard: boolean;
  maxValidityDays: number;
}

export interface Violation {
  field: string;
  value: string;
  reason: string;
}

export type CertStatus = "pending" | "active" | "failing" | "invalid";

export interface Version {
  id: string;
  certificateId: string;
  serial: string;
  fingerprint: string;
  ariCertId?: string;
  notBefore: string;
  notAfter: string;
  renewAfter: string;
  revokedAt?: string;
  revokeReason?: number;
  ariCheckedAt?: string;
  createdAt: string;
}

export interface Certificate {
  id: string;
  projectId: string;
  name: string;
  names: string[];
  keyType: string;
  issuerConfigId: string;
  dnsConfigId?: string;
  profile?: string;
  keyLocation: "server" | "agent";
  renewBeforeRatio: number;
  ownerEmail?: string;
  status: CertStatus;
  lastError?: string;
  renewRequestedAt?: string;
  createdAt: string;
  current?: Version;
}

export interface PluginMeta {
  name: string;
  kind: "issuer" | "dns" | "deployer" | "notifier";
  version: string;
  description: string;
  runsOn: string;
  requiresDns?: boolean;
  configSchema?: JSONSchema;
}

export interface JSONSchema {
  type?: string;
  title?: string;
  format?: string;
  const?: unknown;
  minimum?: number;
  enum?: string[];
  required?: string[];
  properties?: Record<string, JSONSchema>;
  items?: JSONSchema;
  "x-secret"?: boolean;
  "x-generated"?: boolean;
}

export interface PluginConfig {
  id: string;
  orgId: string;
  projectId?: string;
  kind: string;
  plugin: string;
  name: string;
  config: Record<string, unknown>;
  createdAt: string;
}

export interface CAPreset {
  id: string;
  name: string;
  directoryUrl: string;
  requiresEab: boolean;
  docsUrl: string;
  notes?: string;
}

export interface Agent {
  id: string;
  projectId: string;
  name: string;
  hostname?: string;
  os?: string;
  version?: string;
  enrolled: boolean;
  enrollExpiresAt?: string;
  lastSeenAt?: string;
  createdAt: string;
}

export interface Target {
  id: string;
  projectId: string;
  name: string;
  agentId: string;
  deployer: string;
  settings: Record<string, unknown>;
  createdAt: string;
}

export interface DeploymentView {
  target: string;
  targetId: string;
  versionId?: string;
  status: "done" | "failed" | "pending";
  message?: string;
  finishedAt?: string;
  current: boolean;
}

export interface Job {
  id: string;
  type: string;
  status: string;
  attempts: number;
  runAfter: string;
  lastError?: string;
  createdAt: string;
}

export interface AuditEntry {
  id: number;
  at: string;
  orgId?: string;
  projectId?: string;
  actorType: string;
  actorId: string;
  action: string;
  objectType: string;
  objectId: string;
  before?: unknown;
  after?: unknown;
  sourceIp?: string;
}

export interface RoleInfo {
  name: string;
  builtin: boolean;
  permissions: string[];
}

export interface ServiceAccount {
  id: string;
  projectId: string;
  name: string;
  createdAt: string;
}

export interface Finding {
  code: string;
  severity: "info" | "warning" | "critical";
  message: string;
}

export interface DiscoveredCert {
  id: string;
  fingerprint: string;
  subject: string;
  issuer: string;
  names: string[];
  notBefore: string;
  notAfter: string;
  findings: Finding[];
  versionId?: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface DiscoveryEndpoint {
  id: string;
  orgId: string;
  projectId?: string;
  host: string;
  port: number;
  sni?: string;
  lastScannedAt?: string;
  lastError?: string;
  certificate?: DiscoveredCert;
  managed?: { project: string; certificate: string };
}
