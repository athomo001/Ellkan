// Autor: Athan Espinoza

// F-20: wrappers tipados de los endpoints `/admin/*` — cada handler ya
// existe en el backend desde 1.1-1.3, esto sólo les da forma de TS. Tipos
// en snake_case (igual que el JSON real) para no tener que mapear ida y
// vuelta en cada pantalla — a diferencia de `preferences.ts`, acá no hay
// convención camelCase previa que respetar.

import { get } from 'svelte/store';
import { api } from './client';
import { sesion } from '$lib/state/session';

// --- roles ---
export interface Rol {
	id: string;
	name: string;
	permissions: string[];
	created_at: string;
}
export const rolesApi = {
	listar: () => api.get<Rol[]>('/admin/roles'),
	crear: (name: string, permissions: string[]) => api.post<Rol>('/admin/roles', { name, permissions }),
	actualizarPermisos: (id: string, permissions: string[]) =>
		api.put<Rol>(`/admin/roles/${id}`, { permissions })
};

// --- audit log ---
export interface AuditLogEntry {
	id: string;
	actor_user_id: string | null;
	actor_email: string | null;
	event_type: string;
	subject_type: string | null;
	subject_id: string | null;
	metadata: unknown;
	created_at: string;
}
export interface AuditLogPage {
	items: AuditLogEntry[];
	next_cursor: string | null;
}
export interface AuditLogFiltro {
	cursor?: string;
	actor_user_id?: string;
	event_type?: string;
	from?: string;
	to?: string;
}
function queryString(filtro: Record<string, string | undefined>): string {
	const params = new URLSearchParams();
	for (const [k, v] of Object.entries(filtro)) if (v) params.set(k, v);
	const s = params.toString();
	return s ? `?${s}` : '';
}
/**
 * El export exige `Authorization: Bearer` como cualquier otro endpoint — un
 * `<a href>` normal del navegador no manda ese header, así que no alcanza
 * con armar la URL y dejar que el link la abra: hay que pedirla con fetch
 * autenticado y disparar la descarga a mano vía Blob.
 */
async function descargarExport(filtro: AuditLogFiltro, format: 'ndjson' | 'csv'): Promise<void> {
	const sessionId = get(sesion).sessionId;
	const resp = await fetch(`/admin/audit-log/export${queryString({ ...filtro, format })}`, {
		headers: sessionId ? { Authorization: `Bearer ${sessionId}` } : {}
	});
	if (!resp.ok) throw new Error(`export falló: ${resp.status}`);
	const blob = await resp.blob();
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	a.download = `audit-log.${format === 'ndjson' ? 'ndjson' : 'csv'}`;
	a.click();
	URL.revokeObjectURL(url);
}

export const auditLogApi = {
	listar: (filtro: AuditLogFiltro) => api.get<AuditLogPage>(`/admin/audit-log${queryString({ ...filtro })}`),
	descargarExport
};

// --- políticas: MFA ---
export interface MfaPolicy {
	require_mfa: boolean;
	allowed_methods: string[];
	grace_period_days: number;
	require_mfa_since: string | null;
}
export const mfaPolicyApi = {
	obtener: () => api.get<MfaPolicy>('/admin/mfa-policy'),
	actualizar: (p: Omit<MfaPolicy, 'require_mfa_since'>) => api.put<MfaPolicy>('/admin/mfa-policy', p)
};

// --- SMTP (editable desde el admin, Parte A — reemplaza el env-var) ---
export interface SmtpConfig {
	configurado: boolean;
	host: string | null;
	port: number | null;
	from_address: string | null;
	tls: boolean;
	username: string | null;
}
export interface ActualizarSmtpConfig {
	host: string;
	port: number;
	from_address: string;
	tls: boolean;
	username: string | null;
	/** `null` conserva la contraseña guardada; `''` la borra. */
	password: string | null;
}
export const smtpConfigApi = {
	obtener: () => api.get<SmtpConfig>('/admin/smtp-config'),
	actualizar: (c: ActualizarSmtpConfig) => api.put<SmtpConfig>('/admin/smtp-config', c)
};

// --- políticas: password ---
export interface PasswordPolicy {
	min_passphrase_length: number;
	min_passphrase_entropy_bits: number;
	passphrase_rotation_days: number | null;
	generator_default_length: number;
	generator_charset_rules: unknown;
	max_clipboard_clear_minutes: number | null;
	max_auto_lock_minutes: number | null;
}
export const passwordPolicyApi = {
	obtener: () => api.get<PasswordPolicy>('/admin/password-policy'),
	actualizar: (p: PasswordPolicy) => api.put<PasswordPolicy>('/admin/password-policy', p)
};

// --- políticas: auto-registro (F-24) ---
export interface SelfRegistrationPolicy {
	enabled: boolean;
	allowed_domains: string[];
}
export const selfRegistrationPolicyApi = {
	obtener: () => api.get<SelfRegistrationPolicy>('/admin/self-registration-policy'),
	actualizar: (p: SelfRegistrationPolicy) => api.put<SelfRegistrationPolicy>('/admin/self-registration-policy', p)
};

// --- políticas: retención ---
export interface RetentionPolicy {
	data_retention_days: number;
	audit_log_retention_days: number;
}
export const retentionPolicyApi = {
	obtener: () => api.get<RetentionPolicy>('/admin/data-retention-policy'),
	actualizar: (p: RetentionPolicy) => api.put<RetentionPolicy>('/admin/data-retention-policy', p)
};

// --- políticas: account recovery ---
export interface AccountRecoveryPolicy {
	required: boolean;
	grace_period_days: number;
	default_approval_threshold: number;
}
export const accountRecoveryPolicyApi = {
	obtener: () => api.get<AccountRecoveryPolicy>('/admin/account-recovery-policy'),
	actualizar: (p: AccountRecoveryPolicy) => api.put<AccountRecoveryPolicy>('/admin/account-recovery-policy', p)
};

// F-16: descubribilidad de solicitudes de recuperación — el id de una
// solicitud sólo lo conoce quien la creó, este listado es la única forma
// de que un admin se entere de que hay algo pendiente de aprobar.
export interface SolicitudRecoveryAdmin {
	id: string;
	target_email: string;
	status: string;
	approvals_count: number;
	approval_threshold: number;
	created_at: string;
}
interface SolicitudRecoveryTrasAprobar {
	id: string;
	status: string;
	approvals_count: number;
	sealed_private_key_for_requester_b64: string | null;
}
export const accountRecoveryAdminApi = {
	listarPendientes: () => api.get<SolicitudRecoveryAdmin[]>('/admin/account-recovery/requests'),
	aprobar: (id: string) => api.post<SolicitudRecoveryTrasAprobar>(`/admin/account-recovery/requests/${id}/approve`)
};

// --- políticas: emergency access ---
export interface EmergencyAccessPolicy {
	enabled: boolean;
}
export const emergencyAccessPolicyApi = {
	obtener: () => api.get<EmergencyAccessPolicy>('/admin/emergency-access-policy'),
	actualizar: (p: EmergencyAccessPolicy) => api.put<EmergencyAccessPolicy>('/admin/emergency-access-policy', p)
};

// --- políticas: aprobación de dispositivo ---
export interface DeviceApprovalPolicy {
	allow_peer_device_approval: boolean;
	allow_admin_device_approval: boolean;
}
export const deviceApprovalPolicyApi = {
	obtener: () => api.get<DeviceApprovalPolicy>('/admin/device-approval-policy'),
	actualizar: (p: DeviceApprovalPolicy) => api.put<DeviceApprovalPolicy>('/admin/device-approval-policy', p)
};

// --- SSO ---
export interface SsoConfig {
	issuer_url: string | null;
	client_id: string | null;
	jit_provisioning_enabled: boolean;
}
export const ssoApi = {
	obtener: () => api.get<SsoConfig>('/admin/sso-config'),
	actualizar: (c: SsoConfig) => api.put<SsoConfig>('/admin/sso-config', c)
};

// --- SCIM ---
export const scimApi = {
	crearToken: () => api.post<{ token: string }>('/admin/scim-tokens')
};

// --- Directory sync (LDAP) ---
export interface DirectorySyncConfig {
	ldap_url: string | null;
	bind_dn: string | null;
	require_starttls: boolean;
	base_dn: string | null;
	user_filter: string | null;
	attribute_mapping: Record<string, string>;
	last_sync_at: string | null;
}
export interface DirectorySyncConfigUpdate {
	ldap_url?: string;
	bind_dn?: string;
	bind_password?: string;
	require_starttls: boolean;
	base_dn?: string;
	user_filter?: string;
	attribute_mapping: Record<string, string>;
}
export interface ResultadoSync {
	would_create: string[];
	would_reactivate: string[];
	would_deactivate: string[];
	unchanged: number;
	conflicts: string[];
}
export const directorySyncApi = {
	obtenerConfig: () => api.get<DirectorySyncConfig>('/admin/directory-sync/config'),
	actualizarConfig: (c: DirectorySyncConfigUpdate) => api.put<DirectorySyncConfig>('/admin/directory-sync/config', c),
	dryRun: () => api.post<ResultadoSync>('/admin/directory-sync/dry-run'),
	aplicar: () => api.post<ResultadoSync>('/admin/directory-sync/apply')
};

// --- Metadata keys ---
export interface MetadataKeyAdmin {
	id: string;
	public_key_x25519_b64: string;
	fingerprint: string;
	expired_at: string | null;
	own_sealed_private_key_b64: string | null;
}
export interface RotationStatus {
	activa: boolean;
	saliente_id: string | null;
	entrante_id: string | null;
	total_al_iniciar: number | null;
	pendientes: number | null;
}
export const metadataKeysApi = {
	listar: () => api.get<MetadataKeyAdmin[]>('/metadata-keys'),
	crear: (id: string, publicKeyX25519B64: string, fingerprint: string, destinatarios: { user_id: string; sealed_private_key_b64: string }[]) =>
		api.post<MetadataKeyAdmin>('/admin/metadata-keys', {
			id,
			public_key_x25519_b64: publicKeyX25519B64,
			fingerprint,
			destinatarios
		}),
	rotar: (id: string, publicKeyX25519B64: string, fingerprint: string, destinatarios: { user_id: string; sealed_private_key_b64: string }[]) =>
		api.post<MetadataKeyAdmin>('/admin/metadata-keys/rotate', {
			id,
			public_key_x25519_b64: publicKeyX25519B64,
			fingerprint,
			destinatarios
		}),
	estadoRotacion: () => api.get<RotationStatus>('/admin/metadata-keys/rotation-status')
};

// --- Usuarios ---
export interface UsuarioAdmin {
	id: string;
	email: string;
	display_name: string;
	active: boolean;
	has_avatar: boolean;
	groups: string[];
	owned_resources_count: number;
	shared_with_count: number;
}
export interface GrupoBloqueado {
	group_id: string;
	name: string;
}
export interface PurgeDryRun {
	blocked_groups: GrupoBloqueado[];
	blocked_resources: string[];
	blocks_purge: boolean;
}
export interface UsuariosPage {
	items: UsuarioAdmin[];
	next_cursor: string | null;
}
export const usersAdminApi = {
	buscarPorEmail: (email: string) => api.get<{ user_id: string }>(`/users/${encodeURIComponent(email)}/public-key`),
	obtener: (id: string) => api.get<UsuarioAdmin>(`/admin/users/${id}`),
	actualizarActivo: (id: string, active: boolean) => api.put<UsuarioAdmin>(`/admin/users/${id}`, { active }),
	purgeDryRun: (id: string) => api.get<PurgeDryRun>(`/admin/users/${id}/purge/dry-run`),
	purgar: (id: string) => api.post<{ resources_huerfanos_eliminados: number }>(`/admin/users/${id}/purge`, { transfer: {} }),
	/** F-29: listado completo paginado, además de la búsqueda por email de arriba. */
	listar: (cursor?: string, active?: boolean) =>
		api.get<UsuariosPage>(`/admin/users${queryString({ cursor, active: active === undefined ? undefined : String(active) })}`)
};

/** Post-cierre bloque C: avatar de un usuario ajeno (`GET /me/avatar` sólo
 * sirve el propio) — mismo patrón que `obtenerAvatarUrl` en `profile.ts`
 * (bytes crudos, no JSON, hay que pedirlo con el Bearer a mano). */
export async function obtenerAvatarUrlAdmin(userId: string): Promise<string | null> {
	const sessionId = get(sesion).sessionId;
	const resp = await fetch(`/admin/users/${userId}/avatar`, {
		headers: sessionId ? { Authorization: `Bearer ${sessionId}` } : {}
	});
	if (resp.status === 404) return null;
	if (!resp.ok) throw new Error(`avatar: ${resp.status}`);
	const blob = await resp.blob();
	return URL.createObjectURL(blob);
}

// --- Reportes (F-23) ---
export type ReportId = 'passwords_expired' | 'mfa_coverage' | 'inactive_users' | 'resources_never_rotated';
export interface ReportItem {
	user_id?: string;
	email?: string;
	resource_id?: string;
	created_by?: string | null;
	mfa_enabled?: boolean;
	passphrase_set_at?: string;
	last_login_at?: string | null;
	created_at?: string;
}
export interface ReportPage {
	report_id: ReportId;
	items: ReportItem[];
	next_cursor: string | null;
}
export const reportsApi = {
	/** `days` sólo aplica a `inactive_users`/`resources_never_rotated` — se ignora en el resto. */
	obtener: (reportId: ReportId, cursor?: string, days?: number) =>
		api.get<ReportPage>(
			`/admin/reports/${reportId}${queryString({ cursor, days: days === undefined ? undefined : String(days) })}`
		)
};

// --- Grupos ---
export interface Miembro {
	user_id: string;
	is_admin: boolean;
}
export interface Grupo {
	id: string;
	name: string;
	parent_group_id: string | null;
	members: Miembro[];
}
export interface EnvelopeParaGrupo {
	resource_id: string;
	sealed_dek_b64: string;
	secret_ciphertext_b64: string;
	secret_nonce_b64: string;
}
export const groupsApi = {
	listar: () => api.get<Grupo[]>('/groups'),
	crear: (id: string, name: string, parentGroupId?: string) =>
		api.post<Grupo>('/groups', { id, name, parent_group_id: parentGroupId }),
	obtener: (id: string) => api.get<Grupo>(`/groups/${id}`),
	eliminar: (id: string) => api.delete<void>(`/groups/${id}`),
	/** F-12: recursos actualmente compartidos con el grupo — lo que hay que re-sellar antes de agregar un miembro nuevo. */
	recursosCompartidos: (groupId: string) => api.get<string[]>(`/groups/${groupId}/resources`),
	agregarMiembro: (groupId: string, userId: string, isAdmin: boolean, envelopes: EnvelopeParaGrupo[] = []) =>
		api.post<void>(`/groups/${groupId}/members/${userId}`, { is_admin: isAdmin, envelopes }),
	quitarMiembro: (groupId: string, userId: string) => api.delete<void>(`/groups/${groupId}/members/${userId}`)
};

// --- Estado del sistema (F-43): unión discriminada por `id`, igual
// criterio que `ReportResponse`/`report_id` en el backend — un `id` cerrado
// por variante, nunca texto libre (la traducción vive en `$t`, F-31). ---
export type NivelCheck = 'ok' | 'advertencia' | 'error';
export type Check =
	| { id: 'db_ping'; nivel: NivelCheck }
	| { id: 'db_migraciones'; nivel: NivelCheck; aplicadas: number; fallidas: number }
	| { id: 'smtp_configurado'; nivel: NivelCheck; configurado: boolean }
	| { id: 'correo_backlog'; nivel: NivelCheck; pendientes: number; fallidos: number }
	| { id: 'sso_configurado'; nivel: NivelCheck; configurado: boolean }
	| {
			id: 'directory_sync_configurado';
			nivel: NivelCheck;
			configurado: boolean;
			ultima_sincronizacion: string | null;
	  }
	| { id: 'metadata_key_rotacion'; nivel: NivelCheck; claves_activas: number }
	| { id: 'origen_seguro'; nivel: NivelCheck; origen: string };
export interface GrupoChecks {
	categoria: 'base_datos' | 'correo' | 'integraciones' | 'seguridad';
	checks: Check[];
}
export const systemStatusApi = {
	obtener: () => api.get<GrupoChecks[]>('/admin/system-status')
};
