// Autor: Athan Espinoza

// F-16: wrapper de los endpoints públicos/de usuario de Account Recovery —
// distinto de `accountRecoveryPolicyApi`/`accountRecoveryAdminApi`
// (`$lib/api/admin.ts`, sólo admin). `crearSolicitud`/`estadoSolicitud`/
// `completar` no llevan sesión a propósito (ver `account_recovery::handlers`
// en el backend): cubren justo el caso de alguien que perdió la passphrase
// y por eso no puede autenticarse de ningún otro modo.

import { api } from './client';

export const accountRecoveryApi = {
	miEstado: () => api.get<{ enrolled: boolean }>('/account-recovery/status'),
	orgPublicKey: () => api.get<{ public_key_x25519_b64: string }>('/account-recovery/org-public-key'),
	enrolar: (sealedPrivateKeyForOrgB64: string) =>
		api.post<{ id: string; created_at: string }>('/account-recovery/enroll', {
			sealed_private_key_for_org_b64: sealedPrivateKeyForOrgB64
		}),
	crearSolicitud: (email: string, requesterPublicKeyX25519B64: string) =>
		api.post<SolicitudRecovery>('/account-recovery/requests', {
			email,
			requester_public_key_x25519_b64: requesterPublicKeyX25519B64
		}),
	estadoSolicitud: (id: string) => api.get<SolicitudRecovery>(`/account-recovery/requests/${id}`),
	completar: (id: string, blobB64: string, nonceB64: string, saltB64: string) =>
		api.post<void>(`/account-recovery/requests/${id}/complete`, {
			encrypted_private_key_blob_b64: blobB64,
			private_key_nonce_b64: nonceB64,
			kdf_salt_b64: saltB64
		})
};

export interface SolicitudRecovery {
	id: string;
	status: string;
	approvals_count: number;
	sealed_private_key_for_requester_b64: string | null;
}
