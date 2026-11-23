// Autor: Athan Espinoza

// F-16: wrapper de los endpoints públicos/de usuario de Account Recovery —
// distinto de `accountRecoveryPolicyApi`/`accountRecoveryAdminApi`
// (`$lib/api/admin.ts`, sólo admin). `crearSolicitud`/`confirmar`/
// `estadoSolicitud`/`completar` no llevan sesión a propósito: cubren justo
// el caso de alguien que perdió la passphrase. En su lugar, la solicitud se
// confirma con el código que llega al email de la cuenta y eso entrega un
// token del solicitante, que es lo único que permite consultarla o
// completarla.

import { api } from './client';
import { camposDelBlob, type BlobClaveNueva, type PruebaDePosesion } from '$lib/crypto/desbloqueo';

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
	confirmar: (id: string, code: string) =>
		api.post<{ requester_token_b64: string }>(`/account-recovery/requests/${id}/confirm`, { code }),
	estadoSolicitud: (id: string, tokenB64: string) =>
		api.get<SolicitudRecovery>(`/account-recovery/requests/${id}`, { 'X-Ellkan-Recovery-Token': tokenB64 }),
	completar: (id: string, tokenB64: string, blob: BlobClaveNueva, prueba: PruebaDePosesion) =>
		api.post<void>(`/account-recovery/requests/${id}/complete`, {
			requester_token_b64: tokenB64,
			...camposDelBlob(blob),
			...prueba
		})
};

export interface SolicitudRecovery {
	id: string;
	status: string;
	approvals_count: number;
	sealed_private_key_for_requester_b64: string | null;
}
