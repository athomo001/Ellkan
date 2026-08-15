// Autor: Athan Espinoza

// Recovery kit: self-service, sin admin de por medio — distinto de F-16
// (`$lib/api/accountRecovery.ts`). `solicitarReset`/`verificarToken`/
// `enviarCodigoEmail`/`completar` no llevan sesión a propósito (ver
// `recovery_kit::handlers` en el backend).

import { api } from './client';

export interface EstadoRecoveryKit {
	configured: boolean;
	created_at: string | null;
	must_rotate: boolean;
}

export const recoveryKitApi = {
	estado: () => api.get<EstadoRecoveryKit>('/me/recovery-kit'),
	generar: (kitPublicKeyB64: string, sealedMaterialB64: string) =>
		api.put<{ created_at: string }>('/me/recovery-kit', {
			kit_public_key_x25519_b64: kitPublicKeyB64,
			sealed_identity_material_b64: sealedMaterialB64
		}),
	solicitarReset: (email: string) => api.post<void>('/recovery-kit/reset', { email }),
	verificarToken: (token: string) =>
		api.get<{ sealed_identity_material_b64: string; mfa_method: 'totp' | 'email'; email: string }>(
			`/recovery-kit/reset/${encodeURIComponent(token)}`
		),
	enviarCodigoEmail: (token: string) => api.post<void>(`/recovery-kit/reset/${encodeURIComponent(token)}/email-code`),
	completar: (token: string, mfaCode: string, blobB64: string, nonceB64: string, saltB64: string) =>
		api.post<void>(`/recovery-kit/reset/${encodeURIComponent(token)}/complete`, {
			mfa_code: mfaCode,
			encrypted_private_key_blob_b64: blobB64,
			private_key_nonce_b64: nonceB64,
			kdf_salt_b64: saltB64
		})
};
