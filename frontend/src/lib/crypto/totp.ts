// Autor: Athan Espinoza

// F-38: UI de TOTP — la derivación/verificación en sí vive en `ellkan-crypto`
// (Fase 0, desbloqueo local); esto es sólo el wrapper de los tres endpoints
// de MFA server-verified (F-14) que la pantalla de login necesita.

import { api } from '$lib/api/client';
import { deviceTokenHashB64 } from './device';

export interface SetupTotp {
	secretBase32: string;
	otpauthUri: string;
}

/** `POST /me/mfa/totp/setup` — sesión parcial (`SesionValida`) alcanza. */
export async function iniciarSetupTotp(): Promise<SetupTotp> {
	const resp = await api.post<{ secret_base32: string; otpauth_uri: string }>('/me/mfa/totp/setup');
	return { secretBase32: resp.secret_base32, otpauthUri: resp.otpauth_uri };
}

/**
 * `POST /me/mfa/totp/confirm` — confirmar el código completa la sesión en
 * el mismo paso (`MfaService::confirmar_setup_totp` marca
 * `mfa_verified_at`), no hace falta un `verificarLoginTotp` aparte después.
 * 2026-08-13: manda el device token también — este dispositivo recién
 * probó el segundo factor, no hace falta pedírselo nunca de nuevo (mismo
 * criterio que `verificarLoginTotp`).
 */
export async function confirmarSetupTotp(code: string): Promise<void> {
	await api.post('/me/mfa/totp/confirm', { code, device_token_hash_b64: await deviceTokenHashB64() });
}

/**
 * `POST /auth/mfa/verify` — login normal con TOTP (o código por email) ya
 * configurado. 2026-08-13: manda el device token — el backend recuerda que
 * este dispositivo ya pasó MFA y no lo vuelve a pedir en el próximo login
 * (`KnownDeviceRepository::marcar_mfa_confirmado`).
 */
export async function verificarLoginTotp(code: string): Promise<void> {
	await api.post('/auth/mfa/verify', { code, device_token_hash_b64: await deviceTokenHashB64() });
}
