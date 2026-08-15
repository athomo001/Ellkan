// Autor: Athan Espinoza

// Token de dispositivo persistente (F-02) — sólo su hash SHA-256 viaja al
// servidor, nunca el token en claro. Vive en `storage.local` (nunca
// `storage.session`): tiene que sobrevivir a que se cierre el navegador —
// es lo que le permite al servidor reconocer este dispositivo en el
// próximo login sin repetir la verificación por email/MFA.
//
// 2026-08-15: a diferencia de `frontend/src/lib/crypto/device.ts` (donde
// nunca se limpia), acá SÍ se purga — pero únicamente en un logout
// EXPLÍCITO (`AuthService.logout`), nunca en un lock por inactividad ni en
// un reinicio de navegador. El pedido de sesión inteligente exige que el
// próximo inicio tras un logout deliberado sea "desde cero" (incluida
// verificación de dispositivo real), y eso sólo funciona si el dispositivo
// deja de ser "conocido" para el servidor en ese momento puntual.

import { BrowserApi } from '../../browser-api';

const CLAVE = 'ellkan.device_token';

async function tokenCrudo(): Promise<Uint8Array> {
	const r = await BrowserApi.storageLocalGet<Record<string, number[]>>(CLAVE);
	const existente = r[CLAVE];
	if (existente) return new Uint8Array(existente);

	const nuevo = crypto.getRandomValues(new Uint8Array(32));
	await BrowserApi.storageLocalSet({ [CLAVE]: Array.from(nuevo) });
	return nuevo;
}

export async function deviceTokenHashB64(): Promise<string> {
	const token = await tokenCrudo();
	const hash = await crypto.subtle.digest('SHA-256', token as BufferSource);
	const bytes = new Uint8Array(hash);
	let binario = '';
	for (const b of bytes) binario += String.fromCharCode(b);
	return btoa(binario);
}

/** Sólo desde un logout explícito (ver comentario de arriba) — el próximo
 * `deviceTokenHashB64()` genera un token nuevo, así que el servidor vuelve
 * a ver "dispositivo no reconocido". */
export async function borrarTokenDeDispositivo(): Promise<void> {
	await BrowserApi.storageLocalRemove(CLAVE);
}
