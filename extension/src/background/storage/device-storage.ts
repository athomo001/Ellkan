// Autor: Athan Espinoza

// Token de dispositivo persistente (F-02) — sólo su hash SHA-256 viaja al
// servidor, nunca el token en claro. Vive en `storage.local` (nunca
// `storage.session`): tiene que sobrevivir a que se cierre el navegador —
// es lo que le permite al servidor reconocer este dispositivo en el
// próximo login sin repetir la verificación por email. Nunca se limpia en
// logout, mismo criterio que `frontend/src/lib/crypto/device.ts`.

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
