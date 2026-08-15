// Autor: Athan Espinoza

// Token de dispositivo persistente (F-02) — sólo su hash SHA-256 viaja al
// servidor, nunca el token en claro. Vive en `localStorage` directo (no en
// el registro de `declararStore`: nunca debe limpiarse en lock/logout —
// es lo que le permite al servidor reconocer este dispositivo en el
// próximo login sin repetir la verificación por email).

import { bytesABase64 } from './b64';

const CLAVE = 'ellkan:device_token';

function tokenCrudo(): Uint8Array {
	if (typeof localStorage === 'undefined') return crypto.getRandomValues(new Uint8Array(32));
	const existente = localStorage.getItem(CLAVE);
	if (existente) {
		return Uint8Array.from(atob(existente), (c) => c.charCodeAt(0));
	}
	const nuevo = crypto.getRandomValues(new Uint8Array(32));
	localStorage.setItem(CLAVE, btoa(String.fromCharCode(...nuevo)));
	return nuevo;
}

export async function deviceTokenHashB64(): Promise<string> {
	const token = tokenCrudo();
	const hash = await crypto.subtle.digest('SHA-256', token as BufferSource);
	return bytesABase64(new Uint8Array(hash));
}
