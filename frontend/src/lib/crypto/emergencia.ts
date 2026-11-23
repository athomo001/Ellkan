// Autor: Athan Espinoza

// F-36 (pendiente #131): el material del acceso de emergencia es el mismo
// que el de F-16 (las dos claves privadas del titular, 64 bytes), sellado
// para la clave pública X25519 del contacto en vez de la de la organización.
//
// 04-seguridad §"key escrow": el servidor podría entregar una clave pública
// falsa para quedarse con el material. Por eso la pantalla muestra la huella
// de la clave del contacto antes de sellar, para compararla con la que el
// contacto ve en su propia cuenta («Mis claves»).

import { api } from '$lib/api/client';
import { base64ABytes, bytesABase64 } from './b64';
import { sellarMaterialParaOrg } from './accountRecovery';
import type { ClavesDesbloqueadas } from '$lib/state/session';

export interface ContactoConClave {
	user_id: string;
	public_key_x25519_b64: string;
	/** Huella de la clave pública, mismo formato que «Mis claves». */
	huella: string;
}

/** Huella de una clave pública con el formato de «Mis claves»
 * (`settings/keys`): SHA-256 en base64, primeros 16 caracteres. Tiene que
 * coincidir exacto para que el contacto pueda compararla. */
export async function huellaDeClave(publicaB64: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(base64ABytes(publicaB64)));
	return bytesABase64(new Uint8Array(digest)).slice(0, 16);
}

export async function buscarContacto(email: string): Promise<ContactoConClave> {
	const r = await api.get<{ user_id: string; public_key_x25519_b64: string }>(`/users/${encodeURIComponent(email.trim())}/public-key`);
	return { ...r, huella: await huellaDeClave(r.public_key_x25519_b64) };
}

export function sellarMaterialParaContacto(contacto: ContactoConClave, claves: ClavesDesbloqueadas): Promise<string> {
	return sellarMaterialParaOrg(contacto.public_key_x25519_b64, claves);
}
