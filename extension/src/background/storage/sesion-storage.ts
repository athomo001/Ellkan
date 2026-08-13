// Autor: Athan Espinoza

// Nivel 2 del storage (spec 06 §3): passphrase y claves de sesión (DEKs
// descifradas) en `browser.storage.session` — memoria volátil gestionada
// por el propio navegador, se borra sola al cerrarlo, sin código de
// limpieza propio que pueda tener un bug. Store genérico por clave: hoy
// sólo lo usa la passphrase (F-04), sirve igual para las DEKs de sesión que
// se necesiten cuando exista Vault en la extensión — no hace falta un tipo
// dedicado por cada secreto efímero, todos comparten la misma garantía de
// storage (volátil, nunca disco).
//
// Nivel 1 (clave privada nunca cacheada descifrada) no tiene módulo propio
// a propósito: la regla es no escribir ese caché, no envolverlo — se
// reconstruye siempre desde el blob (`storage.local`, cifrado con
// Argon2id+AEAD) + la passphrase de acá, nunca se guarda el resultado.

import { BrowserApi } from '../../browser-api';

const PREFIJO = 'ellkan.sesion.';

export const SesionStorage = {
	async guardar(clave: string, valor: string): Promise<void> {
		await BrowserApi.storageSessionSet({ [PREFIJO + clave]: valor });
	},

	async leer(clave: string): Promise<string | null> {
		const r = await BrowserApi.storageSessionGet<Record<string, string>>(PREFIJO + clave);
		return r[PREFIJO + clave] ?? null;
	},

	async limpiar(clave: string): Promise<void> {
		await BrowserApi.storageSessionRemove(PREFIJO + clave);
	}
};
