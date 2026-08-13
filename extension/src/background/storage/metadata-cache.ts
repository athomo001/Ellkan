// Autor: Athan Espinoza

// Nivel 3 del storage (spec 06 §3): caché de metadata descifrada (nombre/
// usuario/URI/notas, para listados y búsqueda rápidos) — cifrada en reposo
// con una clave simétrica efímera, nunca en claro. Decisión más estricta
// que Passbolt (cachea en claro) y adopta el patrón de Bitwarden: la clave
// efímera vive sólo en `storage.session` (se borra sola al cerrar el
// navegador), el ciphertext en `storage.local`. Si la clave efímera no está
// disponible al leer, el contenido cifrado residual es huérfano — se
// descarta, nunca se intenta "recuperar".
//
// El secreto en sí (contraseña, TOTP) NUNCA pasa por acá, cacheado ni en
// claro ni cifrado — eso sigue descifrándose on-demand y descartándose.

import { BrowserApi } from '../../browser-api';
import { cargarCrypto } from '../wasm';

const CLAVE_EFIMERA_SESSION_KEY = 'ellkan.cache.clave_efimera';
const CACHE_LOCAL_KEY = 'ellkan.cache.metadata';
const AAD = new TextEncoder().encode('ellkan:extension:metadata-cache:v1');

async function leerClaveEfimeraExistente(): Promise<Uint8Array | null> {
	const r = await BrowserApi.storageSessionGet<Record<string, number[]>>(CLAVE_EFIMERA_SESSION_KEY);
	const bytes = r[CLAVE_EFIMERA_SESSION_KEY];
	return bytes ? new Uint8Array(bytes) : null;
}

async function obtenerOCrearClaveEfimera(): Promise<Uint8Array> {
	const existente = await leerClaveEfimeraExistente();
	if (existente) return existente;

	// Sin clave efímera en `storage.session`: cualquier ciphertext que
	// hubiera en `storage.local` quedó huérfano (sesión anterior terminó,
	// navegador reinició, extensión se recargó) — se purga antes de generar
	// la clave nueva, nunca se intenta descifrarlo con una clave distinta.
	await BrowserApi.storageLocalRemove(CACHE_LOCAL_KEY);

	const wasm = await cargarCrypto();
	const clave = wasm.generar_dek();
	await BrowserApi.storageSessionSet({ [CLAVE_EFIMERA_SESSION_KEY]: Array.from(clave) });
	return clave;
}

export const MetadataCache = {
	/** Cifra `datos` (JSON-serializable) con la clave efímera de esta sesión
	 * y lo persiste en `storage.local`. */
	async guardar(datos: unknown): Promise<void> {
		const wasm = await cargarCrypto();
		const clave = await obtenerOCrearClaveEfimera();
		const plaintext = new TextEncoder().encode(JSON.stringify(datos));
		const cifrado = wasm.cifrar_aead(clave, plaintext, AAD);
		await BrowserApi.storageLocalSet({
			[CACHE_LOCAL_KEY]: { ciphertext: Array.from(cifrado.ciphertext), nonce: Array.from(cifrado.nonce) }
		});
	},

	/** `null` si no hay nada cacheado, o si la clave efímera no está
	 * disponible (sesión terminada) — en ese caso ya se purgó el residuo. */
	async leer<T = unknown>(): Promise<T | null> {
		const clave = await leerClaveEfimeraExistente();
		if (!clave) {
			// Mismo criterio que al escribir: sin clave, lo que haya en disco
			// es huérfano — se descarta en vez de dejarlo ahí sin uso.
			await BrowserApi.storageLocalRemove(CACHE_LOCAL_KEY);
			return null;
		}

		const r = await BrowserApi.storageLocalGet<Record<string, { ciphertext: number[]; nonce: number[] }>>(CACHE_LOCAL_KEY);
		const guardado = r[CACHE_LOCAL_KEY];
		if (!guardado) return null;

		const wasm = await cargarCrypto();
		const plaintext = wasm.descifrar_aead(clave, new Uint8Array(guardado.nonce), new Uint8Array(guardado.ciphertext), AAD);
		return JSON.parse(new TextDecoder().decode(plaintext)) as T;
	},

	async limpiar(): Promise<void> {
		await BrowserApi.storageSessionRemove(CLAVE_EFIMERA_SESSION_KEY);
		await BrowserApi.storageLocalRemove(CACHE_LOCAL_KEY);
	}
};
