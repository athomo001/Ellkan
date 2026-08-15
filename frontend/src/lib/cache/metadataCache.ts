// Autor: Athan Espinoza

// F-30 (07-frontend-web.md §4): metadata descifrada cacheable en IndexedDB
// para listados rápidos, **cifrada con una clave simétrica efímera de
// sesión** — mismo riesgo que `browser.storage.local` de la extensión
// (dispositivo con acceso de lectura al perfil después de que la sesión
// terminó), misma mitigación: la clave de cache vive sólo en
// `sessionStorage` (se pierde al cerrar la pestaña, nunca en IndexedDB
// junto al ciphertext que protege) y se borra explícitamente en logout.
//
// Guarda sólo lo que ya se descifró (nombre/usuario/uri, y para recursos
// `user_key` la DEK ya desenvuelta) — nunca ahorra la llamada de red que
// obtiene el `secret_ciphertext` en sí, sólo evita volver a pedir/desenvolver
// la DEK y a descifrar la metadata en cada carga del Vault si nada cambió.
// La clave de cache (`metadata_nonce_b64`) invalida sola: si la metadata de
// un recurso cambiara alguna vez (edición, todavía no implementada), el
// nonce cambia con ella y la entrada vieja deja de matchear.

import { cargarCrypto } from '$lib/crypto/wasm';
import { bytesABase64, base64ABytes } from '$lib/crypto/b64';

const DB_NAME = 'ellkan-cache';
const STORE = 'recursos';
const CLAVE_SESSION_STORAGE = 'ellkan:cache-key';

function abrirDb(): Promise<IDBDatabase> {
	return new Promise((resolve, reject) => {
		const req = indexedDB.open(DB_NAME, 1);
		req.onupgradeneeded = () => {
			req.result.createObjectStore(STORE, { keyPath: 'resourceId' });
		};
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error);
	});
}

async function claveEfimera(): Promise<Uint8Array> {
	const existente = sessionStorage.getItem(CLAVE_SESSION_STORAGE);
	if (existente) return base64ABytes(existente);

	const wasm = await cargarCrypto();
	const nueva = wasm.generar_dek();
	sessionStorage.setItem(CLAVE_SESSION_STORAGE, bytesABase64(nueva));
	return nueva;
}

/** Logout (F-04): la clave de cache se pierde, el ciphertext en IndexedDB queda inerte. */
export function olvidarClaveDeCache(): void {
	sessionStorage.removeItem(CLAVE_SESSION_STORAGE);
}

interface EntradaCache {
	resourceId: string;
	metadataNonceB64: string;
	cacheNonceB64: string;
	cacheCiphertextB64: string;
}

export async function guardarEnCache(
	resourceId: string,
	metadataNonceB64: string,
	valor: unknown
): Promise<void> {
	try {
		const wasm = await cargarCrypto();
		const clave = await claveEfimera();
		const aad = new TextEncoder().encode(resourceId);
		const cifrado = wasm.cifrar_aead(clave, new TextEncoder().encode(JSON.stringify(valor)), aad);
		const entrada: EntradaCache = {
			resourceId,
			metadataNonceB64,
			cacheNonceB64: bytesABase64(cifrado.nonce),
			cacheCiphertextB64: bytesABase64(cifrado.ciphertext)
		};
		const db = await abrirDb();
		await new Promise<void>((resolve, reject) => {
			const tx = db.transaction(STORE, 'readwrite');
			tx.objectStore(STORE).put(entrada);
			tx.oncomplete = () => resolve();
			tx.onerror = () => reject(tx.error);
		});
	} catch {
		// La cache es una optimización, no una fuente de verdad — si
		// IndexedDB no está disponible (modo privado, cuota, etc.) el
		// llamador simplemente vuelve a descifrar desde la red la próxima vez.
	}
}

export async function leerDeCache<T>(resourceId: string, metadataNonceB64: string): Promise<T | null> {
	try {
		const db = await abrirDb();
		const entrada = await new Promise<EntradaCache | undefined>((resolve, reject) => {
			const tx = db.transaction(STORE, 'readonly');
			const req = tx.objectStore(STORE).get(resourceId);
			req.onsuccess = () => resolve(req.result);
			req.onerror = () => reject(req.error);
		});
		if (!entrada || entrada.metadataNonceB64 !== metadataNonceB64) return null;

		const clave = await claveEfimera();
		const wasm = await cargarCrypto();
		const aad = new TextEncoder().encode(resourceId);
		const bytes = wasm.descifrar_aead(
			clave,
			base64ABytes(entrada.cacheNonceB64),
			base64ABytes(entrada.cacheCiphertextB64),
			aad
		);
		return JSON.parse(new TextDecoder().decode(bytes)) as T;
	} catch {
		return null; // clave de sesión distinta (pestaña nueva), entrada corrupta, o IndexedDB no disponible
	}
}
