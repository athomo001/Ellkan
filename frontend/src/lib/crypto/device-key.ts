// Autor: Athan Espinoza

// Clave AES-GCM `extractable:false` por dispositivo, guardada como objeto
// `CryptoKey` en IndexedDB (los navegadores soportan clonar `CryptoKey` vía
// structured clone desde hace años — no hace falta serializarla a bytes, lo
// que además sería imposible para una clave no-extraíble). Usada para
// envolver secretos que necesitan sobrevivir entre sesiones en este
// dispositivo sin quedar legibles por un simple volcado de storage — ver
// `totp-local.ts` (H-01, auditoría 2026-08-12).

const DB_NAME = 'ellkan-device-keys';
const STORE_NAME = 'claves';

function abrirDb(): Promise<IDBDatabase> {
	return new Promise((resolve, reject) => {
		const req = indexedDB.open(DB_NAME, 1);
		req.onupgradeneeded = () => {
			req.result.createObjectStore(STORE_NAME);
		};
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error);
	});
}

async function leerClave(db: IDBDatabase, nombre: string): Promise<CryptoKey | undefined> {
	return new Promise((resolve, reject) => {
		const tx = db.transaction(STORE_NAME, 'readonly');
		const req = tx.objectStore(STORE_NAME).get(nombre);
		req.onsuccess = () => resolve(req.result as CryptoKey | undefined);
		req.onerror = () => reject(req.error);
	});
}

async function guardarClave(db: IDBDatabase, nombre: string, clave: CryptoKey): Promise<void> {
	return new Promise((resolve, reject) => {
		const tx = db.transaction(STORE_NAME, 'readwrite');
		tx.objectStore(STORE_NAME).put(clave, nombre);
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error);
	});
}

/**
 * Devuelve la clave de dispositivo para `nombre`, generándola la primera vez.
 * No-extraíble: ningún código (ni el legítimo) puede leer sus bytes crudos,
 * sólo pedirle al navegador que cifre/descifre con ella.
 */
export async function obtenerClaveDeDispositivo(nombre: string): Promise<CryptoKey> {
	const db = await abrirDb();
	const existente = await leerClave(db, nombre);
	if (existente) return existente;

	const nueva = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
		'encrypt',
		'decrypt'
	]);
	await guardarClave(db, nombre, nueva);
	return nueva;
}

export async function borrarClaveDeDispositivo(nombre: string): Promise<void> {
	const db = await abrirDb();
	await new Promise<void>((resolve, reject) => {
		const tx = db.transaction(STORE_NAME, 'readwrite');
		tx.objectStore(STORE_NAME).delete(nombre);
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error);
	});
}
