// Autor: Athan Espinoza

// Chequeo mínimo del storage en 3 niveles (spec 06 §3) — mockea
// `chrome.storage.session`/`local` en memoria (Node no tiene esas APIs) y
// ejercita el wasm real compartido con el frontend (`generar_dek`/
// `cifrar_aead`/`descifrar_aead`), no una versión de prueba. Prueba en
// particular la regla dura: sin la clave efímera en `storage.session`, todo
// residuo cifrado en `storage.local` se trata como huérfano y se descarta.
//
// Correr: node run-self-check.mjs --storage (ver run-self-check.mjs)

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

// El wasm-bindgen glue carga el `.wasm` vía `fetch(new URL(...))` — correcto
// en un service worker real, pero el `fetch` de Node no sabe resolver
// `file://` (ni falta que le haga: no es su trabajo). Se intercepta sólo
// para este chequeo, para poder ejercitar el wasm real sin un navegador.
// El build de este harness (modo `ssr` de Vite, necesario para que
// `node:fs`/`node:url` resuelvan) no copia el `.wasm` como asset separado
// igual que el build real de la extensión — si el path bundleado no existe,
// se cae al artefacto real conocido (el mismo que usa el frontend).
// `process.cwd()` en vez de `import.meta.dirname`: este archivo corre
// bundleado desde `.self-check-storage-out/`, a una profundidad distinta de
// la fuente — `cwd` es estable porque `run-self-check.mjs` siempre invoca
// desde la raíz de `extension/`.
const ARTEFACTO_WASM_REAL = resolve(process.cwd(), '../frontend/src/lib/wasm/ellkan_crypto_bg.wasm');
const fetchOriginal = globalThis.fetch;
globalThis.fetch = (async (entrada: RequestInfo | URL, init?: RequestInit) => {
	const url = typeof entrada === 'string' ? entrada : entrada instanceof URL ? entrada.href : entrada.url;
	if (url.endsWith('.wasm')) {
		let ruta: string;
		try {
			ruta = fileURLToPath(url);
			readFileSync(ruta);
		} catch {
			ruta = ARTEFACTO_WASM_REAL;
		}
		return new Response(readFileSync(ruta), { headers: { 'Content-Type': 'application/wasm' } });
	}
	return fetchOriginal(entrada, init);
}) as typeof fetch;

function mapStorage() {
	const datos = new Map<string, unknown>();
	return {
		async get(keys: string | string[] | null): Promise<Record<string, unknown>> {
			const lista = keys === null ? [...datos.keys()] : Array.isArray(keys) ? keys : [keys];
			const resultado: Record<string, unknown> = {};
			for (const k of lista) if (datos.has(k)) resultado[k] = datos.get(k);
			return resultado;
		},
		async set(items: Record<string, unknown>): Promise<void> {
			for (const [k, v] of Object.entries(items)) datos.set(k, v);
		},
		async remove(keys: string | string[]): Promise<void> {
			for (const k of Array.isArray(keys) ? keys : [keys]) datos.delete(k);
		},
		_datos: datos
	};
}

const sessionMock = mapStorage();
const localMock = mapStorage();
(globalThis as Record<string, unknown>).chrome = {
	storage: { session: sessionMock, local: localMock },
	// El valor exacto no importa — el parche de `fetch` de arriba cae al
	// artefacto real en cualquier error de resolución.
	runtime: { getURL: (path: string) => `file://${path}` }
};

const { SesionStorage } = await import('./src/background/storage/sesion-storage.ts');
const { MetadataCache } = await import('./src/background/storage/metadata-cache.ts');

async function main() {
	// --- Nivel 2: passphrase/DEKs en storage.session ---
	assert.equal(await SesionStorage.leer('passphrase'), null, 'sin nada guardado, debe leer null');
	await SesionStorage.guardar('passphrase', 'una-passphrase-de-prueba');
	assert.equal(await SesionStorage.leer('passphrase'), 'una-passphrase-de-prueba');
	await SesionStorage.limpiar('passphrase');
	assert.equal(await SesionStorage.leer('passphrase'), null, 'tras limpiar, debe volver a null');
	console.log('OK: SesionStorage (nivel 2) guarda/lee/limpia');

	// --- Nivel 3: metadata cache cifrada con clave efímera (wasm real) ---
	const datosDePrueba = { recursos: [{ id: '1', nombre: 'CRM Ventas' }] };
	await MetadataCache.guardar(datosDePrueba);
	assert.ok(localMock._datos.size > 0, 'debe haber escrito ciphertext en storage.local');
	const leido = await MetadataCache.leer();
	assert.deepEqual(leido, datosDePrueba, 'debe descifrar exactamente lo mismo que se guardó');
	console.log('OK: MetadataCache (nivel 3) cifra/descifra con la clave efímera (AEAD real via wasm)');

	// --- Regla dura: sin clave efímera en session, el residuo en local se purga ---
	sessionMock._datos.clear(); // simula sesión terminada / navegador reiniciado
	assert.ok(localMock._datos.size > 0, 'precondición: todavía hay ciphertext residual en local');
	const trasPerderLaClave = await MetadataCache.leer();
	assert.equal(trasPerderLaClave, null, 'sin la clave efímera, debe leer null (nunca intentar "recuperar")');
	assert.equal(localMock._datos.size, 0, 'el residuo huérfano debe purgarse, no quedar sin uso');
	console.log('OK: sin clave efímera, el residuo cifrado se purga en vez de reintentarse');

	console.log('\nself-check-storage: todo OK');
}

main().catch((e) => {
	console.error('self-check-storage FALLÓ:', e);
	process.exitCode = 1;
});
