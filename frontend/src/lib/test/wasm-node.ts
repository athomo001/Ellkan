// Autor: Athan Espinoza

// QA-14 (pendiente #103): en los tests (Node) el WASM de `ellkan-crypto` no
// se puede pedir por `fetch` como en el navegador; se lee del disco y se
// inicializa con los bytes. Es el mismo módulo que usa la app, nunca una
// implementación aparte.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import init, * as ellkanCrypto from '#lib/wasm/ellkan_crypto.js';

let listo: Promise<typeof ellkanCrypto> | null = null;

export function cargarCryptoEnNode(): Promise<typeof ellkanCrypto> {
	if (!listo) {
		const ruta = fileURLToPath(new URL('../wasm/ellkan_crypto_bg.wasm', import.meta.url));
		listo = init({ module_or_path: readFileSync(ruta) }).then(() => ellkanCrypto);
	}
	return listo;
}
