// Autor: Athan Espinoza

// Carga perezosa (una sola vez) de `ellkan_crypto.wasm` — mismo crate que
// el backend, compilado a WASM (01-propuesta-tecnica.md §3.4). Nunca una
// segunda implementación JS de la criptografía.

import init, * as ellkanCrypto from '$lib/wasm/ellkan_crypto.js';

let listo: Promise<typeof ellkanCrypto> | null = null;

export function cargarCrypto(): Promise<typeof ellkanCrypto> {
	if (!listo) {
		listo = init().then(() => ellkanCrypto);
	}
	return listo;
}
