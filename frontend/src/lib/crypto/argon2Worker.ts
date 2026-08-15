/// <reference lib="webworker" />
// Autor: Athan Espinoza

// Worker dedicado para sellar/abrir el blob de clave privada — los dos
// únicos call sites reales de la cadena Argon2id→HKDF→AEAD (spec 05, gate
// transversal de Fase 0: sin esto, cada login/registro/cambio de passphrase
// congela visiblemente la UI del hilo principal mientras corre Argon2id a
// los parámetros pineados de `02-modelo-de-datos.md`). Mismo wasm que el
// resto de la app, cargado una sola vez dentro de este worker.

import init, * as ellkanCrypto from '$lib/wasm/ellkan_crypto.js';

const ctx = self as unknown as DedicatedWorkerGlobalScope;

let listo: Promise<typeof ellkanCrypto> | null = null;
function cargar(): Promise<typeof ellkanCrypto> {
	if (!listo) listo = init().then(() => ellkanCrypto);
	return listo;
}

interface PedidoSellar {
	tipo: 'sellar';
	id: number;
	passphrase: string;
	salt: Uint8Array;
	x25519Private: Uint8Array;
	ed25519Private: Uint8Array;
	aad: Uint8Array;
}
interface PedidoAbrir {
	tipo: 'abrir';
	id: number;
	passphrase: string;
	salt: Uint8Array;
	nonce: Uint8Array;
	ciphertext: Uint8Array;
	aad: Uint8Array;
}
type Pedido = PedidoSellar | PedidoAbrir;

ctx.onmessage = async (evento: MessageEvent<Pedido>) => {
	const pedido = evento.data;
	try {
		const wasm = await cargar();
		if (pedido.tipo === 'sellar') {
			const blob = wasm.sellar_clave_privada(
				pedido.passphrase,
				pedido.salt,
				pedido.x25519Private,
				pedido.ed25519Private,
				pedido.aad
			);
			const resultado = { ciphertext: blob.ciphertext, nonce: blob.nonce };
			blob.free();
			ctx.postMessage({ id: pedido.id, ok: true, resultado });
		} else {
			const abierta = wasm.abrir_clave_privada(
				pedido.passphrase,
				pedido.salt,
				pedido.nonce,
				pedido.ciphertext,
				pedido.aad
			);
			const resultado = { x25519Private: abierta.x25519_private, ed25519Private: abierta.ed25519_private };
			abierta.free();
			ctx.postMessage({ id: pedido.id, ok: true, resultado });
		}
	} catch (e) {
		ctx.postMessage({ id: pedido.id, ok: false, error: e instanceof Error ? e.message : String(e) });
	}
};
