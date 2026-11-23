/// <reference lib="webworker" />
// Autor: Athan Espinoza

// Worker dedicado para sellar/abrir el blob de clave privada — los únicos
// call sites reales de la cadena Argon2id→HKDF→AEAD (spec 05, gate
// transversal de Fase 0: sin esto, cada login/registro/cambio de passphrase
// congela visiblemente la UI del hilo principal mientras corre Argon2id).
// Mismo wasm que el resto de la app, cargado una sola vez dentro de este
// worker.
//
// QA-03: el desbloqueo es en dos pasos. `derivar` corre Argon2id con la sal
// y los parámetros que devolvió `/auth/prelogin` y entrega la `auth_key`
// (para pedir el blob) y la clave de envoltura (para abrirlo); `abrir` ya no
// deriva nada. `sellar` usa siempre los parámetros actuales del crate.

import init, * as ellkanCrypto from '$lib/wasm/ellkan_crypto.js';

const ctx = self as unknown as DedicatedWorkerGlobalScope;

let listo: Promise<typeof ellkanCrypto> | null = null;
function cargar(): Promise<typeof ellkanCrypto> {
	if (!listo) listo = init().then(() => ellkanCrypto);
	return listo;
}

interface ParametrosKdf {
	m_cost_kib: number;
	t_cost: number;
	p_cost: number;
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
interface PedidoDerivar {
	tipo: 'derivar';
	id: number;
	passphrase: string;
	salt: Uint8Array;
	parametros: ParametrosKdf;
}
interface PedidoAbrir {
	tipo: 'abrir';
	id: number;
	claveEnvoltura: Uint8Array;
	nonce: Uint8Array;
	ciphertext: Uint8Array;
	aad: Uint8Array;
}
type Pedido = PedidoSellar | PedidoDerivar | PedidoAbrir;

ctx.onmessage = async (evento: MessageEvent<Pedido>) => {
	const pedido = evento.data;
	try {
		const wasm = await cargar();
		if (pedido.tipo === 'sellar') {
			const [m, t, p] = wasm.parametros_kdf_actuales();
			const blob = wasm.sellar_clave_privada(
				pedido.passphrase,
				pedido.salt,
				m,
				t,
				p,
				pedido.x25519Private,
				pedido.ed25519Private,
				pedido.aad
			);
			const resultado = {
				ciphertext: blob.ciphertext,
				nonce: blob.nonce,
				authKey: blob.auth_key,
				kdfParams: { m_cost_kib: m, t_cost: t, p_cost: p }
			};
			blob.free();
			ctx.postMessage({ id: pedido.id, ok: true, resultado });
		} else if (pedido.tipo === 'derivar') {
			const { m_cost_kib, t_cost, p_cost } = pedido.parametros;
			const d = wasm.derivar_desbloqueo(pedido.passphrase, pedido.salt, m_cost_kib, t_cost, p_cost);
			const resultado = { authKey: d.auth_key, claveEnvoltura: d.clave_envoltura };
			d.free();
			ctx.postMessage({ id: pedido.id, ok: true, resultado });
		} else {
			const abierta = wasm.abrir_clave_privada(pedido.claveEnvoltura, pedido.nonce, pedido.ciphertext, pedido.aad);
			const resultado = { x25519Private: abierta.x25519_private, ed25519Private: abierta.ed25519_private };
			abierta.free();
			ctx.postMessage({ id: pedido.id, ok: true, resultado });
		}
	} catch (e) {
		ctx.postMessage({ id: pedido.id, ok: false, error: e instanceof Error ? e.message : String(e) });
	}
};
