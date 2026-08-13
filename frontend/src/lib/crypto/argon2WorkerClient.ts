// Autor: Athan Espinoza

// Wrapper del hilo principal para `argon2Worker.ts` — sellar/abrir la clave
// privada (Argon2id real) corre en un Worker dedicado en vez del hilo
// principal, para que el login/registro/cambio de passphrase no congele la
// UI visible. RPC simple por `id` de correlación, mismo criterio que
// cualquier cola de pedidos concurrentes contra un único worker.

interface ResultadoSellar {
	ciphertext: Uint8Array;
	nonce: Uint8Array;
}
interface ResultadoAbrir {
	x25519Private: Uint8Array;
	ed25519Private: Uint8Array;
}

let worker: Worker | null = null;
let siguienteId = 0;
const pendientes = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

function obtenerWorker(): Worker {
	if (!worker) {
		worker = new Worker(new URL('./argon2Worker.ts', import.meta.url), { type: 'module' });
		worker.onmessage = (evento: MessageEvent<{ id: number; ok: boolean; resultado?: unknown; error?: string }>) => {
			const pedido = pendientes.get(evento.data.id);
			if (!pedido) return;
			pendientes.delete(evento.data.id);
			if (evento.data.ok) pedido.resolve(evento.data.resultado);
			else pedido.reject(new Error(evento.data.error ?? 'error desconocido en argon2Worker'));
		};
	}
	return worker;
}

function pedir<T>(mensaje: Record<string, unknown>): Promise<T> {
	const id = siguienteId++;
	return new Promise<T>((resolve, reject) => {
		pendientes.set(id, { resolve: resolve as (v: unknown) => void, reject });
		obtenerWorker().postMessage({ ...mensaje, id });
	});
}

export function sellarClavePrivadaEnWorker(
	passphrase: string,
	salt: Uint8Array,
	x25519Private: Uint8Array,
	ed25519Private: Uint8Array,
	aad: Uint8Array
): Promise<ResultadoSellar> {
	return pedir<ResultadoSellar>({ tipo: 'sellar', passphrase, salt, x25519Private, ed25519Private, aad });
}

export function abrirClavePrivadaEnWorker(
	passphrase: string,
	salt: Uint8Array,
	nonce: Uint8Array,
	ciphertext: Uint8Array,
	aad: Uint8Array
): Promise<ResultadoAbrir> {
	return pedir<ResultadoAbrir>({ tipo: 'abrir', passphrase, salt, nonce, ciphertext, aad });
}
