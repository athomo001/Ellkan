// Autor: Athan Espinoza

// Wrapper del hilo principal para `argon2Worker.ts` — sellar/abrir la clave
// privada (Argon2id real) corre en un Worker dedicado en vez del hilo
// principal, para que el login/registro/cambio de passphrase no congele la
// UI visible. RPC simple por `id` de correlación, mismo criterio que
// cualquier cola de pedidos concurrentes contra un único worker.

/** QA-03: parámetros de Argon2id de un blob (`user_keys.kdf_params`). */
export interface ParametrosKdf {
	m_cost_kib: number;
	t_cost: number;
	p_cost: number;
}
export interface ResultadoSellar {
	ciphertext: Uint8Array;
	nonce: Uint8Array;
	/** QA-03: `auth_key` del mismo Argon2id, para registrar el verificador. */
	authKey: Uint8Array;
	/** Los parámetros actuales con que se selló. */
	kdfParams: ParametrosKdf;
}
interface ResultadoDerivar {
	authKey: Uint8Array;
	claveEnvoltura: Uint8Array;
}
export interface ResultadoAbrir {
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
			// Sin pedidos en curso se cierra: la memoria wasm de Argon2 (64 MiB que
			// nunca se devuelven mientras el worker vive) se libera entera, y con
			// ella los restos de la derivación. Desbloquear es poco frecuente;
			// recrearlo cuesta unos milisegundos.
			if (pendientes.size === 0) {
				worker?.terminate();
				worker = null;
			}
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

/** QA-03: el paso caro del desbloqueo, con la sal y los parámetros del
 * servidor (el WASM rechaza parámetros fuera de rango). */
export function derivarDesbloqueoEnWorker(
	passphrase: string,
	salt: Uint8Array,
	parametros: ParametrosKdf
): Promise<ResultadoDerivar> {
	return pedir<ResultadoDerivar>({ tipo: 'derivar', passphrase, salt, parametros });
}

/** Abre el blob con la clave de envoltura de `derivarDesbloqueoEnWorker`. */
export function abrirClavePrivadaEnWorker(
	claveEnvoltura: Uint8Array,
	nonce: Uint8Array,
	ciphertext: Uint8Array,
	aad: Uint8Array
): Promise<ResultadoAbrir> {
	return pedir<ResultadoAbrir>({ tipo: 'abrir', claveEnvoltura, nonce, ciphertext, aad });
}
