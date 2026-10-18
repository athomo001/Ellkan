// Autor: Athan Espinoza

// Compartido por `client.ts` (backend local) y `sync/remoteClient.ts`
// (servidor remoto). El limitador por IP del servidor (`tower_governor`,
// `backend/src/lib.rs`) responde 429 con texto plano ("Too Many Requests!
// Wait for Xs"), no con el JSON de error de la API: un `JSON.parse` directo
// reventaba con `SyntaxError` y cada pantalla lo mostraba como su error
// genérico ("No se pudo cargar el vault"). Bug real 2026-10-17: importar o
// borrar 137 claves en el escritorio vinculado agotó la ráfaga y dejó la web
// y el escritorio sin poder listar.

const MAX_REINTENTOS_429 = 6;

function esperar(ms: number): Promise<void> {
	return new Promise((resolver) => setTimeout(resolver, ms));
}

/** `fetch` que reintenta los 429. Es seguro para cualquier método: un 429 lo
 * corta el limitador antes del handler, así que el pedido nunca se aplicó. */
export async function fetchConReintento(url: string, init: RequestInit): Promise<Response> {
	for (let intento = 0; ; intento++) {
		const resp = await fetch(url, init);
		if (resp.status !== 429 || intento >= MAX_REINTENTOS_429) return resp;
		// `retry-after` viene en segundos enteros y suele ser 0: se usa un piso
		// creciente con jitter para que varios pedidos en espera no vuelvan
		// todos en el mismo instante. `Math.random` es aceptable: es jitter de
		// espera, no material criptográfico (spec/09 §CSPRNG).
		const segundos = Number(resp.headers.get('retry-after')) || 0;
		const base = Math.max(segundos * 1000, 500 * 2 ** intento);
		await esperar(base + Math.random() * 250);
	}
}

/**
 * Acciones masivas (mover, borrar, taggear...): corre `accion` sobre cada id
 * con a lo más `limite` pedidos a la vez, en vez de `Promise.all` sobre todo
 * (que agotaba el límite por IP con muchos seleccionados). No corta al primer
 * fallo: devuelve qué ids se aplicaron y el primer error, para que la UI
 * refleje lo que sí se hizo.
 */
export async function porLotes(
	ids: string[],
	accion: (id: string) => Promise<unknown>,
	limite = 3
): Promise<{ aplicados: Set<string>; error?: unknown }> {
	const aplicados = new Set<string>();
	let error: unknown;
	let siguiente = 0;
	async function trabajador() {
		while (siguiente < ids.length) {
			const id = ids[siguiente++];
			try {
				await accion(id);
				aplicados.add(id);
			} catch (err) {
				error ??= err;
			}
		}
	}
	await Promise.all(Array.from({ length: Math.min(limite, ids.length) }, trabajador));
	return { aplicados, error };
}

/** JSON si el cuerpo lo es; si no (texto plano del limitador, HTML de un
 * proxy), `undefined` — el caller arma el error con el status HTTP. */
export function parsearCuerpo(texto: string): any {
	if (!texto) return undefined;
	try {
		return JSON.parse(texto);
	} catch {
		return undefined;
	}
}
