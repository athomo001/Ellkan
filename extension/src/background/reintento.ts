// Autor: Athan Espinoza

// Reintento de 429 (límite de solicitudes) para los pedidos de la extensión,
// mismo criterio que `frontend/src/lib/api/reintento.ts`. Antes la extensión
// mostraba el error directo (2026-10-18). Es seguro para cualquier método: el
// servidor corta un 429 antes de procesar el pedido.

const MAX_REINTENTOS_429 = 6;

export async function conReintento429(enviar: () => Promise<Response>): Promise<Response> {
	for (let intento = 0; ; intento++) {
		const resp = await enviar();
		if (resp.status !== 429 || intento >= MAX_REINTENTOS_429) return resp;
		// `retry-after` viene en segundos enteros y suele ser 0: piso creciente
		// con jitter. `Math.random` es sólo jitter de espera, no material
		// criptográfico (spec/09 §CSPRNG).
		const segundos = Number(resp.headers.get('retry-after')) || 0;
		const espera = Math.max(segundos * 1000, 500 * 2 ** intento) + Math.random() * 250;
		await new Promise((r) => setTimeout(r, espera));
	}
}
