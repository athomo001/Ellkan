// Autor: Athan Espinoza

// Estrategia de sincronización (07-frontend-web.md §2): refresco por foco
// de pestaña + tras cualquier mutación propia, chequeo de frescura por
// `updated_at` (no re-fetch ciego), y deduplicación de requests
// concurrentes idénticos — sin el endpoint agregado `GET /sync` de
// Bitwarden ni WebSocket, decisión explícita (fuera de alcance de v1).

const enVuelo = new Map<string, Promise<unknown>>();

/**
 * Deduplica requests concurrentes idénticos por `clave` — si ya hay una
 * promesa en curso para esa clave, la segunda llamada espera la primera en
 * vez de disparar una request nueva (mismo principio que `inFlightApiCalls`
 * de Bitwarden).
 */
export async function conDeduplicacion<T>(clave: string, fetcher: () => Promise<T>): Promise<T> {
	const existente = enVuelo.get(clave);
	if (existente) return existente as Promise<T>;

	const promesa = fetcher().finally(() => enVuelo.delete(clave));
	enVuelo.set(clave, promesa);
	return promesa;
}

/**
 * Compara el `updated_at` más reciente ya conocido contra el de una lista
 * nueva — si no cambió nada, el caller no debería reemplazar el store
 * (evita perder estado de UI local, ej. una fila expandida, por un
 * refresco sin cambios reales).
 */
export function huboCambios(itemsActuales: { updated_at?: string }[], itemsNuevos: { updated_at?: string }[]): boolean {
	if (itemsActuales.length !== itemsNuevos.length) return true;
	const masReciente = (items: { updated_at?: string }[]) =>
		items.reduce<string>((max, i) => (i.updated_at && i.updated_at > max ? i.updated_at : max), '');
	return masReciente(itemsActuales) !== masReciente(itemsNuevos);
}

/**
 * Refresca `callback` cuando la pestaña recupera el foco
 * (`visibilitychange`) — llamar una vez desde el layout raíz autenticado.
 */
export function refrescarAlEnfocar(callback: () => void): () => void {
	const handler = () => {
		if (document.visibilityState === 'visible') callback();
	};
	document.addEventListener('visibilitychange', handler);
	return () => document.removeEventListener('visibilitychange', handler);
}
