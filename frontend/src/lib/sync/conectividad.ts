// Autor: Athan Espinoza

// ¿Se puede llegar al servidor Ellkan remoto ahora mismo? Sirve para que la UI
// muestre el estado real en vez de un aviso fijo ("este modo necesita
// internet") aunque haya conexión. Sólo mide alcance de red, nunca autentica.

export type EstadoConexion = 'comprobando' | 'en_linea' | 'sin_conexion';

/**
 * `true` si el servidor responde algo (cualquier cosa) antes de `ms`.
 *
 * `mode: 'no-cors'` a propósito: lo único que interesa es si hay camino hasta
 * el servidor, no leer su respuesta. Sin él, un servidor alcanzable que no
 * habilita CORS para este origen se vería igual que uno caído (`fetch` rechaza
 * en los dos casos). La respuesta opaca resuelve; sólo un fallo de red rechaza.
 */
export async function servidorAlcanzable(serverUrl: string, ms = 5000): Promise<boolean> {
	if (typeof navigator !== 'undefined' && navigator.onLine === false) return false;
	const control = new AbortController();
	const temporizador = setTimeout(() => control.abort(), ms);
	try {
		await fetch(`${serverUrl.replace(/\/+$/, '')}/healthz`, {
			method: 'GET',
			mode: 'no-cors',
			cache: 'no-store',
			signal: control.signal
		});
		return true;
	} catch {
		return false;
	} finally {
		clearTimeout(temporizador);
	}
}
