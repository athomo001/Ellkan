// Autor: Athan Espinoza

// ¿Se puede llegar al servidor Ellkan remoto ahora mismo? Sirve para que la UI
// muestre el estado real en vez de un aviso fijo ("este modo necesita
// internet") aunque haya conexión. Sólo mide alcance de red, nunca autentica.

export type EstadoConexion = 'comprobando' | 'en_linea' | 'sin_conexion';

/**
 * `true` si el servidor responde algo (cualquier cosa) antes de `ms`.
 *
 * Pedido CORS normal, no `no-cors`: el servidor manda
 * `Cross-Origin-Resource-Policy: same-origin`, que hace fallar cualquier
 * pedido `no-cors` desde otro origen aunque el servidor esté arriba (así se
 * veía "sin conexión" siempre). El servidor habilita CORS para los orígenes
 * de la app de escritorio, así que el pedido normal funciona.
 */
export async function servidorAlcanzable(serverUrl: string, ms = 5000): Promise<boolean> {
	if (typeof navigator !== 'undefined' && navigator.onLine === false) return false;
	const control = new AbortController();
	const temporizador = setTimeout(() => control.abort(), ms);
	try {
		await fetch(`${serverUrl.replace(/\/+$/, '')}/healthz`, {
			method: 'GET',
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
