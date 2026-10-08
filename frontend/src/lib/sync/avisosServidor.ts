// Autor: Athan Espinoza

// F-47: escucha los avisos en vivo del servidor (`GET /sync/eventos`,
// Server-Sent Events) para traer los cambios apenas ocurren, sin preguntar
// cada pocos segundos. Se usa `fetch` con el cuerpo en streaming y no
// `EventSource`, porque `EventSource` no puede mandar el header
// `Authorization` con la sesión.
//
// Si la conexión se corta (sin red, servidor reiniciado, o el cierre
// periódico que hace el propio servidor), reconecta con espera creciente y,
// al reconectar, pide un sync por si algo cambió mientras tanto.

import { get } from 'svelte/store';
import { sesion, clavesDesbloqueadas } from '$lib/state/session';
import { obtenerVinculacion, sesionRemotaVigente, olvidarSesionRemota } from './vinculacion';

const ESPERA_MINIMA_MS = 2_000;
const ESPERA_MAXIMA_MS = 60_000;

/** Empieza a escuchar; devuelve la función que corta la conexión. */
export function escucharAvisosDelServidor(alCambiar: () => void): () => void {
	const control = new AbortController();
	let espera = ESPERA_MINIMA_MS;

	async function bucle(): Promise<void> {
		while (!control.signal.aborted) {
			const conecto = await conectarUnaVez(alCambiar, control.signal).catch(() => false);
			if (control.signal.aborted) return;
			// Una conexión que llegó a abrirse reinicia la espera; si ni siquiera
			// abrió, se espera cada vez más para no golpear un servidor caído.
			espera = conecto ? ESPERA_MINIMA_MS : Math.min(espera * 2, ESPERA_MAXIMA_MS);
			await new Promise((r) => setTimeout(r, espera));
		}
	}

	void bucle();
	return () => control.abort();
}

/** Una conexión hasta que se corta. `true` si llegó a abrirse. */
async function conectarUnaVez(alCambiar: () => void, signal: AbortSignal): Promise<boolean> {
	const email = get(sesion).email;
	const claves = get(clavesDesbloqueadas);
	const vinculacion = email ? obtenerVinculacion(email) : null;
	if (!vinculacion || !claves) return false;

	const sessionId = await sesionRemotaVigente(vinculacion, claves);
	const resp = await fetch(`${vinculacion.serverUrl}/sync/eventos`, {
		headers: { Authorization: `Bearer ${sessionId}`, Accept: 'text/event-stream' },
		cache: 'no-store',
		signal
	});
	if (resp.status === 401) {
		olvidarSesionRemota(vinculacion);
		return false;
	}
	if (!resp.ok || !resp.body) return false;

	// Recién conectados: lo que haya cambiado mientras no había conexión.
	alCambiar();

	const lector = resp.body.pipeThrough(new TextDecoderStream()).getReader();
	let pendiente = '';
	for (;;) {
		const { value, done } = await lector.read();
		if (done) return true;
		pendiente += value;
		// Los mensajes SSE terminan en una línea vacía.
		let corte: number;
		while ((corte = pendiente.indexOf('\n\n')) >= 0) {
			const mensaje = pendiente.slice(0, corte);
			pendiente = pendiente.slice(corte + 2);
			if (mensaje.split('\n').some((linea) => linea.trim() === 'event: cambio')) alCambiar();
		}
	}
}
