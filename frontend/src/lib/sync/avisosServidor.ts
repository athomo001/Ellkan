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
import { registrar } from '$lib/tauri/registro';

const ESPERA_MINIMA_MS = 2_000;
const ESPERA_MAXIMA_MS = 60_000;

/** Empieza a escuchar; devuelve la función que corta la conexión. */
export function escucharAvisosDelServidor(alCambiar: () => void): () => void {
	const control = new AbortController();
	let espera = ESPERA_MINIMA_MS;

	async function bucle(): Promise<void> {
		// Al `Ellkan.log` sólo los cambios de estado (conectado ↔ sin
		// conexión), no cada reintento: el servidor corta la conexión
		// periódicamente a propósito y eso no es una novedad.
		let estadoAnterior: 'conectado' | 'sin_conexion' | null = null;
		while (!control.signal.aborted) {
			let fallo: unknown = null;
			const conecto = await conectarUnaVez(alCambiar, control.signal, () => {
				if (estadoAnterior !== 'conectado') registrar('info', '[servidor] avisos en vivo conectados');
				estadoAnterior = 'conectado';
			}).catch((err) => {
				fallo = err;
				return false;
			});
			if (control.signal.aborted) return;
			// Una conexión que llegó a abrirse reinicia la espera; si ni siquiera
			// abrió, se espera cada vez más para no golpear un servidor caído.
			espera = conecto ? ESPERA_MINIMA_MS : Math.min(espera * 2, ESPERA_MAXIMA_MS);
			if (!conecto && estadoAnterior !== 'sin_conexion') {
				registrar('warn', `[servidor] sin conexión para avisos en vivo; reintento cada vez más espaciado (ahora ${espera / 1000} s)`, fallo ?? '');
				estadoAnterior = 'sin_conexion';
			}
			await new Promise((r) => setTimeout(r, espera));
		}
	}

	void bucle();
	return () => control.abort();
}

/** Una conexión hasta que se corta. `true` si llegó a abrirse. */
async function conectarUnaVez(alCambiar: () => void, signal: AbortSignal, alAbrir: () => void): Promise<boolean> {
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

	alAbrir();
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
			const lineas = mensaje.split('\n');
			const evento = lineas.find((l) => l.startsWith('event:'))?.slice(6).trim();
			if (evento === 'cambio') alCambiar();
			else if (evento === 'cuenta_revocada') {
				// Revocación remota: el aviso firmado viene en `data`. `revocacion.ts`
				// lo verifica contra la clave fijada antes de tocar nada.
				const datos = lineas
					.filter((l) => l.startsWith('data:'))
					.map((l) => l.slice(5).trimStart())
					.join('\n');
				try {
					const { procesarAvisoRevocacion } = await import('./revocacion');
					await procesarAvisoRevocacion(JSON.parse(datos));
				} catch {
					/* aviso ilegible: no se borra nada */
				}
				return true;
			}
		}
	}
}
