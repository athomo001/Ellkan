// Autor: Athan Espinoza

// Web (modo servidor): avisos en vivo del propio servidor (`GET /sync/eventos`,
// el mismo SSE que usa la app de escritorio vinculada). Cuando otro
// dispositivo del mismo usuario cambia algo — la app de escritorio, la
// extensión, otra pestaña — el Vault se recarga solo, sin F5 (pedido del
// usuario 2026-10-18: «no debería estar haciendo F5 para que una pass se
// actualice»). Antes la web sólo se refrescaba al volver a la pestaña.
//
// `fetch` en streaming y no `EventSource`, que no puede mandar el header
// `Authorization` (mismo criterio que `avisosServidor.ts`). Reconecta con
// espera creciente; un 401 corta (la sesión ya no vale: el resto de la app
// ya manda al login).

import { get } from 'svelte/store';
import { sesion } from '$lib/state/session';
import { baseUrl } from '$lib/api/client';
import { cambiosDelServidor } from './automatico';

const ESPERA_MINIMA_MS = 2_000;
const ESPERA_MAXIMA_MS = 60_000;

/** Empieza a escuchar; devuelve la función que corta la conexión. */
export function escucharAvisosEnWeb(): () => void {
	const control = new AbortController();
	let espera = ESPERA_MINIMA_MS;

	async function bucle(): Promise<void> {
		while (!control.signal.aborted) {
			const resultado = await conectarUnaVez(control.signal).catch(() => 'fallo' as const);
			if (control.signal.aborted || resultado === 'sin_sesion') return;
			espera = resultado === 'conecto' ? ESPERA_MINIMA_MS : Math.min(espera * 2, ESPERA_MAXIMA_MS);
			await new Promise((r) => setTimeout(r, espera));
		}
	}

	void bucle();
	return () => control.abort();
}

async function conectarUnaVez(signal: AbortSignal): Promise<'conecto' | 'fallo' | 'sin_sesion'> {
	const sessionId = get(sesion).sessionId;
	if (!sessionId) return 'sin_sesion';
	const resp = await fetch(`${await baseUrl()}/sync/eventos`, {
		headers: { Authorization: `Bearer ${sessionId}`, Accept: 'text/event-stream' },
		cache: 'no-store',
		signal
	});
	if (resp.status === 401) return 'sin_sesion';
	if (!resp.ok || !resp.body) return 'fallo';

	// Recién conectados: puede haber cambios de mientras no había conexión.
	cambiosDelServidor.update((n) => n + 1);

	const lector = resp.body.pipeThrough(new TextDecoderStream()).getReader();
	let pendiente = '';
	for (;;) {
		const { value, done } = await lector.read();
		if (done) return 'conecto';
		pendiente += value;
		let corte: number;
		while ((corte = pendiente.indexOf('\n\n')) >= 0) {
			const mensaje = pendiente.slice(0, corte);
			pendiente = pendiente.slice(corte + 2);
			const evento = mensaje
				.split('\n')
				.find((l) => l.startsWith('event:'))
				?.slice(6)
				.trim();
			// `cuenta_revocada` es para la app de escritorio (borra la bóveda
			// local); en la web la sesión revocada ya da 401 y manda al login.
			if (evento === 'cambio') cambiosDelServidor.update((n) => n + 1);
		}
	}
}
