// Autor: Athan Espinoza

// F-47: con la bóveda vinculada a un servidor, lo que cambia allá tiene que
// llegar sin tocar "Sincronizar ahora". Lo que se guarda acá ya se sube solo
// (`notificador.ts`); esto hace el camino inverso. El disparador principal es
// el AVISO del servidor (`avisosServidor.ts`): cuando algo cambia allá, el
// servidor lo dice por una conexión abierta y recién ahí se pide el delta —
// sin cambios no hay tráfico. Además, por si se pierde un aviso: un pull al
// entrar, al volver a la ventana y cada `INTERVALO_RESPALDO_MS`. Nunca corre
// más de uno a la vez: un pedido que llega durante otro queda encolado (uno
// solo). Si llegó algo, avisa por `cambiosDelServidor` para que la pantalla se
// recargue sola. Un fallo (sin red, servidor caído) se reintenta en la próxima.

import { get, writable } from 'svelte/store';
import { sincronizarAhora, type ResultadoSync } from './motor';
import { escucharAvisosDelServidor } from './avisosServidor';
import { obtenerVinculacion } from './vinculacion';
import { sesion } from '$lib/state/session';

const INTERVALO_RESPALDO_MS = 5 * 60_000;

/** Se incrementa cada vez que un sync automático trajo cambios del servidor. */
export const cambiosDelServidor = writable(0);

function trajoCambios(r: ResultadoSync): boolean {
	return r.recursosNuevosOActualizados + r.recursosBorrados + r.carpetasNuevas + r.carpetasBorradas + r.tagsNuevos + r.tagsBorrados > 0;
}

/** Último resultado del sync automático (o `null` si todavía no corrió). */
export const ultimoSyncAutomatico = writable<{ fecha: Date; resultado?: ResultadoSync; error?: string } | null>(null);

let enCurso = false;
let pendiente = false;

async function sincronizarSiCorresponde(): Promise<void> {
	if (enCurso) {
		pendiente = true;
		return;
	}
	enCurso = true;
	try {
		const resultado = await sincronizarAhora();
		ultimoSyncAutomatico.set({ fecha: new Date(), resultado });
		if (trajoCambios(resultado)) cambiosDelServidor.update((n) => n + 1);
	} catch (err) {
		ultimoSyncAutomatico.set({ fecha: new Date(), error: err instanceof Error ? err.message : String(err) });
	} finally {
		enCurso = false;
		if (pendiente) {
			pendiente = false;
			void sincronizarSiCorresponde();
		}
	}
}

/** Arranca el sync automático; devuelve la función que lo detiene. */
export function iniciarSyncAutomatico(): () => void {
	void sincronizarSiCorresponde();
	const dejarDeEscuchar = escucharAvisosDelServidor(() => void sincronizarSiCorresponde());
	const intervalo = setInterval(() => void sincronizarSiCorresponde(), INTERVALO_RESPALDO_MS);
	const alEnfocar = () => {
		if (document.visibilityState !== 'hidden') void sincronizarSiCorresponde();
	};
	window.addEventListener('focus', alEnfocar);
	document.addEventListener('visibilitychange', alEnfocar);

	// La extensión del navegador cambió un recurso hablando directo con el
	// backend local (native messaging): esta interfaz no se enteró, así que
	// nadie lo subía al servidor (bug 2026-10-18). Se anota en la cola de
	// pendientes (el sync lo sube reconstruyendo el cuerpo desde la copia
	// local) y se refresca la pantalla.
	let dejarDeEscucharExtension: (() => void) | undefined;
	let cancelado = false;
	if ('__TAURI_INTERNALS__' in window) {
		void import('@tauri-apps/api/event').then(({ listen }) =>
			// El cambio ya quedó anotado por la app (`cambios-extension.json`);
			// el sync lo recoge y lo sube (`motor.ts::recogerCambiosDeExtension`).
			listen('recurso-cambiado-por-extension', () => {
				const email = get(sesion).email;
				if (!email || !obtenerVinculacion(email)) return;
				cambiosDelServidor.update((n) => n + 1);
				void sincronizarSiCorresponde();
			}).then((unlisten) => {
				if (cancelado) unlisten();
				else dejarDeEscucharExtension = unlisten;
			})
		);
	}

	return () => {
		cancelado = true;
		dejarDeEscucharExtension?.();
		dejarDeEscuchar();
		clearInterval(intervalo);
		window.removeEventListener('focus', alEnfocar);
		document.removeEventListener('visibilitychange', alEnfocar);
	};
}
