// Autor: Athan Espinoza

// F-47 (push automático): "cada vez que creás/editás/borrás una contraseña
// con la bóveda conectada, se replica al servidor al toque" (decisión
// confirmada con el usuario) — este módulo es el único punto que
// `$lib/crypto/recursos.ts` toca para eso, una línea por operación, sin
// que esos call sites necesiten saber nada de vinculación/sesión remota.
//
// Lee `sesion`/`clavesDesbloqueadas` directo de sus stores en vez de que
// cada caller los pase. Nunca bloquea ni rompe la operación LOCAL: un
// fallo de red/servidor remoto acá se loguea en `estadoSync`, nunca se
// propaga como excepción al código que ya terminó de escribir localmente
// — coherente con "el server es opcional" incluso en modo conectado (spec
// 13 §7bis no dice qué hacer si el push puntual falla; "avisar sin
// bloquear" es la lectura más simple, ver `estadoSync` para el aviso).
//
// **Alcance de esta primera versión, documentado, no un descuido**: sólo
// `resources`. `folders`/`tags` locales creados/editados/borrados con la
// bóveda conectada NO se empujan todavía al servidor remoto — sólo se
// PULLean (`motor.ts::sincronizarAhora` sí trae los del servidor). Un
// folder/tag nuevo hecho offline-conectado queda sólo local hasta que se
// prioridad esta extensión.

import { get, writable } from 'svelte/store';
import { sesion, clavesDesbloqueadas } from '$lib/state/session';
import { obtenerVinculacion, sesionRemotaVigente } from './vinculacion';
import { clienteRemoto, RemoteApiError, type ClienteRemoto } from './remoteClient';

export interface EstadoSync {
	ultimoError: string | null;
	ultimoOkEn: number | null;
}

export const estadoSync = writable<EstadoSync>({ ultimoError: null, ultimoOkEn: null });

function marcarError(mensaje: string): void {
	estadoSync.update((e) => ({ ultimoError: mensaje, ultimoOkEn: e.ultimoOkEn }));
}

function marcarOk(): void {
	estadoSync.update((e) => ({ ultimoError: null, ultimoOkEn: Date.now() }));
}

async function conCliente(): Promise<ClienteRemoto | null> {
	const email = get(sesion).email;
	const claves = get(clavesDesbloqueadas);
	if (!email || !claves) return null;

	const vinculacion = obtenerVinculacion(email);
	if (!vinculacion) return null;

	try {
		const sessionId = await sesionRemotaVigente(vinculacion, claves);
		return clienteRemoto(vinculacion.serverUrl, sessionId);
	} catch (err) {
		marcarError(err instanceof Error ? err.message : 'no se pudo autenticar contra el servidor remoto');
		return null;
	}
}

async function ejecutar(accion: (cliente: ClienteRemoto) => Promise<void>): Promise<void> {
	const cliente = await conCliente();
	if (!cliente) return; // sin vínculo, o sin poder autenticar (ya quedó el error en `estadoSync`)
	try {
		await accion(cliente);
		marcarOk();
	} catch (err) {
		marcarError(err instanceof Error ? err.message : 'no se pudo sincronizar con el servidor remoto');
	}
}

export function notificarRecursoCreado(body: Record<string, unknown>): void {
	void ejecutar((cliente) => cliente.post('/resources', body));
}

/**
 * `cuerpoParaCrear`: mismo shape que `crearRecurso` ya manda — se usa como
 * fallback si el servidor remoto todavía no tiene este recurso (ej. el
 * push de la creación falló offline y esta edición es la primera vez que
 * se logra hablar con el servidor).
 */
export function notificarRecursoEditado(resourceId: string, cuerpoParaEditar: Record<string, unknown>, cuerpoParaCrear: Record<string, unknown>): void {
	void ejecutar(async (cliente) => {
		try {
			const remoto = await cliente.get<{ updated_at: string }>(`/resources/${resourceId}`);
			await cliente.put(`/resources/${resourceId}`, cuerpoParaEditar, { 'If-Match': remoto.updated_at });
		} catch (err) {
			if (err instanceof RemoteApiError && err.status === 404) {
				await cliente.post('/resources', cuerpoParaCrear);
				return;
			}
			throw err;
		}
	});
}

export function notificarRecursoEliminado(resourceId: string): void {
	void ejecutar(async (cliente) => {
		try {
			await cliente.delete(`/resources/${resourceId}`);
		} catch (err) {
			// Ya no está del otro lado tampoco — no es un fallo real, es el
			// estado al que justamente se quería llegar.
			if (err instanceof RemoteApiError && err.status === 404) return;
			throw err;
		}
	});
}
