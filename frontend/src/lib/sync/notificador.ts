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
// — coherente con "el server es opcional" incluso en modo conectado.
//
// Un push que falla por algo pasajero (sin red, servidor caído, sesión que
// no se pudo renovar) deja el recurso en la cola de `pendientes.ts`, y
// `subirPendientes` lo vuelve a subir en el próximo sync que logre hablar con
// el servidor — al reconectar, el aviso en vivo dispara uno enseguida.
//
// **Alcance de esta primera versión, documentado, no un descuido**: sólo
// `resources`. `folders`/`tags` locales creados/editados/borrados con la
// bóveda conectada NO se empujan todavía al servidor remoto — sólo se
// PULLean (`motor.ts::sincronizarAhora` sí trae los del servidor). Un
// folder/tag nuevo hecho offline-conectado queda sólo local hasta que se
// prioridad esta extensión.

import { get, writable } from 'svelte/store';
import { api, ApiError } from '$lib/api/client';
import { sesion, clavesDesbloqueadas, type ClavesDesbloqueadas } from '$lib/state/session';
import { obtenerVinculacion, sesionRemotaVigente, olvidarSesionRemota, type VinculacionServidor } from './vinculacion';
import { clienteRemoto, RemoteApiError, type ClienteRemoto } from './remoteClient';
import { esAdaptado } from './adaptacion';
import { marcarPendiente, quitarPendiente, obtenerPendientes, type OperacionPendiente } from './pendientes';

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

function mensajeDe(err: unknown): string {
	return err instanceof Error ? err.message : 'no se pudo sincronizar con el servidor remoto';
}

/**
 * Si vale la pena reintentar más tarde. Sí: sin red (`fetch` tira un
 * `TypeError`), servidor caído o reiniciando (5xx), sesión que no se pudo
 * renovar (401), límite de pedidos (408/429). No: cualquier otro 4xx (409,
 * 422...) es el servidor rechazando ESTE pedido, y se repetiría igual en cada
 * intento — se descarta y queda el aviso en `estadoSync`.
 */
function esReintentable(err: unknown): boolean {
	if (!(err instanceof RemoteApiError)) return true;
	return err.status >= 500 || err.status === 401 || err.status === 408 || err.status === 429;
}

/** Corre la acción con la sesión remota vigente; si venció del otro lado, saca
 * una nueva y la repite una vez. */
async function conSesionRemota(
	vinculacion: VinculacionServidor,
	claves: ClavesDesbloqueadas,
	accion: (cliente: ClienteRemoto) => Promise<void>
): Promise<void> {
	try {
		await accion(clienteRemoto(vinculacion.serverUrl, await sesionRemotaVigente(vinculacion, claves)));
	} catch (err) {
		if (!(err instanceof RemoteApiError && err.status === 401)) throw err;
		olvidarSesionRemota(vinculacion);
		await accion(clienteRemoto(vinculacion.serverUrl, await sesionRemotaVigente(vinculacion, claves)));
	}
}

/** Push en vivo de un recurso. Se anota en la cola antes de intentar y se
 * quita al confirmarse, o si el servidor lo rechazó de forma definitiva. */
async function ejecutar(resourceId: string, operacion: OperacionPendiente, accion: (cliente: ClienteRemoto) => Promise<void>): Promise<void> {
	const email = get(sesion).email;
	const claves = get(clavesDesbloqueadas);
	if (!email || !claves) return;
	const vinculacion = obtenerVinculacion(email);
	if (!vinculacion) return; // bóveda sólo local: no hay a quién avisarle

	marcarPendiente(email, resourceId, operacion);
	try {
		await conSesionRemota(vinculacion, claves, accion);
		quitarPendiente(email, resourceId);
		marcarOk();
	} catch (err) {
		if (!esReintentable(err)) quitarPendiente(email, resourceId);
		marcarError(mensajeDe(err));
	}
}

/** Edita el recurso en el servidor; si allá todavía no existe, lo crea. */
async function subirEnServidor(
	cliente: ClienteRemoto,
	resourceId: string,
	cuerpoParaEditar: Record<string, unknown>,
	cuerpoParaCrear: Record<string, unknown>
): Promise<void> {
	try {
		const remoto = await cliente.get<{ updated_at: string }>(`/resources/${resourceId}`);
		await cliente.put(`/resources/${resourceId}`, cuerpoParaEditar, { 'If-Match': remoto.updated_at });
	} catch (err) {
		// El servidor responde 403 (no 404) a un id que no existe, para no
		// revelar qué ids hay: los dos significan "todavía no está allá".
		if (err instanceof RemoteApiError && (err.status === 404 || err.status === 403)) {
			await cliente.post('/resources', cuerpoParaCrear);
			return;
		}
		throw err;
	}
}

async function borrarEnServidor(cliente: ClienteRemoto, resourceId: string): Promise<void> {
	try {
		await cliente.delete(`/resources/${resourceId}`);
	} catch (err) {
		// Ya no está del otro lado tampoco — no es un fallo real, es el
		// estado al que justamente se quería llegar.
		// 403: no existe allá (o no es de esta cuenta): no hay nada que borrar.
		if (err instanceof RemoteApiError && (err.status === 404 || err.status === 403)) return;
		throw err;
	}
}

/** `null` si la bóveda local no tiene el recurso (el backend local responde
 * 403 a un id que no existe, igual que el servidor). */
async function ausenteComoNull<T>(promesa: Promise<T>): Promise<T | null> {
	try {
		return await promesa;
	} catch (err) {
		if (err instanceof ApiError && (err.status === 404 || err.status === 403)) return null;
		throw err;
	}
}

/**
 * Arma los cuerpos del push a partir de lo que hay HOY en la bóveda local —
 * el mismo ciphertext que se guardó, sin descifrar nada. `null` si no hay
 * nada que subir: el recurso ya no existe localmente, es de metadata de
 * equipo o adaptado al bajarlo (se editan en la web, mismo criterio que el
 * push en vivo), o el secreto no está en disco (modos «sólo memoria» y
 * «sólo nombres»: el servidor es el dueño del secreto y no hay una versión
 * local completa que subir).
 */
async function cuerposDesdeLocal(
	email: string,
	resourceId: string,
	userId: string
): Promise<{ editar: Record<string, unknown>; crear: Record<string, unknown> } | null> {
	if (esAdaptado(email, resourceId)) return null;
	const recurso = await ausenteComoNull(
		api.get<{ resource_type_slug: string; metadata_ciphertext_b64: string; metadata_nonce_b64: string; metadata_key_type: string }>(
			`/resources/${resourceId}`
		)
	);
	if (recurso?.metadata_key_type !== 'user_key') return null;
	const secreto = await ausenteComoNull(
		api.get<{ sealed_dek_b64: string; secret_ciphertext_b64: string; secret_nonce_b64: string }>(`/resources/${resourceId}/secret`)
	);
	if (!secreto) return null;

	const metadata = { metadata_ciphertext_b64: recurso.metadata_ciphertext_b64, metadata_nonce_b64: recurso.metadata_nonce_b64 };
	return {
		// En modo escritorio el único destinatario es el propio usuario, con el
		// mismo id en la app y en el servidor.
		editar: { ...metadata, envelopes: [{ recipient_user_id: userId, ...secreto }] },
		crear: { id: resourceId, resource_type_slug: recurso.resource_type_slug, ...metadata, ...secreto }
	};
}

/**
 * Sube lo que quedó en la cola. Lo llama `motor.ts::sincronizarAhora` DESPUÉS
 * de bajar los cambios del servidor: así una edición hecha allá mientras
 * tanto ya pasó por la detección de conflictos (la versión local quedó
 * guardada aparte) y no se pisa. Si el servidor vuelve a fallar se corta acá:
 * el resto sigue en la cola para el próximo sync. Devuelve cuántos subió.
 */
export async function subirPendientes(cliente: ClienteRemoto, email: string, userId: string): Promise<number> {
	let subidos = 0;
	for (const [resourceId, operacion] of Object.entries(obtenerPendientes(email))) {
		try {
			if (operacion === 'borrar') {
				await borrarEnServidor(cliente, resourceId);
				subidos++;
			} else {
				const cuerpos = await cuerposDesdeLocal(email, resourceId, userId);
				if (cuerpos) {
					await subirEnServidor(cliente, resourceId, cuerpos.editar, cuerpos.crear);
					subidos++;
				}
			}
			quitarPendiente(email, resourceId);
		} catch (err) {
			if (esReintentable(err)) {
				marcarError(mensajeDe(err));
				break;
			}
			quitarPendiente(email, resourceId);
			marcarError(mensajeDe(err));
		}
	}
	return subidos;
}

export function notificarRecursoCreado(body: Record<string, unknown>): void {
	void ejecutar(String(body.id), 'subir', (cliente) => cliente.post('/resources', body));
}

/**
 * `cuerpoParaCrear`: mismo shape que `crearRecurso` ya manda — se usa como
 * fallback si el servidor remoto todavía no tiene este recurso (ej. el
 * push de la creación falló offline y esta edición es la primera vez que
 * se logra hablar con el servidor).
 */
export function notificarRecursoEditado(resourceId: string, cuerpoParaEditar: Record<string, unknown>, cuerpoParaCrear: Record<string, unknown>): void {
	// Recurso adaptado al bajarlo (metadata de equipo o de otra persona, ver
	// `adaptacion.ts`): el servidor lo guarda con otro esquema, subir esta
	// versión lo dejaría ilegible allá. Se edita en la web.
	if (esAdaptado(get(sesion).email, resourceId)) return;
	void ejecutar(resourceId, 'subir', (cliente) => subirEnServidor(cliente, resourceId, cuerpoParaEditar, cuerpoParaCrear));
}

export function notificarRecursoEliminado(resourceId: string): void {
	void ejecutar(resourceId, 'borrar', (cliente) => borrarEnServidor(cliente, resourceId));
}
