// Autor: Athan Espinoza

// F-47: "Sincronizar ahora" — pull real contra el servidor remoto vinculado
// y aplicación a la bóveda LOCAL vía los endpoints de siempre (nunca un
// camino de escritura nuevo — el backend local no distingue "esto lo
// escribió el usuario" de "esto lo escribió el motor de sync").
//
// **Gap real encontrado escribiendo esto, documentado en vez de ignorado**:
// no existe en TODO el producto (ni server ni desktop) un endpoint para
// RENOMBRAR una carpeta ya creada (`PUT /folders/{id}/move` sólo cambia el
// padre, nunca el nombre) ni para editar un tag. Por eso el pull de
// `folders`/`tags` de esta primera versión sólo cubre CREAR (si no existe
// localmente) y BORRAR (tombstone) — un rename remoto de una carpeta/tag
// que ya existía localmente no se refleja hasta que se agregue ese
// endpoint. `resources` sí tiene el ciclo completo (crear/editar/mover/
// borrar todos existen), por eso ahí sí hay conflicto real resuelto.

import { get, writable } from 'svelte/store';
import { api, ApiError } from '$lib/api/client';
import { sesion, clavesDesbloqueadas, type ClavesDesbloqueadas } from '$lib/state/session';
import { cargarCrypto } from '../crypto/wasm';
import { bytesABase64, base64ABytes } from '../crypto/b64';
import { uuidABytes } from '../crypto/uuid';
import {
	obtenerVinculacion,
	obtenerCursor,
	guardarCursor,
	sesionRemotaVigente,
	olvidarSesionRemota,
	fijarIdentidadDelServidor
} from './vinculacion';
import { clienteRemoto, RemoteApiError } from './remoteClient';
import { obtenerPersistencia } from './persistencia';
import { necesitaAdaptacion, adaptarRecurso, marcarAdaptado, esAdaptado, type CuerpoLocal } from './adaptacion';
import { sincronizarAvatar } from './avatar';
import { sincronizarKit } from './kit';
import { obtenerPendientes, marcarPendiente, quitarPendiente } from './pendientes';
import { subirPendientes } from './notificador';
import { registrar } from '$lib/tauri/registro';

interface RecursoListado {
	id: string;
	metadata_ciphertext_b64: string;
	metadata_key_type: string;
	updated_at: string;
}

/** Correos ya reconciliados en esta sesión de la app (memoria). */
const reconciliados = new Set<string>();

/**
 * Red de seguridad, una vez por sesión de la app (después del primer pull):
 * compara la bóveda local con el servidor y pone en la cola lo que la app
 * tiene más nuevo o que falta allá. Atrapa cambios cuyo aviso se perdió —
 * p. ej. la extensión editando con la bóveda bloqueada antes del arreglo de
 * `cambios-extension.json` (bug real 2026-10-18), o una app que se cerró a
 * mitad de un push. Un pedido por lado (las listas ya vienen completas).
 * Sólo `user_key` y no adaptados: lo demás se edita en la web.
 */
async function reconciliarUnaVez(remoto: ReturnType<typeof clienteRemoto>, email: string): Promise<void> {
	if (reconciliados.has(email)) return;
	try {
		const [locales, delServidor] = await Promise.all([
			api.get<RecursoListado[]>('/resources'),
			remoto.get<RecursoListado[]>('/resources')
		]);
		const servidor = new Map(delServidor.map((r) => [r.id, r]));
		let encolados = 0;
		for (const local of locales) {
			if (local.metadata_key_type !== 'user_key' || esAdaptado(email, local.id)) continue;
			const allá = servidor.get(local.id);
			// Igual en los dos lados (el caso normal, incluido lo recién bajado).
			if (allá?.metadata_ciphertext_b64 === local.metadata_ciphertext_b64) continue;
			// Distinto y el servidor es más nuevo: lo resuelve el pull, no acá.
			if (allá && Date.parse(allá.updated_at) >= Date.parse(local.updated_at)) continue;
			marcarPendiente(email, local.id, 'subir');
			encolados++;
		}
		reconciliados.add(email);
		registrar(
			encolados > 0 ? 'warn' : 'info',
			`[reconciliación] ${locales.length} locales contra ${delServidor.length} del servidor: ${encolados} más nuevos acá, a la cola`
		);
	} catch (err) {
		// Se reintenta en el próximo sync.
		registrar('warn', '[reconciliación] no se pudo comparar con el servidor:', err);
	}
}

/**
 * Escritorio: cambios que la extensión hizo en la bóveda local (anotados por
 * la app en `cambios-extension.json`, aunque la bóveda estuviera bloqueada)
 * pasan a la cola de pendientes para subirlos en este sync. Antes sólo se
 * avisaban con un evento, que nadie escuchaba con la bóveda bloqueada, y el
 * cambio se perdía (bug real 2026-10-18).
 */
async function recogerCambiosDeExtension(email: string): Promise<void> {
	if (typeof window === 'undefined' || !('__TAURI_INTERNALS__' in window)) return;
	try {
		const { invoke } = await import('@tauri-apps/api/core');
		const cambios = await invoke<Record<string, string>>('tomar_cambios_extension');
		for (const [id, operacion] of Object.entries(cambios)) {
			if (operacion !== 'subir' && operacion !== 'borrar') continue;
			marcarPendiente(email, id, operacion);
			registrar('info', `[extensión] ${operacion} ${id} → a la cola para subir`);
		}
	} catch (err) {
		registrar('warn', '[extensión] no se pudieron recoger sus cambios:', err);
	}
}
import { olvidarSecretoEnMemoria } from '$lib/crypto/recursos';

interface SyncSecretCrudo {
	sealed_dek_b64: string;
	secret_ciphertext_b64: string;
	secret_nonce_b64: string;
}

interface SyncResourceCrudo {
	id: string;
	deleted: boolean;
	resource_type_slug: string | null;
	metadata_ciphertext_b64: string | null;
	metadata_nonce_b64: string | null;
	created_by: string | null;
	metadata_key_type: string | null;
	metadata_key_id: string | null;
	folder_id: string | null;
	secret: SyncSecretCrudo | null;
}

interface SyncFolderCrudo {
	folder_id: string;
	deleted: boolean;
	parent_folder_id: string | null;
	name_ciphertext_b64: string | null;
	name_nonce_b64: string | null;
}

interface SyncTagCrudo {
	id: string;
	deleted: boolean;
	name: string | null;
	is_shared: boolean | null;
}

interface SyncResponseCrudo {
	cursor: string;
	resources: SyncResourceCrudo[];
	folders: SyncFolderCrudo[];
	tags: SyncTagCrudo[];
}

export interface ResultadoSync {
	recursosNuevosOActualizados: number;
	recursosBorrados: number;
	recursosEnConflicto: number;
	/** Recursos que no se pudieron traer: metadata con una clave de equipo a
	 * la que no hay acceso, o de otra persona en un modo sin réplica. */
	recursosOmitidos: number;
	/** Cambios hechos en la app que no habían llegado al servidor (estaba
	 * caído o sin red) y se subieron en este sync. */
	recursosSubidos: number;
	carpetasNuevas: number;
	carpetasBorradas: number;
	tagsNuevos: number;
	tagsBorrados: number;
}

/** Claves de metadata del equipo a las que esta cuenta tiene acceso en el
 * servidor, ya abiertas con la clave privada (mismo criterio que
 * `recursos.ts::cargarClavesMetadataCompartidas`, pero contra el servidor). */
async function clavesMetadataRemotas(
	remoto: ReturnType<typeof clienteRemoto>,
	claves: ClavesDesbloqueadas
): Promise<Map<string, Uint8Array>> {
	const wasm = await cargarCrypto();
	const mapa = new Map<string, Uint8Array>();
	try {
		const activas = await remoto.get<{ id: string; own_sealed_private_key_b64: string | null }[]>('/metadata-keys');
		for (const c of activas) {
			if (c.own_sealed_private_key_b64) mapa.set(c.id, wasm.abrir_sellado(claves.x25519Private, base64ABytes(c.own_sealed_private_key_b64)));
		}
	} catch {
		// Sin acceso a las claves de equipo: esos recursos se cuentan como omitidos.
	}
	return mapa;
}

/**
 * `null` si el recurso/carpeta/tag no existe en la bóveda LOCAL. El backend
 * responde 403 (no 404) a un id que no existe — a propósito, para no revelar
 * qué ids hay — así que acá los dos significan "no está": en la bóveda de
 * escritorio, de un solo usuario, todo lo que existe es del usuario local.
 * Antes sólo se aceptaba 404 y el primer recurso nuevo que bajaba del
 * servidor cortaba todo el sync con "no tenés permiso".
 */
async function ignorarAusente<T>(promesa: Promise<T>): Promise<T | null> {
	try {
		return await promesa;
	} catch (err) {
		if (err instanceof ApiError && (err.status === 404 || err.status === 403)) return null;
		throw err;
	}
}

/** Mismo formato que `recursos.ts::aadDeRecurso` (no exportado desde ahí,
 * se reimplementa acá con el mismo `uuidABytes` — 2 líneas, no vale la
 * pena cambiar la superficie pública de ese módulo sólo por esto). */
function aad(resourceId: string, createdBy: string): Uint8Array {
	const bytes = new Uint8Array(32);
	bytes.set(uuidABytes(resourceId), 0);
	bytes.set(uuidABytes(createdBy), 16);
	return bytes;
}

/**
 * Guarda la versión LOCAL actual de un recurso bajo un id nuevo, con el
 * nombre marcado como conflicto — spec/13 §7: "se conserva la versión del
 * servidor, la local se guarda como un recurso nuevo, nada se pierde".
 * Mismo patrón cripto que `recursos.ts::verSecreto`/`crearRecurso`: abrir
 * la DEK sellada con la clave privada, descifrar con ESA dek (nunca
 * directo con la clave privada). Devuelve el id de la copia, o `null` si no
 * se pudo hacer.
 */
async function copiarComoConflicto(resourceId: string): Promise<string | null> {
	const wasm = await cargarCrypto();
	const claves = get(clavesDesbloqueadas);
	// Sin claves desbloqueadas no hay forma de leer la metadata local para
	// renombrarla — no se pierde el dato (sigue tal cual en `resources`),
	// sólo este intento puntual de preservarlo aparte; un sync posterior
	// con la bóveda desbloqueada lo vuelve a intentar.
	if (!claves) return null;

	const recurso = await ignorarAusente(
		api.get<{ id: string; resource_type_slug: string; metadata_ciphertext_b64: string; metadata_nonce_b64: string; created_by: string | null }>(
			`/resources/${resourceId}`
		)
	);
	if (!recurso?.created_by) return null;
	const secreto = await ignorarAusente(
		api.get<{ sealed_dek_b64: string; secret_ciphertext_b64: string; secret_nonce_b64: string }>(`/resources/${resourceId}/secret`)
	);
	if (!secreto) return null;

	const aadVieja = aad(resourceId, recurso.created_by);
	const dek = wasm.abrir_sellado(claves.x25519Private, base64ABytes(secreto.sealed_dek_b64));
	const metadataJson = JSON.parse(
		new TextDecoder().decode(
			wasm.descifrar_aead(dek, base64ABytes(recurso.metadata_nonce_b64), base64ABytes(recurso.metadata_ciphertext_b64), aadVieja)
		)
	);
	const secretoJson = JSON.parse(
		new TextDecoder().decode(wasm.descifrar_aead(dek, base64ABytes(secreto.secret_nonce_b64), base64ABytes(secreto.secret_ciphertext_b64), aadVieja))
	);

	const fecha = new Date().toLocaleDateString('es-AR');
	metadataJson.name = `${metadataJson.name ?? 'Sin nombre'} (conflicto ${fecha})`;

	const nuevoId = crypto.randomUUID();
	const nuevaAad = aad(nuevoId, recurso.created_by);
	const nuevaDek = wasm.generar_dek();
	const metadataCifrada = wasm.cifrar_aead(nuevaDek, new TextEncoder().encode(JSON.stringify(metadataJson)), nuevaAad);
	const secretoCifrado = wasm.cifrar_aead(nuevaDek, new TextEncoder().encode(JSON.stringify(secretoJson)), nuevaAad);
	const sealedDek = wasm.sellar_para(claves.x25519Public, nuevaDek);

	await api.post('/resources', {
		id: nuevoId,
		resource_type_slug: recurso.resource_type_slug,
		metadata_ciphertext_b64: bytesABase64(metadataCifrada.ciphertext),
		metadata_nonce_b64: bytesABase64(metadataCifrada.nonce),
		sealed_dek_b64: bytesABase64(sealedDek),
		secret_ciphertext_b64: bytesABase64(secretoCifrado.ciphertext),
		secret_nonce_b64: bytesABase64(secretoCifrado.nonce)
	});
	return nuevoId;
}

/** Guarda aparte la versión local y deja la copia en la cola para que también
 * llegue al servidor: antes quedaba sólo en la app. */
async function preservarVersionLocal(email: string, resourceId: string): Promise<void> {
	const copia = await copiarComoConflicto(resourceId);
	if (copia) marcarPendiente(email, copia, 'subir');
	quitarPendiente(email, resourceId);
}

/** Avance del sync en curso, para la barra de progreso (pedido 2026-10-18:
 * traer cientos de claves al escritorio no mostraba nada hasta terminar).
 * `null` = no hay sync, o es tan chico que no vale la pena mostrarlo. */
export interface ProgresoSync {
	fase: 'bajando' | 'subiendo';
	hechos: number;
	/** 0 = no se sabe cuántos (barra indeterminada). */
	total: number;
}
export const progresoSync = writable<ProgresoSync | null>(null);

/** Por debajo de esto el sync termina antes de que la barra se alcance a ver. */
const UMBRAL_PROGRESO = 10;

export async function sincronizarAhora(): Promise<ResultadoSync> {
	const inicio = Date.now();
	try {
		const r = await sincronizarAhoraInterno();
		// Resumen al `Ellkan.log` (escritorio): antes un sync que bajaba o
		// borraba cientos de claves no dejaba rastro (2026-10-18). Sólo
		// conteos, nunca nombres.
		const huboAlgo = Object.values(r).some((n) => n > 0);
		registrar(
			'info',
			`[sync] ${huboAlgo ? 'listo' : 'sin cambios'} en ${Date.now() - inicio} ms: ` +
				`${r.recursosNuevosOActualizados} bajados, ${r.recursosBorrados} borrados acá, ${r.recursosSubidos} subidos, ` +
				`${r.recursosEnConflicto} en conflicto, ${r.recursosOmitidos} omitidos; ` +
				`carpetas +${r.carpetasNuevas}/-${r.carpetasBorradas}, tags +${r.tagsNuevos}/-${r.tagsBorrados}`
		);
		return r;
	} catch (err) {
		registrar('warn', '[sync] falló:', err);
		throw err;
	} finally {
		progresoSync.set(null);
	}
}

async function sincronizarAhoraInterno(): Promise<ResultadoSync> {
	const email = get(sesion).email;
	const userIdLocal = get(sesion).userId;
	const claves = get(clavesDesbloqueadas);
	if (!email || !userIdLocal || !claves) throw new Error('No hay una sesión desbloqueada.');

	const vinculacion = obtenerVinculacion(email);
	if (!vinculacion) throw new Error('Esta bóveda no está conectada a ningún servidor.');

	let remoto = clienteRemoto(vinculacion.serverUrl, await sesionRemotaVigente(vinculacion, claves));

	const cursorAnterior = obtenerCursor(email);
	const query = cursorAnterior ? `?since=${encodeURIComponent(cursorAnterior)}` : '';
	let resultado: SyncResponseCrudo;
	try {
		resultado = await remoto.get<SyncResponseCrudo>(`/sync${query}`);
	} catch (err) {
		// La sesión reusada venció o la revocaron del otro lado: una nueva y otra vez.
		if (!(err instanceof RemoteApiError && err.status === 401)) throw err;
		olvidarSesionRemota(vinculacion);
		remoto = clienteRemoto(vinculacion.serverUrl, await sesionRemotaVigente(vinculacion, claves));
		resultado = await remoto.get<SyncResponseCrudo>(`/sync${query}`);
	}

	// F-48 (spec/13 §8): en modo `full` (default) cada recurso se replica
	// completo, igual que siempre. En `memory`/`names_only`, el pull escribe
	// SÓLO metadata local — el cuerpo del secreto nunca toca disco, se pide
	// al servidor remoto recién al revelar (`recursos.ts::verSecreto`).
	const modoPersistencia = await obtenerPersistencia();
	const soloMetadata = modoPersistencia !== 'full';

	let clavesMetadata: Map<string, Uint8Array> | undefined;

	const stats: ResultadoSync = {
		recursosNuevosOActualizados: 0,
		recursosBorrados: 0,
		recursosEnConflicto: 0,
		recursosOmitidos: 0,
		recursosSubidos: 0,
		carpetasNuevas: 0,
		carpetasBorradas: 0,
		tagsNuevos: 0,
		tagsBorrados: 0
	};

	// Cambios hechos en la app que todavía no llegaron al servidor. Se bajan
	// los del servidor primero y recién al final se suben estos: un recurso
	// que cambió en los dos lados pasa por la detección de conflictos de abajo
	// en vez de pisar la versión del servidor.
	await recogerCambiosDeExtension(email);
	const enCola = obtenerPendientes(email);

	const totalBajada = resultado.resources.length;
	for (const [i, item] of resultado.resources.entries()) {
		if (totalBajada >= UMBRAL_PROGRESO) progresoSync.set({ fase: 'bajando', hechos: i, total: totalBajada });
		if (item.deleted) {
			// Borrado allá pero editado acá sin llegar a subirse: la edición
			// local se guarda aparte antes de borrar, para no perderla.
			if (enCola[item.id] === 'subir') {
				await preservarVersionLocal(email, item.id);
				stats.recursosEnConflicto++;
			}
			quitarPendiente(email, item.id);
			await ignorarAusente(api.delete(`/resources/${item.id}`));
			olvidarSecretoEnMemoria(item.id);
			stats.recursosBorrados++;
			continue;
		}
		if (!item.secret || !item.metadata_ciphertext_b64 || !item.metadata_nonce_b64) continue; // defensivo: siempre vienen si !deleted

		// Metadata de equipo o recurso de otra persona: se adapta para poder
		// leerlo localmente (ver `adaptacion.ts`). Si no se puede, se omite.
		let cuerpo: CuerpoLocal = {
			metadata_ciphertext_b64: item.metadata_ciphertext_b64,
			metadata_nonce_b64: item.metadata_nonce_b64,
			sealed_dek_b64: item.secret.sealed_dek_b64,
			secret_ciphertext_b64: item.secret.secret_ciphertext_b64,
			secret_nonce_b64: item.secret.secret_nonce_b64
		};
		const recursoServidor = { ...item, metadata_ciphertext_b64: item.metadata_ciphertext_b64, metadata_nonce_b64: item.metadata_nonce_b64, secret: item.secret };
		if (necesitaAdaptacion(recursoServidor, userIdLocal)) {
			clavesMetadata ??= await clavesMetadataRemotas(remoto, claves);
			const adaptado = await adaptarRecurso(recursoServidor, claves, userIdLocal, clavesMetadata, !soloMetadata).catch(() => null);
			if (!adaptado) {
				stats.recursosOmitidos++;
				continue;
			}
			cuerpo = adaptado;
			marcarAdaptado(email, item.id);
		}

		const local = await ignorarAusente(api.get<{ updated_at: string; metadata_ciphertext_b64: string }>(`/resources/${item.id}`));

		// Eco de un cambio hecho en esta misma app: el push sube exactamente el
		// mismo ciphertext (con su nonce aleatorio, imposible de repetir por
		// casualidad). No hay nada que aplicar, y no es un conflicto aunque la
		// copia local sea más nueva que el cursor anterior.
		// Si estaba en la cola, el push sí llegó y sólo se perdió la respuesta.
		if (local && local.metadata_ciphertext_b64 === cuerpo.metadata_ciphertext_b64) {
			quitarPendiente(email, item.id);
			continue;
		}

		// Borrado acá sin llegar a subirse: gana el borrado. Antes ganaba el
		// servidor ("se vuelve a crear localmente"), pero que el recurso venga
		// en el delta no prueba que alguien lo editó allá: suele ser el eco de
		// lo que subió esta misma app. Bug real 2026-10-18: 137 claves borradas
		// en el escritorio con el push cortado por 429 volvían a bajar, el
		// borrado pendiente se descartaba y la recreación chocaba con la fila
		// borrada ("error interno"). El borrado lo sube `subirPendientes` al final.
		if (enCola[item.id] === 'borrar') continue;

		if (!local) {
			try {
				if (soloMetadata) {
					await api.post('/resources/metadata-only', {
						id: item.id,
						resource_type_slug: item.resource_type_slug,
						metadata_ciphertext_b64: cuerpo.metadata_ciphertext_b64,
						metadata_nonce_b64: cuerpo.metadata_nonce_b64,
						sealed_dek_b64: cuerpo.sealed_dek_b64
					});
				} else {
					await api.post('/resources', {
						id: item.id,
						resource_type_slug: item.resource_type_slug,
						metadata_ciphertext_b64: cuerpo.metadata_ciphertext_b64,
						metadata_nonce_b64: cuerpo.metadata_nonce_b64,
						sealed_dek_b64: cuerpo.sealed_dek_b64,
						secret_ciphertext_b64: cuerpo.secret_ciphertext_b64,
						secret_nonce_b64: cuerpo.secret_nonce_b64
					});
				}
			} catch (err) {
				// 409: el id existe acá pero borrado (la fila queda con
				// `deleted_at`). Se borró en esta app y el aviso al servidor se
				// perdió: mismo criterio, gana el borrado y se reintenta subirlo.
				if (!(err instanceof ApiError && err.status === 409)) throw err;
				marcarPendiente(email, item.id, 'borrar');
				continue;
			}
			stats.recursosNuevosOActualizados++;
		} else {
			// Conflicto = hay una edición hecha ACÁ que todavía no llegó al
			// servidor, y el servidor trae otra. La única fuente confiable de
			// eso es la cola de pendientes (se marca antes de intentar el push y
			// se quita al confirmarlo). Antes también se comparaba
			// `local.updated_at > cursorAnterior`, pero al BAJAR un recurso la
			// copia local nace con la hora local, siempre posterior al cursor:
			// cualquier edición hecha después en la web se tomaba como conflicto
			// y aparecían copias «(conflicto …)» sin que nadie hubiera tocado
			// nada en la app (bug real 2026-10-18).
			if (enCola[item.id] === 'subir') {
				await preservarVersionLocal(email, item.id);
				stats.recursosEnConflicto++;
			}
			// Llega otra versión del servidor: el secreto cacheado (modo
			// «sólo memoria») ya no es el vigente.
			olvidarSecretoEnMemoria(item.id);
			if (soloMetadata) {
				await api.put(
					`/resources/${item.id}/metadata-only`,
					{
						metadata_ciphertext_b64: cuerpo.metadata_ciphertext_b64,
						metadata_nonce_b64: cuerpo.metadata_nonce_b64,
						sealed_dek_b64: cuerpo.sealed_dek_b64
					},
					{ 'If-Match': local.updated_at }
				);
			} else {
				await api.put(
					`/resources/${item.id}`,
					{
						metadata_ciphertext_b64: cuerpo.metadata_ciphertext_b64,
						metadata_nonce_b64: cuerpo.metadata_nonce_b64,
						envelopes: [
							{
								// El DTO exige un UUID (`EnvelopeInputRequest.recipient_user_id`):
								// el único destinatario posible en modo escritorio es el propio
								// usuario local. Mandar el email acá fallaba con 422 en cualquier
								// pull que editara un recurso ya existente localmente.
								recipient_user_id: userIdLocal,
								sealed_dek_b64: cuerpo.sealed_dek_b64,
								secret_ciphertext_b64: cuerpo.secret_ciphertext_b64,
								secret_nonce_b64: cuerpo.secret_nonce_b64
							}
						]
					},
					{ 'If-Match': local.updated_at }
				);
			}
			stats.recursosNuevosOActualizados++;
		}

		if (item.folder_id) {
			await ignorarAusente(api.put(`/resources/${item.id}/move`, { folder_id: item.folder_id }));
		}
	}

	// Folders/tags: sólo crear (si no existe) y borrar — ver el comentario
	// de arriba del archivo, no hay endpoint de rename en todo el producto
	// todavía.
	if (resultado.folders.length > 0) {
		const arbolLocal = await api.get<{ folder_id: string }[]>('/folders');
		const idsLocales = new Set(arbolLocal.map((n) => n.folder_id));
		for (const f of resultado.folders) {
			if (f.deleted) {
				const borrado = await ignorarAusente(api.delete(`/folders/${f.folder_id}`));
				if (borrado !== null) stats.carpetasBorradas++;
				continue;
			}
			if (idsLocales.has(f.folder_id)) continue; // ya existe — un rename no se aplica, ver nota de arriba
			await api.post('/folders', {
				id: f.folder_id,
				name_ciphertext_b64: f.name_ciphertext_b64,
				name_nonce_b64: f.name_nonce_b64,
				parent_folder_id: f.parent_folder_id
			});
			stats.carpetasNuevas++;
		}
	}

	if (resultado.tags.length > 0) {
		const tagsLocales = await api.get<{ id: string }[]>('/tags');
		const idsLocales = new Set(tagsLocales.map((t) => t.id));
		for (const t of resultado.tags) {
			if (t.deleted) {
				const borrado = await ignorarAusente(api.delete(`/tags/${t.id}`));
				if (borrado !== null) stats.tagsBorrados++;
				continue;
			}
			if (idsLocales.has(t.id)) continue;
			await api.post('/tags', { id: t.id, name: t.name, is_shared: t.is_shared ?? false });
			stats.tagsNuevos++;
		}
	}

	guardarCursor(email, resultado.cursor);

	// Una vez por sesión: lo que la app tiene más nuevo que el servidor y que
	// ningún aviso puso en la cola (ver `reconciliarUnaVez`).
	if (!soloMetadata) await reconciliarUnaVez(remoto, email);

	// Lo que se creó, editó o borró en la app mientras el servidor no
	// respondía. Si vuelve a fallar no corta el sync: lo bajado ya quedó
	// aplicado y el resto sigue en la cola.
	stats.recursosSubidos = await subirPendientes(remoto, email, userIdLocal, (hechos, total) => {
		if (total >= UMBRAL_PROGRESO) progresoSync.set({ fase: 'subiendo', hechos, total });
	}).catch(() => 0);

	// Revocación remota: el primer sync exitoso fija la clave del servidor.
	await fijarIdentidadDelServidor(email, userIdLocal).catch(() => {});

	// El avatar va aparte del delta de `/sync` (ver `avatar.ts`); un fallo acá
	// no invalida lo ya aplicado, se reintenta en el próximo sync.
	await sincronizarAvatar().catch(() => false);
	await sincronizarKit().catch(() => {});
	return stats;
}
