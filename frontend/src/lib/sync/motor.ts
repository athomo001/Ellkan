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

import { get } from 'svelte/store';
import { api, ApiError } from '$lib/api/client';
import { sesion, clavesDesbloqueadas } from '$lib/state/session';
import { cargarCrypto } from '../crypto/wasm';
import { bytesABase64, base64ABytes } from '../crypto/b64';
import { uuidABytes } from '../crypto/uuid';
import { obtenerVinculacion, obtenerCursor, guardarCursor, sesionRemotaVigente } from './vinculacion';
import { clienteRemoto } from './remoteClient';
import { obtenerPersistencia } from './persistencia';

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
	carpetasNuevas: number;
	carpetasBorradas: number;
	tagsNuevos: number;
	tagsBorrados: number;
}

async function ignorar404<T>(promesa: Promise<T>): Promise<T | null> {
	try {
		return await promesa;
	} catch (err) {
		if (err instanceof ApiError && err.status === 404) return null;
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
 * directo con la clave privada).
 */
async function copiarComoConflicto(resourceId: string): Promise<void> {
	const wasm = await cargarCrypto();
	const claves = get(clavesDesbloqueadas);
	// Sin claves desbloqueadas no hay forma de leer la metadata local para
	// renombrarla — no se pierde el dato (sigue tal cual en `resources`),
	// sólo este intento puntual de preservarlo aparte; un sync posterior
	// con la bóveda desbloqueada lo vuelve a intentar.
	if (!claves) return;

	const recurso = await ignorar404(
		api.get<{ id: string; resource_type_slug: string; metadata_ciphertext_b64: string; metadata_nonce_b64: string; created_by: string | null }>(
			`/resources/${resourceId}`
		)
	);
	if (!recurso || !recurso.created_by) return;
	const secreto = await ignorar404(
		api.get<{ sealed_dek_b64: string; secret_ciphertext_b64: string; secret_nonce_b64: string }>(`/resources/${resourceId}/secret`)
	);
	if (!secreto) return;

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
}

export async function sincronizarAhora(): Promise<ResultadoSync> {
	const email = get(sesion).email;
	const userIdLocal = get(sesion).userId;
	const claves = get(clavesDesbloqueadas);
	if (!email || !userIdLocal || !claves) throw new Error('No hay una sesión desbloqueada.');

	const vinculacion = obtenerVinculacion(email);
	if (!vinculacion) throw new Error('Esta bóveda no está conectada a ningún servidor.');

	const sessionId = await sesionRemotaVigente(vinculacion, claves);
	const remoto = clienteRemoto(vinculacion.serverUrl, sessionId);

	const cursorAnterior = obtenerCursor(email);
	const query = cursorAnterior ? `?since=${encodeURIComponent(cursorAnterior)}` : '';
	const resultado = await remoto.get<SyncResponseCrudo>(`/sync${query}`);

	// F-48 (spec/13 §8): en modo `full` (default) cada recurso se replica
	// completo, igual que siempre. En `memory`/`names_only`, el pull escribe
	// SÓLO metadata local — el cuerpo del secreto nunca toca disco, se pide
	// al servidor remoto recién al revelar (`recursos.ts::verSecreto`).
	const modoPersistencia = await obtenerPersistencia();
	const soloMetadata = modoPersistencia !== 'full';

	const stats: ResultadoSync = {
		recursosNuevosOActualizados: 0,
		recursosBorrados: 0,
		recursosEnConflicto: 0,
		carpetasNuevas: 0,
		carpetasBorradas: 0,
		tagsNuevos: 0,
		tagsBorrados: 0
	};

	for (const item of resultado.resources) {
		if (item.deleted) {
			await ignorar404(api.delete(`/resources/${item.id}`));
			stats.recursosBorrados++;
			continue;
		}
		if (!item.secret) continue; // no debería pasar (spec: secret siempre presente si !deleted), defensivo

		const local = await ignorar404(api.get<{ updated_at: string }>(`/resources/${item.id}`));

		if (!local) {
			if (soloMetadata) {
				await api.post('/resources/metadata-only', {
					id: item.id,
					resource_type_slug: item.resource_type_slug,
					metadata_ciphertext_b64: item.metadata_ciphertext_b64,
					metadata_nonce_b64: item.metadata_nonce_b64,
					sealed_dek_b64: item.secret.sealed_dek_b64
				});
			} else {
				await api.post('/resources', {
					id: item.id,
					resource_type_slug: item.resource_type_slug,
					metadata_ciphertext_b64: item.metadata_ciphertext_b64,
					metadata_nonce_b64: item.metadata_nonce_b64,
					sealed_dek_b64: item.secret.sealed_dek_b64,
					secret_ciphertext_b64: item.secret.secret_ciphertext_b64,
					secret_nonce_b64: item.secret.secret_nonce_b64
				});
			}
			stats.recursosNuevosOActualizados++;
		} else {
			// Conflicto: la copia local cambió DESPUÉS del último cursor que
			// este dispositivo ya había sincronizado con éxito — spec 13 §7,
			// primera versión simplificada (cursor único por bóveda en vez de
			// `base_updated_at` por recurso, ver `vinculacion.ts`).
			if (cursorAnterior && local.updated_at > cursorAnterior) {
				await copiarComoConflicto(item.id);
				stats.recursosEnConflicto++;
			}
			if (soloMetadata) {
				await api.put(
					`/resources/${item.id}/metadata-only`,
					{
						metadata_ciphertext_b64: item.metadata_ciphertext_b64,
						metadata_nonce_b64: item.metadata_nonce_b64,
						sealed_dek_b64: item.secret.sealed_dek_b64
					},
					{ 'If-Match': local.updated_at }
				);
			} else {
				await api.put(
					`/resources/${item.id}`,
					{
						metadata_ciphertext_b64: item.metadata_ciphertext_b64,
						metadata_nonce_b64: item.metadata_nonce_b64,
						envelopes: [
							{
								// El DTO exige un UUID (`EnvelopeInputRequest.recipient_user_id`):
								// el único destinatario posible en modo escritorio es el propio
								// usuario local. Mandar el email acá fallaba con 422 en cualquier
								// pull que editara un recurso ya existente localmente.
								recipient_user_id: userIdLocal,
								sealed_dek_b64: item.secret.sealed_dek_b64,
								secret_ciphertext_b64: item.secret.secret_ciphertext_b64,
								secret_nonce_b64: item.secret.secret_nonce_b64
							}
						]
					},
					{ 'If-Match': local.updated_at }
				);
			}
			stats.recursosNuevosOActualizados++;
		}

		if (item.folder_id) {
			await ignorar404(api.put(`/resources/${item.id}/move`, { folder_id: item.folder_id }));
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
				const borrado = await ignorar404(api.delete(`/folders/${f.folder_id}`));
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
				const borrado = await ignorar404(api.delete(`/tags/${t.id}`));
				if (borrado !== null) stats.tagsBorrados++;
				continue;
			}
			if (idsLocales.has(t.id)) continue;
			await api.post('/tags', { id: t.id, name: t.name, is_shared: t.is_shared ?? false });
			stats.tagsNuevos++;
		}
	}

	guardarCursor(email, resultado.cursor);
	return stats;
}
