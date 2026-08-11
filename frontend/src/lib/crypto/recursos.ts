// Autor: Athan Espinoza

// F-05/F-06/F-11: ciclo completo de un recurso contra el backend real — el
// servidor nunca ve metadata ni secreto en claro, todo el cifrado/descifrado
// pasa por acá. Dos rutas de clave de metadata (F-06):
//
// - `user_key` (personal, default): metadata y secreto comparten la misma
//   DEK por-recurso, sellada en `secret_envelopes` — ver
//   `backend/migrations/0001_fase0_core.sql`, mismo criterio que ya usa
//   `cli/src/main.rs::crear`.
// - `shared_key`: la metadata se cifra con la clave privada de la
//   `metadata_key` (bytes crudos, HKDF ya resuelto server-side en su
//   creación) — el secreto SIEMPRE sigue su propia DEK por-recurso vía
//   `secret_envelopes`, sin importar el tipo de metadata.
//
// `editarRecurso` (abajo) cubre los dos tipos: re-sella una DEK nueva para
// el secreto en el `secret_envelope` de cada destinatario actual
// (`GET .../recipients`), y re-cifra la metadata con la DEK nueva
// (`user_key`) o con la `metadata_key` compartida ya resuelta
// (`shared_key`) — nunca con la misma clave para las dos cosas.

import { cargarCrypto } from './wasm';
import { bytesABase64, base64ABytes } from './b64';
import { uuidABytes } from './uuid';
import { leerDeCache, guardarEnCache } from '$lib/cache/metadataCache';
import { api } from '$lib/api/client';
import type { ClavesDesbloqueadas } from '$lib/state/session';

function aadDeRecurso(resourceId: string, createdBy: string): Uint8Array {
	const aad = new Uint8Array(32);
	aad.set(uuidABytes(resourceId), 0);
	aad.set(uuidABytes(createdBy), 16);
	return aad;
}

interface RecursoCrudo {
	id: string;
	resource_type_id: string;
	resource_type_slug: string;
	metadata_ciphertext_b64: string;
	metadata_nonce_b64: string;
	created_by: string | null;
	created_at: string;
	updated_at: string;
	metadata_key_type: 'user_key' | 'shared_key';
	metadata_key_id: string | null;
	/** F-11: carpeta donde el usuario actual tiene posicionado este recurso
	 * en su propio árbol — `null`/ausente = raíz. Nunca cifrado, plano. */
	folder_id?: string | null;
	/** 2026-08-11: si el caller puede `DELETE` este recurso — ver
	 * `ResourceService::puede_borrar`. */
	puede_borrar?: boolean;
}

interface MetadataKeyCruda {
	id: string;
	public_key_x25519_b64: string;
	fingerprint: string;
	own_sealed_private_key_b64: string | null;
}

interface SecretoCrudo {
	sealed_dek_b64: string;
	secret_ciphertext_b64: string;
	secret_nonce_b64: string;
}

interface MetadataJson {
	name?: string;
	username?: string;
	uri?: string;
}

/**
 * Módulo 5 (spec/11): `recovery_codes`/`campos_extra` extienden el modelo sin
 * migración — el secreto ya es JSON libre cifrado client-side, agregar un
 * campo nuevo no toca el backend (`resource_types` nunca valida el
 * contenido del blob). Todavía sin productor real (la detección de backup
 * codes en la extensión de navegador es Fase 2, sin arrancar) ni consumidor
 * en el flujo de editar/crear — `crearRecurso`/`editarRecurso` reconstruyen
 * el JSON sólo con `password`/`notes`/`totp_secret`, así que un recurso con
 * estos campos poblados a mano perdería el resto al editarse; wireear el
 * round-trip completo (preservar+mostrar+editar) queda para cuando la
 * extensión exista y realmente los escriba.
 */
interface SecretoJson {
	password?: string;
	notes?: string;
	totp_secret?: string;
	recovery_codes?: string[];
	campos_extra?: Record<string, string>;
}

export interface Recurso {
	id: string;
	createdBy: string;
	nombre: string;
	usuario: string;
	uri: string;
	resourceTypeSlug: string;
	metadataKeyType: 'user_key' | 'shared_key';
	/** Sólo poblado para `user_key` — ya se necesitó para descifrar la metadata, se reusa al revelar el secreto. */
	dekPropia?: Uint8Array;
	/** Sólo poblado para `shared_key` — necesaria para re-resolver esa clave al editar. */
	metadataKeyId?: string;
	/** F-30/F-07: refresco inteligente (`huboCambios`) y valor de `If-Match` al editar. */
	updated_at: string;
	/** F-11: `null` = raíz. */
	folderId: string | null;
	/** 2026-08-11: si el caller puede `DELETE /resources/{id}` — ver
	 * `ResourceService::puede_borrar` (admin del grupo dueño de la carpeta,
	 * o `owner` fuera de una carpeta de grupo). */
	puedeBorrar: boolean;
}

/**
 * F-06: unsealea la clave privada de cada `metadata_key` activa a la que
 * este usuario tiene acceso — una sola llamada, reusada para todos los
 * recursos `shared_key` de la lista.
 */
async function cargarClavesMetadataCompartidas(claves: ClavesDesbloqueadas): Promise<Map<string, Uint8Array>> {
	const wasm = await cargarCrypto();
	const activas = await api.get<MetadataKeyCruda[]>('/metadata-keys');
	const mapa = new Map<string, Uint8Array>();
	for (const clave of activas) {
		if (!clave.own_sealed_private_key_b64) continue;
		const privada = wasm.abrir_sellado(claves.x25519Private, base64ABytes(clave.own_sealed_private_key_b64));
		mapa.set(clave.id, privada);
	}
	return mapa;
}

export async function listarRecursos(claves: ClavesDesbloqueadas): Promise<Recurso[]> {
	const wasm = await cargarCrypto();
	const crudos = await api.get<RecursoCrudo[]>('/resources');
	const clavesMetadata = await cargarClavesMetadataCompartidas(claves);

	const resultado: Recurso[] = [];
	for (const r of crudos) {
		if (!r.created_by) continue;

		// F-30 (07-frontend-web.md §4): evita re-pedir/desenvolver la DEK y
		// re-descifrar la metadata si ya se hizo en una carga anterior de
		// esta misma pestaña — `metadata_nonce_b64` como parte de la clave
		// de cache invalida sola si la metadata cambiara alguna vez.
		const enCache = await leerDeCache<{
			nombre: string;
			usuario: string;
			uri: string;
			dekPropiaB64?: string;
		}>(r.id, r.metadata_nonce_b64);
		if (enCache) {
			resultado.push({
				id: r.id,
				createdBy: r.created_by,
				nombre: enCache.nombre,
				usuario: enCache.usuario,
				uri: enCache.uri,
				resourceTypeSlug: r.resource_type_slug,
				metadataKeyType: r.metadata_key_type,
				dekPropia: enCache.dekPropiaB64 ? base64ABytes(enCache.dekPropiaB64) : undefined,
				metadataKeyId: r.metadata_key_id ?? undefined,
				updated_at: r.updated_at,
				folderId: r.folder_id ?? null,
				puedeBorrar: r.puede_borrar ?? false
			});
			continue;
		}

		const aad = aadDeRecurso(r.id, r.created_by);

		let claveMetadata: Uint8Array;
		let dekPropia: Uint8Array | undefined;
		if (r.metadata_key_type === 'shared_key' && r.metadata_key_id) {
			const clave = clavesMetadata.get(r.metadata_key_id);
			if (!clave) continue; // sin acceso a esta metadata key — no debería listarse, pero por las dudas no rompe el resto
			claveMetadata = clave;
		} else {
			// `user_key`: la DEK por-recurso es la misma clave que la metadata
			// — sólo se obtiene pidiendo el envelope propio.
			const secreto = await api.get<SecretoCrudo>(`/resources/${r.id}/secret`);
			dekPropia = wasm.abrir_sellado(claves.x25519Private, base64ABytes(secreto.sealed_dek_b64));
			claveMetadata = dekPropia;
		}

		try {
			const metadataBytes = wasm.descifrar_aead(
				claveMetadata,
				base64ABytes(r.metadata_nonce_b64),
				base64ABytes(r.metadata_ciphertext_b64),
				aad
			);
			const metadata: MetadataJson = JSON.parse(new TextDecoder().decode(metadataBytes));
			const nombre = metadata.name ?? '';
			const usuario = metadata.username ?? '';
			const uri = metadata.uri ?? '';
			resultado.push({
				id: r.id,
				createdBy: r.created_by,
				nombre,
				usuario,
				uri,
				resourceTypeSlug: r.resource_type_slug,
				metadataKeyType: r.metadata_key_type,
				dekPropia,
				metadataKeyId: r.metadata_key_id ?? undefined,
				updated_at: r.updated_at,
				folderId: r.folder_id ?? null,
				puedeBorrar: r.puede_borrar ?? false
			});
			await guardarEnCache(r.id, r.metadata_nonce_b64, {
				nombre,
				usuario,
				uri,
				dekPropiaB64: dekPropia ? bytesABase64(dekPropia) : undefined
			});
		} catch {
			// Metadata que no descifra con la clave resuelta (dato corrupto o
			// clave equivocada) — se omite en vez de romper el resto de la
			// lista; no hay forma de mostrar un nombre para esa fila igual.
			continue;
		}
	}
	return resultado;
}

const PUERTOS_DEFAULT: Record<string, number> = { ssh: 22, ftp: 21, telnet: 23, vnc: 5900 };

/** Separa `host` y `puerto` de un `uri` como los que ya guarda un recurso
 * FTP/SSH/VNC/Telnet — acepta `host`, `host:puerto` o `esquema://host:puerto`
 * (los tres formatos que ya circulan, el campo del formulario es texto
 * libre). `undefined` de puerto = usar el default del protocolo. */
function parsearHostPuerto(uri: string): { host: string; puerto?: number } {
	const sinEsquema = uri.replace(/^[a-z]+:\/\//i, '').trim();
	const idx = sinEsquema.lastIndexOf(':');
	if (idx === -1) return { host: sinEsquema };
	const resto = sinEsquema.slice(idx + 1);
	const puerto = Number(resto);
	if (!resto || !Number.isInteger(puerto)) return { host: sinEsquema };
	return { host: sinEsquema.slice(0, idx), puerto };
}

/** Protocolo + puerto resuelto (con el default aplicado) para el header de
 * conexión estilo Termius en el panel de detalle — `null` para tipos sin
 * comando de conexión asociado. */
export function infoConexion(
	recurso: Pick<Recurso, 'resourceTypeSlug' | 'uri'>
): { protocolo: string; puerto: number } | null {
	const slug = recurso.resourceTypeSlug;
	if (!recurso.uri || !(slug in PUERTOS_DEFAULT)) return null;
	const { puerto } = parsearHostPuerto(recurso.uri);
	return { protocolo: slug.toUpperCase(), puerto: puerto ?? PUERTOS_DEFAULT[slug] };
}

/** Comando/URI listo para copiar y pegar en una terminal o cliente real —
 * pedido explícito de uso real (2026-08-11): "cuando agrego un ssh o un
 * telnet, ftp debería aparecerme el comando". `null` si el tipo de recurso
 * no tiene un comando de conexión asociado (ej. login-password). */
export function comandoDeConexion(recurso: Pick<Recurso, 'resourceTypeSlug' | 'usuario' | 'uri'>): string | null {
	const slug = recurso.resourceTypeSlug;
	if (!recurso.uri || !(slug in PUERTOS_DEFAULT)) return null;
	const { host, puerto } = parsearHostPuerto(recurso.uri);
	const puertoDefault = PUERTOS_DEFAULT[slug];
	const puertoNoDefault = puerto !== undefined && puerto !== puertoDefault ? puerto : undefined;
	const arroba = recurso.usuario ? `${recurso.usuario}@` : '';

	switch (slug) {
		case 'ssh':
			return `ssh ${arroba}${host}${puertoNoDefault ? ` -p ${puertoNoDefault}` : ''}`;
		case 'telnet':
			// El comando `telnet` no toma usuario — se pide al conectar.
			return `telnet ${host}${puertoNoDefault ? ` ${puertoNoDefault}` : ''}`;
		case 'ftp':
			return `ftp://${arroba}${host}${puertoNoDefault ? `:${puertoNoDefault}` : ''}`;
		case 'vnc':
			return `vnc://${arroba}${host}${puertoNoDefault ? `:${puertoNoDefault}` : ''}`;
		default:
			return null;
	}
}

export async function verSecreto(
	recurso: Recurso,
	claves: ClavesDesbloqueadas
): Promise<{ password: string; notes: string; totpSecret?: string }> {
	const wasm = await cargarCrypto();
	const secreto = await api.get<SecretoCrudo>(`/resources/${recurso.id}/secret`);
	const dek = recurso.dekPropia ?? wasm.abrir_sellado(claves.x25519Private, base64ABytes(secreto.sealed_dek_b64));
	const aad = aadDeRecurso(recurso.id, recurso.createdBy);
	const bytes = wasm.descifrar_aead(
		dek,
		base64ABytes(secreto.secret_nonce_b64),
		base64ABytes(secreto.secret_ciphertext_b64),
		aad
	);
	const json: SecretoJson = JSON.parse(new TextDecoder().decode(bytes));
	return { password: json.password ?? '', notes: json.notes ?? '', totpSecret: json.totp_secret };
}

/** `DELETE /resources/{id}` (2026-08-11, endpoint nuevo) — ver
 * `ResourceService::eliminar` para la regla de autorización real; el
 * frontend sólo muestra el botón cuando `recurso.puedeBorrar` es `true`. */
export async function eliminarRecurso(resourceId: string): Promise<void> {
	await api.delete(`/resources/${resourceId}`);
}

/** F-07: FTP/SSH/VNC/Telnet reusan el mismo shape que login-password
 * (host:puerto en `uri`) — sólo cambia el `resource_type_slug` para
 * categorizar/mostrar un ícono distinto y armar el comando de conexión
 * copiable (`comandoDeConexion`), sin autenticación por clave SSH todavía. */
export type TipoRecurso = 'login-password' | 'ftp' | 'ssh' | 'vnc' | 'telnet';

export interface NuevoRecurso {
	/** Sólo relevante para `crearRecurso` — `editarRecurso` reusa este mismo
	 * tipo pero nunca cambia el `resource_type_id` de un recurso existente,
	 * así que ahí no hace falta pasarlo. */
	tipo?: TipoRecurso;
	nombre: string;
	usuario: string;
	uri: string;
	password: string;
	notas: string;
	totpSecretBase32?: string;
}

/**
 * Hallazgo real de uso 2026-08-10: esto creaba `user_key` siempre —
 * el botón de "Compartir" (`metadataKeyType === 'shared_key'`) nunca
 * aparecía para ningún recurso creado desde el Vault, así que nadie podía
 * compartir nada con otro usuario (sólo "Compartir externo" quedaba
 * visible). El bloqueo original ("falta un selector de usuarios en el
 * panel admin") ya no existe — F-29 (`GET /admin/users`) está desde hace
 * rato. Ahora usa la primera `metadata_key` activa a la que el usuario
 * actual ya tiene acceso (`GET /metadata-keys`, mismo lookup que ya hace
 * `editarRecurso`) si existe alguna; si no hay ninguna todavía (instancia
 * nueva sin que un admin haya creado la primera), cae a `user_key` como
 * antes — nunca rompe la creación por falta de una key.
 */
export async function crearRecurso(datos: NuevoRecurso, claves: ClavesDesbloqueadas, userId: string): Promise<void> {
	const wasm = await cargarCrypto();
	const resourceId = crypto.randomUUID();
	const aad = aadDeRecurso(resourceId, userId);
	const dek = wasm.generar_dek();

	const clavesMetadata = await cargarClavesMetadataCompartidas(claves);
	const primeraEntrada = clavesMetadata.entries().next();
	const metadataKeyId = primeraEntrada.done ? null : primeraEntrada.value[0];
	const claveMetadata = primeraEntrada.done ? dek : primeraEntrada.value[1];

	const metadata = { name: datos.nombre, username: datos.usuario, uri: datos.uri };
	const secretoJson: SecretoJson = { password: datos.password, notes: datos.notas };
	if (datos.totpSecretBase32) secretoJson.totp_secret = datos.totpSecretBase32;

	const metadataCifrada = wasm.cifrar_aead(claveMetadata, new TextEncoder().encode(JSON.stringify(metadata)), aad);
	const secretoCifrado = wasm.cifrar_aead(dek, new TextEncoder().encode(JSON.stringify(secretoJson)), aad);
	const sealedDek = wasm.sellar_para(claves.x25519Public, dek);

	await api.post('/resources', {
		id: resourceId,
		resource_type_slug:
			(datos.tipo ?? 'login-password') === 'login-password' && datos.totpSecretBase32
				? 'login-password-totp'
				: (datos.tipo ?? 'login-password'),
		metadata_ciphertext_b64: bytesABase64(metadataCifrada.ciphertext),
		metadata_nonce_b64: bytesABase64(metadataCifrada.nonce),
		sealed_dek_b64: bytesABase64(sealedDek),
		secret_ciphertext_b64: bytesABase64(secretoCifrado.ciphertext),
		secret_nonce_b64: bytesABase64(secretoCifrado.nonce),
		...(metadataKeyId ? { metadata_key_id: metadataKeyId } : {})
	});
}

/**
 * F-07: edita un recurso ya creado — re-sella una DEK nueva para **todos**
 * los destinatarios actuales (`GET .../recipients`, mismo dato que ya
 * resuelve `compartirRecurso` para uno nuevo), nunca sólo para el editor.
 * Concurrencia optimista real: `If-Match` lleva el `updated_at` que el
 * caller vio en su último `GET` — si otra edición ya corrió antes, el
 * servidor responde `409` (mapeado a `ApiError`) sin aplicar nada, y el
 * caller decide si reintenta sobre el estado nuevo.
 *
 * `shared_key`: la metadata se re-cifra con la clave simétrica de la
 * `metadata_key` compartida (`recurso.metadataKeyId`, poblada por
 * `listarRecursos`), nunca con la DEK nueva del recurso — esa DEK nueva
 * sigue siendo sólo para el secreto, igual que en un recurso `user_key`.
 */
export async function editarRecurso(
	recurso: Recurso,
	datos: NuevoRecurso,
	claves: ClavesDesbloqueadas
): Promise<Recurso> {
	const wasm = await cargarCrypto();
	const aad = aadDeRecurso(recurso.id, recurso.createdBy);
	const dek = wasm.generar_dek();

	let claveMetadata = dek;
	if (recurso.metadataKeyType === 'shared_key') {
		if (!recurso.metadataKeyId) throw new Error('Falta la clave de metadata compartida de este recurso.');
		const clavesMetadata = await cargarClavesMetadataCompartidas(claves);
		const clave = clavesMetadata.get(recurso.metadataKeyId);
		if (!clave) throw new Error('No tenés acceso a la clave de metadata compartida de este recurso.');
		claveMetadata = clave;
	}

	const metadata = { name: datos.nombre, username: datos.usuario, uri: datos.uri };
	const secretoJson: SecretoJson = { password: datos.password, notes: datos.notas };
	if (datos.totpSecretBase32) secretoJson.totp_secret = datos.totpSecretBase32;

	const metadataCifrada = wasm.cifrar_aead(claveMetadata, new TextEncoder().encode(JSON.stringify(metadata)), aad);
	const secretoCifrado = wasm.cifrar_aead(dek, new TextEncoder().encode(JSON.stringify(secretoJson)), aad);

	const destinatarios = await api.get<{ user_id: string; public_key_x25519_b64: string }[]>(
		`/resources/${recurso.id}/recipients`
	);
	const envelopes = destinatarios.map((d) => ({
		recipient_user_id: d.user_id,
		sealed_dek_b64: bytesABase64(wasm.sellar_para(base64ABytes(d.public_key_x25519_b64), dek)),
		secret_ciphertext_b64: bytesABase64(secretoCifrado.ciphertext),
		secret_nonce_b64: bytesABase64(secretoCifrado.nonce)
	}));

	const actualizado = await api.put<{ updated_at: string }>(
		`/resources/${recurso.id}`,
		{
			metadata_ciphertext_b64: bytesABase64(metadataCifrada.ciphertext),
			metadata_nonce_b64: bytesABase64(metadataCifrada.nonce),
			envelopes
		},
		{ 'If-Match': recurso.updated_at }
	);

	return {
		...recurso,
		nombre: datos.nombre,
		usuario: datos.usuario,
		uri: datos.uri,
		dekPropia: recurso.metadataKeyType === 'user_key' ? dek : recurso.dekPropia,
		updated_at: actualizado.updated_at
	};
}

/**
 * F-12: re-sella el secreto de un recurso ya compartido con un grupo para
 * un miembro nuevo — mismo criterio criptográfico que `compartirRecurso`
 * (misma DEK, nonce fresco, la metadata de un recurso `shared_key` no
 * necesita re-sellado propio porque cualquiera con la `metadata_key` ya la
 * descifra). Requiere que quien llama ya tenga su propio `secret_envelope`
 * en ese recurso — si no, falla explícito (nadie puede extender acceso a
 * un secreto que no puede leer, restricción zero-knowledge real, no un
 * bug).
 */
export async function resellarSecretoParaGrupo(
	resourceId: string,
	claves: ClavesDesbloqueadas,
	publicKeyDestinatarioB64: string
): Promise<{ resource_id: string; sealed_dek_b64: string; secret_ciphertext_b64: string; secret_nonce_b64: string }> {
	const wasm = await cargarCrypto();
	const recurso = await api.get<{ created_by: string | null }>(`/resources/${resourceId}`);
	if (!recurso.created_by) throw new Error(`recurso ${resourceId} sin created_by`);
	const aad = aadDeRecurso(resourceId, recurso.created_by);

	const secreto = await api.get<SecretoCrudo>(`/resources/${resourceId}/secret`);
	const dek = wasm.abrir_sellado(claves.x25519Private, base64ABytes(secreto.sealed_dek_b64));
	const bytes = wasm.descifrar_aead(
		dek,
		base64ABytes(secreto.secret_nonce_b64),
		base64ABytes(secreto.secret_ciphertext_b64),
		aad
	);
	const reCifrado = wasm.cifrar_aead(dek, bytes, aad);
	const sealedDek = wasm.sellar_para(base64ABytes(publicKeyDestinatarioB64), dek);

	return {
		resource_id: resourceId,
		sealed_dek_b64: bytesABase64(sealedDek),
		secret_ciphertext_b64: bytesABase64(reCifrado.ciphertext),
		secret_nonce_b64: bytesABase64(reCifrado.nonce)
	};
}

export interface DestinatarioLote {
	userId: string;
	publicKeyX25519B64: string;
}

export interface ResultadoItemLote {
	resource_id: string;
	recipient_user_id: string;
	error: string | null;
}

/**
 * Módulo 3 (compartir en lote): N recursos × M destinatarios en una sola
 * llamada de red — cada par reusa exactamente `resellarSecretoParaGrupo`
 * (mismo sellado asimétrico barato de siempre, nada nuevo del lado cripto),
 * el backend sólo agrupa el loop. Tolerante a fallos parciales: un ítem que
 * el servidor rechace (ej. sin permiso Owner sobre ese recurso puntual) no
 * aborta el resto, viene reflejado en `resultados`.
 */
export async function compartirRecursosEnLote(
	resourceIds: string[],
	destinatarios: DestinatarioLote[],
	claves: ClavesDesbloqueadas,
	level: 'read' | 'update' | 'owner' = 'read'
): Promise<ResultadoItemLote[]> {
	const items = [];
	for (const resourceId of resourceIds) {
		for (const destinatario of destinatarios) {
			const resellado = await resellarSecretoParaGrupo(resourceId, claves, destinatario.publicKeyX25519B64);
			items.push({
				resource_id: resellado.resource_id,
				recipient_user_id: destinatario.userId,
				sealed_dek_b64: resellado.sealed_dek_b64,
				secret_ciphertext_b64: resellado.secret_ciphertext_b64,
				secret_nonce_b64: resellado.secret_nonce_b64,
				level
			});
		}
	}
	const resp = await api.post<{ resultados: ResultadoItemLote[] }>('/resources/share-bulk', { items });
	return resp.resultados;
}

export interface UsuarioBusqueda {
	userId: string;
	email: string;
	displayName: string;
	publicKeyX25519B64: string;
	hasAvatar: boolean;
}

/** Buscador en vivo del modal de compartir — mínimo 2 caracteres, hasta 10 resultados. */
export async function buscarUsuarios(q: string): Promise<UsuarioBusqueda[]> {
	if (q.trim().length < 2) return [];
	const crudos = await api.get<
		{ user_id: string; email: string; display_name: string; public_key_x25519_b64: string; has_avatar: boolean }[]
	>(`/users/search?q=${encodeURIComponent(q.trim())}`);
	return crudos.map((u) => ({
		userId: u.user_id,
		email: u.email,
		displayName: u.display_name,
		publicKeyX25519B64: u.public_key_x25519_b64,
		hasAvatar: u.has_avatar
	}));
}

/**
 * F-11: funciona igual para `user_key` y `shared_key` (2026-08-11) — la DEK
 * que se resella para el destinatario acá es la misma que cifra la
 * metadata en un recurso `user_key`, así que el destinatario nuevo la
 * descifra sin problema. El backend ya no distingue por tipo.
 */
export async function compartirRecursoConDestinatario(
	recurso: Recurso,
	userId: string,
	publicKeyX25519B64: string,
	claves: ClavesDesbloqueadas,
	level: 'read' | 'update' | 'owner' = 'read'
): Promise<void> {
	const wasm = await cargarCrypto();
	const secreto = await api.get<SecretoCrudo>(`/resources/${recurso.id}/secret`);
	const dek = recurso.dekPropia ?? wasm.abrir_sellado(claves.x25519Private, base64ABytes(secreto.sealed_dek_b64));
	const aad = aadDeRecurso(recurso.id, recurso.createdBy);
	const bytes = wasm.descifrar_aead(
		dek,
		base64ABytes(secreto.secret_nonce_b64),
		base64ABytes(secreto.secret_ciphertext_b64),
		aad
	);

	// Nonce propio para el destinatario nuevo (`secret_envelopes` guarda un
	// ciphertext por fila, no reusa el nonce ajeno) — misma DEK, se vuelve a
	// cifrar el mismo plaintext con un nonce fresco.
	const reCifrado = wasm.cifrar_aead(dek, bytes, aad);
	const sealedDekDestinatario = wasm.sellar_para(base64ABytes(publicKeyX25519B64), dek);

	await api.post(`/resources/${recurso.id}/share`, {
		recipient_user_id: userId,
		sealed_dek_b64: bytesABase64(sealedDekDestinatario),
		secret_ciphertext_b64: bytesABase64(reCifrado.ciphertext),
		secret_nonce_b64: bytesABase64(reCifrado.nonce),
		level
	});
}

/** Wrapper por email — usado por el modal viejo, se mantiene por compatibilidad con `compartirRecursosEnLote`. */
export async function compartirRecurso(recurso: Recurso, emailDestinatario: string, claves: ClavesDesbloqueadas): Promise<void> {
	const destinatario = await api.get<{ user_id: string; public_key_x25519_b64: string }>(
		`/users/${encodeURIComponent(emailDestinatario)}/public-key`
	);
	await compartirRecursoConDestinatario(recurso, destinatario.user_id, destinatario.public_key_x25519_b64, claves);
}

export interface PermisoGrantee {
	granteeType: 'user' | 'group';
	granteeId: string;
	level: 'read' | 'update' | 'owner';
	/** Email (usuario) o nombre (grupo) — sólo para mostrar. */
	label: string | null;
}

/** Hallazgo real de uso: no había forma de ver/administrar quién tenía acceso a un recurso, sólo de agregar uno nuevo a ciegas. */
export async function listarPermisos(resourceId: string): Promise<PermisoGrantee[]> {
	const crudos = await api.get<{ grantee_type: string; grantee_id: string; level: string; label: string | null }[]>(
		`/resources/${resourceId}/permissions`
	);
	return crudos.map((g) => ({
		granteeType: g.grantee_type as 'user' | 'group',
		granteeId: g.grantee_id,
		level: g.level as 'read' | 'update' | 'owner',
		label: g.label
	}));
}

export async function cambiarNivelPermiso(
	resourceId: string,
	granteeType: string,
	granteeId: string,
	level: 'read' | 'update' | 'owner'
): Promise<void> {
	await api.put(`/resources/${resourceId}/permissions/${granteeType}/${granteeId}`, { level });
}

export async function revocarPermiso(resourceId: string, granteeType: string, granteeId: string): Promise<void> {
	await api.delete(`/resources/${resourceId}/permissions/${granteeType}/${granteeId}`);
}
