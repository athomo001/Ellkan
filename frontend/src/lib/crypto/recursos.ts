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
	metadata_ciphertext_b64: string;
	metadata_nonce_b64: string;
	created_by: string | null;
	created_at: string;
	updated_at: string;
	metadata_key_type: 'user_key' | 'shared_key';
	metadata_key_id: string | null;
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

interface SecretoJson {
	password?: string;
	notes?: string;
	totp_secret?: string;
}

export interface Recurso {
	id: string;
	createdBy: string;
	nombre: string;
	usuario: string;
	uri: string;
	metadataKeyType: 'user_key' | 'shared_key';
	/** Sólo poblado para `user_key` — ya se necesitó para descifrar la metadata, se reusa al revelar el secreto. */
	dekPropia?: Uint8Array;
	/** Sólo poblado para `shared_key` — necesaria para re-resolver esa clave al editar. */
	metadataKeyId?: string;
	/** F-30/F-07: refresco inteligente (`huboCambios`) y valor de `If-Match` al editar. */
	updated_at: string;
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
				metadataKeyType: r.metadata_key_type,
				dekPropia: enCache.dekPropiaB64 ? base64ABytes(enCache.dekPropiaB64) : undefined,
				metadataKeyId: r.metadata_key_id ?? undefined,
				updated_at: r.updated_at
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
				metadataKeyType: r.metadata_key_type,
				dekPropia,
				metadataKeyId: r.metadata_key_id ?? undefined,
				updated_at: r.updated_at
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

export interface NuevoRecurso {
	nombre: string;
	usuario: string;
	uri: string;
	password: string;
	notas: string;
	totpSecretBase32?: string;
}

/**
 * Sólo crea recursos personales (`user_key`) — la opción de crearlo ya
 * ligado a una `metadata_key` compartida (F-06) queda para cuando el
 * panel de administración (F-20) exponga la gestión de esas claves; acá
 * alcanza con el caso simple, ya cubre el criterio de aceptación de F-05.
 */
export async function crearRecurso(datos: NuevoRecurso, claves: ClavesDesbloqueadas, userId: string): Promise<void> {
	const wasm = await cargarCrypto();
	const resourceId = crypto.randomUUID();
	const aad = aadDeRecurso(resourceId, userId);
	const dek = wasm.generar_dek();

	const metadata = { name: datos.nombre, username: datos.usuario, uri: datos.uri };
	const secretoJson: SecretoJson = { password: datos.password, notes: datos.notas };
	if (datos.totpSecretBase32) secretoJson.totp_secret = datos.totpSecretBase32;

	const metadataCifrada = wasm.cifrar_aead(dek, new TextEncoder().encode(JSON.stringify(metadata)), aad);
	const secretoCifrado = wasm.cifrar_aead(dek, new TextEncoder().encode(JSON.stringify(secretoJson)), aad);
	const sealedDek = wasm.sellar_para(claves.x25519Public, dek);

	await api.post('/resources', {
		id: resourceId,
		resource_type_slug: datos.totpSecretBase32 ? 'login-password-totp' : 'login-password',
		metadata_ciphertext_b64: bytesABase64(metadataCifrada.ciphertext),
		metadata_nonce_b64: bytesABase64(metadataCifrada.nonce),
		sealed_dek_b64: bytesABase64(sealedDek),
		secret_ciphertext_b64: bytesABase64(secretoCifrado.ciphertext),
		secret_nonce_b64: bytesABase64(secretoCifrado.nonce)
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

/**
 * F-11: sólo recursos `shared_key` son compartibles — el backend rechaza
 * `user_key` explícitamente (`METADATA_PERSONAL_NO_COMPARTIBLE`,
 * `ResourceService::compartir`) porque un destinatario nuevo no tendría
 * forma de leer la metadata (esa clave nunca se le selló a él).
 */
export async function compartirRecurso(recurso: Recurso, emailDestinatario: string, claves: ClavesDesbloqueadas): Promise<void> {
	const wasm = await cargarCrypto();
	const destinatario = await api.get<{ user_id: string; public_key_x25519_b64: string }>(
		`/users/${encodeURIComponent(emailDestinatario)}/public-key`
	);

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
	const sealedDekDestinatario = wasm.sellar_para(base64ABytes(destinatario.public_key_x25519_b64), dek);

	await api.post(`/resources/${recurso.id}/share`, {
		recipient_user_id: destinatario.user_id,
		sealed_dek_b64: bytesABase64(sealedDekDestinatario),
		secret_ciphertext_b64: bytesABase64(reCifrado.ciphertext),
		secret_nonce_b64: bytesABase64(reCifrado.nonce)
	});
}
