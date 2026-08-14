// Autor: Athan Espinoza

// Quick Access (spec 06 §2, WorkerName 'QuickAccess'; spec 05 §2.1) — lista,
// descifra, crea y edita recursos del usuario para el popup. Mismo criterio
// criptográfico que `frontend/src/lib/crypto/recursos.ts` (idéntico AAD,
// misma resolución `user_key`/`shared_key`, mismo resellado por destinatario
// al editar), sin la capa de caché de metadata (`$lib/cache/metadataCache`,
// Svelte-specific — spec 06 §5, "SvelteKit no es importable en un content
// script/popup sin arrastrar su runtime"). Compartir/carpetas/tags siguen
// siendo sólo de la app web — spec 06 §5bis, "Abrir en la app web" cubre eso.

import { cargarCrypto } from '../wasm';
import { bytesABase64, base64ABytes } from '../../../../frontend/src/lib/crypto/b64';
import { uuidABytes } from '../../../../frontend/src/lib/crypto/uuid';
import { SesionStorage } from '../storage/sesion-storage';

interface ErrorApi {
	error?: { code?: string; message?: string };
}

async function sesionActiva(): Promise<{ serverUrl: string; sessionId: string; userId: string; x25519Private: Uint8Array }> {
	const serverUrl = await SesionStorage.leer('server_url');
	const sessionId = await SesionStorage.leer('session_id');
	const userId = await SesionStorage.leer('user_id');
	const x25519PrivateB64 = await SesionStorage.leer('x25519_private');
	if (!serverUrl || !sessionId || !userId || !x25519PrivateB64) throw new Error('no hay una sesión activa');
	return { serverUrl, sessionId, userId, x25519Private: base64ABytes(x25519PrivateB64) };
}

async function peticion<T>(serverUrl: string, method: string, path: string, sessionId: string, body?: unknown, extraHeaders?: Record<string, string>): Promise<T> {
	const headers: Record<string, string> = { Authorization: `Bearer ${sessionId}`, ...extraHeaders };
	if (body !== undefined) headers['Content-Type'] = 'application/json';
	let resp: Response;
	try {
		resp = await fetch(`${serverUrl}${path}`, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
	} catch {
		throw new Error(`no se pudo contactar al servidor (${serverUrl}) — ¿está corriendo?`);
	}
	if (!resp.ok) {
		let mensaje = `el servidor respondió ${resp.status}`;
		try {
			const cuerpo = (await resp.json()) as ErrorApi;
			if (cuerpo.error?.message) mensaje = cuerpo.error.message;
		} catch {
			// cuerpo no era JSON — se usa el mensaje genérico de arriba
		}
		throw new Error(mensaje);
	}
	if (resp.status === 204) return undefined as T;
	return resp.json() as Promise<T>;
}

const get = <T>(serverUrl: string, path: string, sessionId: string) => peticion<T>(serverUrl, 'GET', path, sessionId);

/** Mismo AAD que `resources/service.rs`/`recursos.ts`: `resource_id ||
 * created_by` como bytes crudos de UUID (16+16), tiene que coincidir bit a
 * bit con lo que el servidor esperaba cuando el cliente que creó el recurso
 * lo cifró. */
function aadDeRecurso(resourceId: string, createdBy: string): Uint8Array {
	const aad = new Uint8Array(32);
	aad.set(uuidABytes(resourceId), 0);
	aad.set(uuidABytes(createdBy), 16);
	return aad;
}

interface RecursoCrudo {
	id: string;
	resource_type_slug: string;
	metadata_ciphertext_b64: string;
	metadata_nonce_b64: string;
	created_by: string | null;
	metadata_key_type: 'user_key' | 'shared_key';
	metadata_key_id: string | null;
	updated_at: string;
	created_at: string;
}

interface MetadataKeyCruda {
	id: string;
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

export interface SecretoRevelado {
	password: string;
	notes: string;
	totpSecret?: string;
}

export interface ItemVault {
	id: string;
	nombre: string;
	usuario: string;
	uri: string;
	resourceTypeSlug: string;
	createdBy: string;
	metadataKeyType: 'user_key' | 'shared_key';
	metadataKeyId: string | null;
	updatedAt: string;
	createdAt: string;
}

/** Datos de un formulario de crear/editar — mismo shape que
 * `frontend/src/lib/crypto/recursos.ts::NuevoRecurso`. */
export interface DatosRecurso {
	tipo?: 'login-password' | 'ssh' | 'ftp' | 'vnc' | 'telnet';
	nombre: string;
	usuario: string;
	uri: string;
	password: string;
	notas: string;
	totpSecretBase32?: string;
}

/** F-06: unsealea la clave privada de cada `metadata_key` activa a la que
 * este usuario tiene acceso — una sola llamada, reusada por `listar`
 * (lazy) y por `crear`/`editar` (siempre la necesitan para decidir
 * `user_key` vs `shared_key`). */
async function cargarClavesMetadataCompartidas(
	serverUrl: string,
	sessionId: string,
	x25519Private: Uint8Array
): Promise<Map<string, Uint8Array>> {
	const wasm = await cargarCrypto();
	const activas = await get<MetadataKeyCruda[]>(serverUrl, '/metadata-keys', sessionId);
	const mapa = new Map<string, Uint8Array>();
	for (const clave of activas) {
		if (!clave.own_sealed_private_key_b64) continue;
		mapa.set(clave.id, wasm.abrir_sellado(x25519Private, base64ABytes(clave.own_sealed_private_key_b64)));
	}
	return mapa;
}

export const VaultService = {
	async listar(): Promise<ItemVault[]> {
		const wasm = await cargarCrypto();
		const { serverUrl, sessionId, x25519Private } = await sesionActiva();

		const crudos = await get<RecursoCrudo[]>(serverUrl, '/resources', sessionId);

		// F-06: las metadata keys compartidas sólo se piden si de verdad hace
		// falta alguna — evita el roundtrip extra cuando todos los recursos
		// son `user_key` (el caso común de una cuenta sin recursos de grupo).
		let clavesMetadata: Map<string, Uint8Array> | null = null;

		const resultado: ItemVault[] = [];
		for (const r of crudos) {
			if (!r.created_by) continue;
			const aad = aadDeRecurso(r.id, r.created_by);

			let claveMetadata: Uint8Array;
			if (r.metadata_key_type === 'shared_key' && r.metadata_key_id) {
				if (!clavesMetadata) clavesMetadata = await cargarClavesMetadataCompartidas(serverUrl, sessionId, x25519Private);
				const clave = clavesMetadata.get(r.metadata_key_id);
				if (!clave) continue; // sin acceso a esta metadata key — no debería listarse, pero por las dudas no rompe el resto
				claveMetadata = clave;
			} else {
				// `user_key`: la DEK por-recurso es la misma clave que la metadata.
				const secreto = await get<SecretoCrudo>(serverUrl, `/resources/${r.id}/secret`, sessionId);
				claveMetadata = wasm.abrir_sellado(x25519Private, base64ABytes(secreto.sealed_dek_b64));
			}

			try {
				const metadataBytes = wasm.descifrar_aead(
					claveMetadata,
					base64ABytes(r.metadata_nonce_b64),
					base64ABytes(r.metadata_ciphertext_b64),
					aad
				);
				const metadata: MetadataJson = JSON.parse(new TextDecoder().decode(metadataBytes));
				resultado.push({
					id: r.id,
					nombre: metadata.name ?? '',
					usuario: metadata.username ?? '',
					uri: metadata.uri ?? '',
					resourceTypeSlug: r.resource_type_slug,
					createdBy: r.created_by,
					metadataKeyType: r.metadata_key_type,
					metadataKeyId: r.metadata_key_id,
					updatedAt: r.updated_at,
					createdAt: r.created_at
				});
			} catch {
				// Metadata que no descifra con la clave resuelta — se omite en
				// vez de romper el resto de la lista.
				continue;
			}
		}
		return resultado;
	},

	/** Mismo criterio que `frontend/src/lib/crypto/recursos.ts::verSecreto`:
	 * una sola revelación trae password+notas+TOTP juntos (misma DEK, mismo
	 * fetch) — evita 3 llamadas separadas para 3 campos que ya vienen en el
	 * mismo blob cifrado. */
	async revelarSecreto(resourceId: string): Promise<SecretoRevelado> {
		const wasm = await cargarCrypto();
		const { serverUrl, sessionId, x25519Private } = await sesionActiva();

		const recurso = await get<RecursoCrudo>(serverUrl, `/resources/${resourceId}`, sessionId);
		if (!recurso.created_by) throw new Error('recurso sin creador registrado');

		const secreto = await get<SecretoCrudo>(serverUrl, `/resources/${resourceId}/secret`, sessionId);
		const dek = wasm.abrir_sellado(x25519Private, base64ABytes(secreto.sealed_dek_b64));
		const aad = aadDeRecurso(resourceId, recurso.created_by);
		const bytes = wasm.descifrar_aead(dek, base64ABytes(secreto.secret_nonce_b64), base64ABytes(secreto.secret_ciphertext_b64), aad);
		const json: SecretoJson = JSON.parse(new TextDecoder().decode(bytes));
		return { password: json.password ?? '', notes: json.notes ?? '', totpSecret: json.totp_secret };
	},

	/** Mismo criterio que `frontend/src/lib/crypto/recursos.ts::crearRecurso`:
	 * si el usuario ya tiene acceso a alguna `metadata_key` compartida, el
	 * recurso nace `shared_key` (compartible más adelante desde la app web)
	 * — si no hay ninguna todavía, cae a `user_key` sin romper la creación. */
	async crear(datos: DatosRecurso): Promise<void> {
		const wasm = await cargarCrypto();
		const { serverUrl, sessionId, userId, x25519Private } = await sesionActiva();
		const x25519Public = wasm.clave_publica_x25519_de(x25519Private);

		const resourceId = crypto.randomUUID();
		const aad = aadDeRecurso(resourceId, userId);
		const dek = wasm.generar_dek();

		const clavesMetadata = await cargarClavesMetadataCompartidas(serverUrl, sessionId, x25519Private);
		const primeraEntrada = clavesMetadata.entries().next();
		const metadataKeyId = primeraEntrada.done ? null : primeraEntrada.value[0];
		const claveMetadata = primeraEntrada.done ? dek : primeraEntrada.value[1];

		const metadata = { name: datos.nombre, username: datos.usuario, uri: datos.uri };
		const secretoJson: SecretoJson = { password: datos.password, notes: datos.notas };
		if (datos.totpSecretBase32) secretoJson.totp_secret = datos.totpSecretBase32;

		const metadataCifrada = wasm.cifrar_aead(claveMetadata, new TextEncoder().encode(JSON.stringify(metadata)), aad);
		const secretoCifrado = wasm.cifrar_aead(dek, new TextEncoder().encode(JSON.stringify(secretoJson)), aad);
		const sealedDek = wasm.sellar_para(x25519Public, dek);

		await peticion(serverUrl, 'POST', '/resources', sessionId, {
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
	},

	/** Mismo criterio que `frontend/src/lib/crypto/recursos.ts::editarRecurso`:
	 * re-sella una DEK nueva para **todos** los destinatarios actuales (no
	 * sólo para quien edita), con concurrencia optimista real (`If-Match`
	 * sobre `updatedAt`, que el caller vio en su último `listar()`). */
	async editar(item: ItemVault, datos: DatosRecurso): Promise<{ updatedAt: string }> {
		const wasm = await cargarCrypto();
		const { serverUrl, sessionId, x25519Private } = await sesionActiva();
		const aad = aadDeRecurso(item.id, item.createdBy);
		const dek = wasm.generar_dek();

		let claveMetadata = dek;
		if (item.metadataKeyType === 'shared_key') {
			if (!item.metadataKeyId) throw new Error('Falta la clave de metadata compartida de este recurso.');
			const clavesMetadata = await cargarClavesMetadataCompartidas(serverUrl, sessionId, x25519Private);
			const clave = clavesMetadata.get(item.metadataKeyId);
			if (!clave) throw new Error('No tenés acceso a la clave de metadata compartida de este recurso.');
			claveMetadata = clave;
		}

		const metadata = { name: datos.nombre, username: datos.usuario, uri: datos.uri };
		const secretoJson: SecretoJson = { password: datos.password, notes: datos.notas };
		if (datos.totpSecretBase32) secretoJson.totp_secret = datos.totpSecretBase32;

		const metadataCifrada = wasm.cifrar_aead(claveMetadata, new TextEncoder().encode(JSON.stringify(metadata)), aad);
		const secretoCifrado = wasm.cifrar_aead(dek, new TextEncoder().encode(JSON.stringify(secretoJson)), aad);

		const destinatarios = await get<{ user_id: string; public_key_x25519_b64: string }[]>(
			serverUrl,
			`/resources/${item.id}/recipients`,
			sessionId
		);
		const envelopes = destinatarios.map((d) => ({
			recipient_user_id: d.user_id,
			sealed_dek_b64: bytesABase64(wasm.sellar_para(base64ABytes(d.public_key_x25519_b64), dek)),
			secret_ciphertext_b64: bytesABase64(secretoCifrado.ciphertext),
			secret_nonce_b64: bytesABase64(secretoCifrado.nonce)
		}));

		const actualizado = await peticion<{ updated_at: string }>(
			serverUrl,
			'PUT',
			`/resources/${item.id}`,
			sessionId,
			{
				metadata_ciphertext_b64: bytesABase64(metadataCifrada.ciphertext),
				metadata_nonce_b64: bytesABase64(metadataCifrada.nonce),
				envelopes
			},
			{ 'If-Match': item.updatedAt }
		);
		return { updatedAt: actualizado.updated_at };
	}
};
