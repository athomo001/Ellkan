// Autor: Athan Espinoza

// Quick Access (spec 06 §2, WorkerName 'QuickAccess'; spec 05 §2.1 "qué
// falta" — hasta acá el popup sólo tenía login/logout, sin ninguna vista de
// la bóveda) — lista y descifra los recursos del usuario para el popup.
// Mismo criterio de descifrado que
// `frontend/src/lib/crypto/recursos.ts::listarRecursos`/`verSecreto`
// (idéntico AAD, misma resolución `user_key`/`shared_key`), sin la capa de
// caché de metadata (`$lib/cache/metadataCache`, Svelte-specific — spec 06
// §5, "SvelteKit no es importable en un content script/popup sin arrastrar
// su runtime") y sin las operaciones de escritura (crear/editar/compartir/
// carpetas/tags) — Quick Access es sólo lectura por ahora, ver spec/05
// sección 2.1: autofill (2.2) y el resto de la UI de escritura quedan para
// cuando esa parte de la Fase 2 se implemente.

import { cargarCrypto } from '../wasm';
import { base64ABytes } from '../../../../frontend/src/lib/crypto/b64';
import { uuidABytes } from '../../../../frontend/src/lib/crypto/uuid';
import { SesionStorage } from '../storage/sesion-storage';

interface ErrorApi {
	error?: { code?: string; message?: string };
}

async function sesionActiva(): Promise<{ serverUrl: string; sessionId: string; x25519Private: Uint8Array }> {
	const serverUrl = await SesionStorage.leer('server_url');
	const sessionId = await SesionStorage.leer('session_id');
	const x25519PrivateB64 = await SesionStorage.leer('x25519_private');
	if (!serverUrl || !sessionId || !x25519PrivateB64) throw new Error('no hay una sesión activa');
	return { serverUrl, sessionId, x25519Private: base64ABytes(x25519PrivateB64) };
}

async function get<T>(serverUrl: string, path: string, sessionId: string): Promise<T> {
	let resp: Response;
	try {
		resp = await fetch(`${serverUrl}${path}`, { headers: { Authorization: `Bearer ${sessionId}` } });
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
	return resp.json() as Promise<T>;
}

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
}

export interface ItemVault {
	id: string;
	nombre: string;
	usuario: string;
	uri: string;
	resourceTypeSlug: string;
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
				if (!clavesMetadata) {
					clavesMetadata = new Map();
					const activas = await get<MetadataKeyCruda[]>(serverUrl, '/metadata-keys', sessionId);
					for (const clave of activas) {
						if (!clave.own_sealed_private_key_b64) continue;
						clavesMetadata.set(clave.id, wasm.abrir_sellado(x25519Private, base64ABytes(clave.own_sealed_private_key_b64)));
					}
				}
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
					resourceTypeSlug: r.resource_type_slug
				});
			} catch {
				// Metadata que no descifra con la clave resuelta — se omite en
				// vez de romper el resto de la lista.
				continue;
			}
		}
		return resultado;
	},

	async revelarPassword(resourceId: string): Promise<string> {
		const wasm = await cargarCrypto();
		const { serverUrl, sessionId, x25519Private } = await sesionActiva();

		const recurso = await get<RecursoCrudo>(serverUrl, `/resources/${resourceId}`, sessionId);
		if (!recurso.created_by) throw new Error('recurso sin creador registrado');

		const secreto = await get<SecretoCrudo>(serverUrl, `/resources/${resourceId}/secret`, sessionId);
		const dek = wasm.abrir_sellado(x25519Private, base64ABytes(secreto.sealed_dek_b64));
		const aad = aadDeRecurso(resourceId, recurso.created_by);
		const bytes = wasm.descifrar_aead(dek, base64ABytes(secreto.secret_nonce_b64), base64ABytes(secreto.secret_ciphertext_b64), aad);
		const json: SecretoJson = JSON.parse(new TextDecoder().decode(bytes));
		return json.password ?? '';
	}
};
