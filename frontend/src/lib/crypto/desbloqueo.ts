// Autor: Athan Espinoza

// QA-03: desbloqueo en dos pasos y sellado con parámetros versionados, en un
// solo lugar para todos los flujos (login, desbloqueo tras auto-bloqueo,
// cambio de passphrase, recuperación, vinculación del escritorio).
//
// Antes `/auth/key-material` entregaba el blob de la clave privada a
// cualquiera que conociera el email, para crackear la passphrase offline.
// Ahora:
//   1. `POST /auth/prelogin` → sal y parámetros de Argon2id (nada que crackear).
//   2. Argon2id en el Worker → `auth_key` + clave de envoltura (HKDF, `info`
//      distinto: conocer la primera no da la segunda).
//   3. `POST /auth/key-material` con la `auth_key` → el blob.
// Una cuenta sellada antes de QA-03 (`auth_key_required: false`) recibe el
// blob sin la prueba y se re-sella en cuanto hay sesión (`mejorarKdf`).

import { bytesABase64, base64ABytes } from './b64';
import { cargarCrypto } from './wasm';
import {
	abrirClavePrivadaEnWorker,
	derivarDesbloqueoEnWorker,
	sellarClavePrivadaEnWorker,
	type ParametrosKdf,
	type ResultadoAbrir
} from './argon2WorkerClient';

export type { ParametrosKdf };

/** Los de toda cuenta sellada antes de QA-03 (y los que asume un servidor
 * anterior que no los manda). */
export const PARAMETROS_LEGADO: ParametrosKdf = { m_cost_kib: 19456, t_cost: 2, p_cost: 1 };

/** `post` del cliente contra el que se desbloquea: el local (`api.post`) o
 * uno remoto (`clienteRemoto(...).post`). */
export type Post = <T>(ruta: string, cuerpo?: unknown) => Promise<T>;

/** Lo que devuelve `/auth/key-material`. QA-16: el servidor busca el email
 * sin distinguir mayúsculas y devuelve el que tiene guardado, que es el AAD
 * del blob: se abre con ése, no con lo que se tipeó. Un servidor anterior no
 * lo manda. */
export interface MaterialClave {
	email?: string;
	encrypted_private_key_blob_b64: string;
	private_key_nonce_b64: string;
	kdf_salt_b64: string;
	kdf_params?: ParametrosKdf;
}

interface Prelogin {
	email?: string;
	kdf_salt_b64: string;
	kdf_params: ParametrosKdf;
	auth_key_required: boolean;
}

/** La passphrase no corresponde a la cuenta (o la cuenta no existe: el
 * servidor no distingue los dos casos). Distinto de un `ApiError`, que trae
 * el mensaje real del servidor (rate limit, caída). */
export class ErrorPassphraseIncorrecta extends Error {
	constructor() {
		super('passphrase incorrecta');
	}
}

export interface Desbloqueado {
	/** El email tal como está guardado (AAD del blob). */
	email: string;
	abierta: ResultadoAbrir;
	/** `true`: cuenta sellada antes de QA-03, hay que re-sellarla. */
	legado: boolean;
}

function conStatus(e: unknown, status: number): boolean {
	return typeof e === 'object' && e !== null && 'status' in e && (e as { status: unknown }).status === status;
}

/** AAD del blob de clave privada — fijo por usuario, mismo criterio que el
 * AAD de `secret_envelopes` (nunca variar según quién descifra). */
export function aadClavePrivada(email: string): Uint8Array {
	return new TextEncoder().encode(email);
}

/** Pide el blob probando la `auth_key` y lo abre. Contra un servidor
 * anterior a QA-03 (sin `/auth/prelogin`) cae al protocolo viejo. */
export async function abrirMaterial(post: Post, email: string, passphrase: string): Promise<Desbloqueado> {
	let pre: Prelogin | undefined;
	try {
		pre = await post<Prelogin>('/auth/prelogin', { email });
	} catch (e) {
		if (!conStatus(e, 404)) throw e;
	}

	let claveEnvoltura: Uint8Array | undefined;
	let cuerpo: Record<string, string> = { email };
	if (pre) {
		const d = await derivarDesbloqueoEnWorker(passphrase, base64ABytes(pre.kdf_salt_b64), pre.kdf_params);
		claveEnvoltura = d.claveEnvoltura;
		if (pre.auth_key_required) cuerpo = { email, auth_key_b64: bytesABase64(d.authKey) };
		d.authKey.fill(0);
	}

	let material: MaterialClave;
	try {
		material = await post<MaterialClave>('/auth/key-material', cuerpo);
	} catch (e) {
		if (conStatus(e, 401)) throw new ErrorPassphraseIncorrecta();
		throw e;
	}
	if (!claveEnvoltura) {
		const d = await derivarDesbloqueoEnWorker(
			passphrase,
			base64ABytes(material.kdf_salt_b64),
			material.kdf_params ?? PARAMETROS_LEGADO
		);
		claveEnvoltura = d.claveEnvoltura;
		d.authKey.fill(0);
	}

	const emailGuardado = material.email ?? pre?.email ?? email.trim();
	try {
		const abierta = await abrirClavePrivadaEnWorker(
			claveEnvoltura,
			base64ABytes(material.private_key_nonce_b64),
			base64ABytes(material.encrypted_private_key_blob_b64),
			aadClavePrivada(emailGuardado)
		);
		return { email: emailGuardado, abierta, legado: pre ? !pre.auth_key_required : false };
	} catch {
		throw new ErrorPassphraseIncorrecta();
	} finally {
		claveEnvoltura.fill(0);
	}
}

/** Un blob recién sellado, listo para subir. */
export interface BlobClaveNueva {
	blobB64: string;
	nonceB64: string;
	saltB64: string;
	/** QA-03: parámetros de Argon2id y `auth_key` del mismo Argon2id. */
	kdfParams: ParametrosKdf;
	authKeyB64: string;
}

/** Sella las dos privadas con `passphrase`, una sal nueva y los parámetros
 * actuales de Argon2id (en el Worker). */
export async function sellarNuevo(
	passphrase: string,
	x25519Private: Uint8Array,
	ed25519Private: Uint8Array,
	email: string
): Promise<BlobClaveNueva> {
	const wasm = await cargarCrypto();
	const salt = wasm.generar_salt_kdf();
	const r = await sellarClavePrivadaEnWorker(passphrase, salt, x25519Private, ed25519Private, aadClavePrivada(email));
	const blob: BlobClaveNueva = {
		blobB64: bytesABase64(r.ciphertext),
		nonceB64: bytesABase64(r.nonce),
		saltB64: bytesABase64(salt),
		kdfParams: r.kdfParams,
		authKeyB64: bytesABase64(r.authKey)
	};
	r.authKey.fill(0);
	return blob;
}

/** Los campos de un blob nuevo tal como los esperan todos los endpoints que
 * lo guardan (registro, enrolar, cambio de passphrase, recuperación…). */
export function camposDelBlob(blob: BlobClaveNueva) {
	return {
		encrypted_private_key_blob_b64: blob.blobB64,
		private_key_nonce_b64: blob.nonceB64,
		kdf_salt_b64: blob.saltB64,
		kdf_params: blob.kdfParams,
		auth_key_b64: blob.authKeyB64
	};
}

/** QA-06: campos que el servidor exige para aceptar un blob nuevo. */
export interface PruebaDePosesion {
	challenge_nonce_b64: string;
	signature_b64: string;
}

/** QA-06: pide un challenge (`POST /auth/challenge`) y firma, con la Ed25519
 * de la cuenta, el mensaje que ata ese challenge al blob nuevo y a su
 * `auth_key` (`ellkan_crypto::clave_privada::mensaje_reemplazo_clave_privada`,
 * en WASM: nunca se arma acá). `post` es el cliente contra el que se va a
 * subir el blob (el local o uno remoto). */
export async function pruebaDePosesion(
	post: Post,
	email: string,
	ed25519Private: Uint8Array,
	blob: BlobClaveNueva
): Promise<PruebaDePosesion> {
	const wasm = await cargarCrypto();
	const desafio = await post<{ nonce_b64: string }>('/auth/challenge', { email });
	const { m_cost_kib, t_cost, p_cost } = blob.kdfParams;
	const firma = wasm.firmar_reemplazo_clave_privada(
		ed25519Private,
		base64ABytes(desafio.nonce_b64),
		base64ABytes(blob.blobB64),
		base64ABytes(blob.nonceB64),
		base64ABytes(blob.saltB64),
		m_cost_kib,
		t_cost,
		p_cost,
		base64ABytes(blob.authKeyB64)
	);
	return { challenge_nonce_b64: desafio.nonce_b64, signature_b64: bytesABase64(firma) };
}

/** QA-03: re-sella una cuenta sellada antes de QA-03 con la misma
 * passphrase y los parámetros actuales (`POST /me/kdf-upgrade`, no cierra
 * sesiones). Necesita una sesión completa en `post`. */
export async function mejorarKdf(post: Post, email: string, passphrase: string, abierta: ResultadoAbrir): Promise<void> {
	const blob = await sellarNuevo(passphrase, abierta.x25519Private, abierta.ed25519Private, email);
	const prueba = await pruebaDePosesion(post, email, abierta.ed25519Private, blob);
	await post('/me/kdf-upgrade', { ...camposDelBlob(blob), ...prueba });
}

/** QA-03: la mejora preparada durante un login (sólo entonces se tiene la
 * passphrase), para aplicarla cuando la sesión queda completa (después de
 * verificar dispositivo o el segundo factor). El blob ya va sellado: la
 * passphrase no queda en memoria. */
export interface MejoraKdfPendiente {
	email: string;
	blob: BlobClaveNueva;
}

export async function prepararMejoraKdf(d: Desbloqueado, passphrase: string): Promise<MejoraKdfPendiente | undefined> {
	if (!d.legado) return undefined;
	return { email: d.email, blob: await sellarNuevo(passphrase, d.abierta.x25519Private, d.abierta.ed25519Private, d.email) };
}

export async function aplicarMejoraKdf(post: Post, mejora: MejoraKdfPendiente, ed25519Private: Uint8Array): Promise<void> {
	const prueba = await pruebaDePosesion(post, mejora.email, ed25519Private, mejora.blob);
	await post('/me/kdf-upgrade', { ...camposDelBlob(mejora.blob), ...prueba });
}
