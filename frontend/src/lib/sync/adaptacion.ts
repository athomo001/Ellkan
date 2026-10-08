// Autor: Athan Espinoza

// F-47: recursos del servidor que la bóveda local no puede guardar tal cual.
//
// La bóveda local es de un solo usuario y no tiene las claves de metadata de
// la organización. Dos casos llegan del servidor y no se podrían leer acá:
//   - metadata `shared_key`: el nombre/usuario/URL están cifrados con una
//     clave de metadata del equipo (la web la usa siempre que exista una);
//   - creados por otra persona: el dato asociado (AAD) del cifrado lleva el
//     id del creador, y localmente el recurso queda a nombre del usuario local.
// Para esos se descifra con lo que corresponde del lado del servidor y se
// vuelve a cifrar con la DEK del recurso y el AAD local. El recurso queda
// marcado como "adaptado": sus cambios locales NO se suben (el servidor lo
// guarda con otro esquema, y si es compartido tiene más destinatarios que
// esta app no conoce); se editan en la web.

import { cargarCrypto } from '$lib/crypto/wasm';
import { bytesABase64, base64ABytes } from '$lib/crypto/b64';
import { uuidABytes } from '$lib/crypto/uuid';
import type { ClavesDesbloqueadas } from '$lib/state/session';

export interface RecursoDelServidor {
	id: string;
	metadata_ciphertext_b64: string;
	metadata_nonce_b64: string;
	created_by: string | null;
	metadata_key_type: 'user_key' | 'shared_key' | string | null;
	metadata_key_id: string | null;
	secret: { sealed_dek_b64: string; secret_ciphertext_b64: string; secret_nonce_b64: string };
}

export interface CuerpoLocal {
	metadata_ciphertext_b64: string;
	metadata_nonce_b64: string;
	sealed_dek_b64: string;
	secret_ciphertext_b64: string;
	secret_nonce_b64: string;
}

function aad(resourceId: string, createdBy: string): Uint8Array {
	const bytes = new Uint8Array(32);
	bytes.set(uuidABytes(resourceId), 0);
	bytes.set(uuidABytes(createdBy), 16);
	return bytes;
}

/** ¿Hay que adaptarlo para guardarlo en la bóveda local? */
export function necesitaAdaptacion(item: RecursoDelServidor, userIdLocal: string): boolean {
	return item.metadata_key_type === 'shared_key' || (!!item.created_by && item.created_by !== userIdLocal);
}

/**
 * Devuelve el recurso listo para la bóveda local (metadata y secreto con la
 * DEK del recurso y AAD `(id, usuario local)`), o `null` si no se puede.
 * `clavesMetadata`: claves de metadata del servidor ya abiertas (id → clave).
 * `conSecreto`: en los modos sin réplica del secreto (`memory`/`names_only`)
 * sólo se adapta la metadata; un recurso de OTRA persona no se puede usar en
 * esos modos (su secreto se pide al servidor y se descifra con el AAD de su
 * creador), así que devuelve `null`.
 */
export async function adaptarRecurso(
	item: RecursoDelServidor,
	claves: ClavesDesbloqueadas,
	userIdLocal: string,
	clavesMetadata: Map<string, Uint8Array>,
	conSecreto: boolean
): Promise<CuerpoLocal | null> {
	const creador = item.created_by ?? userIdLocal;
	if (!conSecreto && creador !== userIdLocal) return null;

	const wasm = await cargarCrypto();
	const dek = wasm.abrir_sellado(claves.x25519Private, base64ABytes(item.secret.sealed_dek_b64));
	const aadServidor = aad(item.id, creador);
	const aadLocal = aad(item.id, userIdLocal);

	let claveMetadata = dek;
	if (item.metadata_key_type === 'shared_key') {
		const clave = item.metadata_key_id ? clavesMetadata.get(item.metadata_key_id) : undefined;
		if (!clave) return null; // sin acceso a esa clave de metadata del equipo
		claveMetadata = clave;
	}

	const metadataPlano = wasm.descifrar_aead(
		claveMetadata,
		base64ABytes(item.metadata_nonce_b64),
		base64ABytes(item.metadata_ciphertext_b64),
		aadServidor
	);
	const metadata = wasm.cifrar_aead(dek, metadataPlano, aadLocal);

	let secreto = { ciphertext: base64ABytes(item.secret.secret_ciphertext_b64), nonce: base64ABytes(item.secret.secret_nonce_b64) };
	if (conSecreto && creador !== userIdLocal) {
		const secretoPlano = wasm.descifrar_aead(dek, secreto.nonce, secreto.ciphertext, aadServidor);
		secreto = wasm.cifrar_aead(dek, secretoPlano, aadLocal);
	}

	return {
		metadata_ciphertext_b64: bytesABase64(metadata.ciphertext),
		metadata_nonce_b64: bytesABase64(metadata.nonce),
		sealed_dek_b64: item.secret.sealed_dek_b64,
		secret_ciphertext_b64: bytesABase64(secreto.ciphertext),
		secret_nonce_b64: bytesABase64(secreto.nonce)
	};
}

// --- Registro de adaptados (por cuenta, en este dispositivo) ---

function claveRegistro(email: string): string {
	return `ellkan:sync:adaptados:${email}`;
}

function leerRegistro(email: string): Set<string> {
	try {
		return new Set(JSON.parse(localStorage.getItem(claveRegistro(email)) ?? '[]') as string[]);
	} catch {
		return new Set();
	}
}

export function marcarAdaptado(email: string, resourceId: string): void {
	const ids = leerRegistro(email);
	if (ids.has(resourceId)) return;
	ids.add(resourceId);
	try {
		localStorage.setItem(claveRegistro(email), JSON.stringify([...ids]));
	} catch {
		// Sin almacenamiento disponible: el próximo sync lo vuelve a marcar.
	}
}

export function esAdaptado(email: string | null | undefined, resourceId: string): boolean {
	return !!email && leerRegistro(email).has(resourceId);
}
