// Autor: Athan Espinoza

// F-01/F-38: primera superficie real donde corre la cadena
// Argon2id→HKDF→AEAD dentro de un navegador de verdad — orquesta el WASM
// (`ellkan_crypto`) con las llamadas HTTP reales, la passphrase nunca sale
// de esta capa hacia el resto de la app (ni se loguea, ni cruza a Sentry
// si algún día se agrega uno).

import { cargarCrypto } from './wasm';
import { bytesABase64, base64ABytes } from './b64';
import { api } from '$lib/api/client';
import { deviceTokenHashB64 } from './device';
import type { ClavesDesbloqueadas } from '$lib/state/session';

/** AAD del blob de clave privada — fijo por usuario, mismo criterio que
 * el AAD de `secret_envelopes` (nunca variar según quién descifra). */
function aadClavePrivada(email: string): Uint8Array {
	return new TextEncoder().encode(email);
}

export async function registrar(email: string, displayName: string, passphrase: string): Promise<string> {
	const wasm = await cargarCrypto();
	const identidad = wasm.generar_identidad();
	const salt = wasm.generar_salt_kdf();
	const blob = wasm.sellar_clave_privada(
		passphrase,
		salt,
		identidad.x25519_private,
		identidad.ed25519_private,
		aadClavePrivada(email)
	);

	const resp = await api.post<{ user_id: string }>('/auth/register', {
		email,
		display_name: displayName,
		public_key_x25519_b64: bytesABase64(identidad.x25519_public),
		public_key_ed25519_b64: bytesABase64(identidad.ed25519_public),
		encrypted_private_key_blob_b64: bytesABase64(blob.ciphertext),
		private_key_nonce_b64: bytesABase64(blob.nonce),
		kdf_salt_b64: bytesABase64(salt)
	});
	return resp.user_id;
}

interface ResultadoLogin {
	estado: 'completo' | 'pendiente_dispositivo' | 'pendiente_mfa' | 'requiere_configurar_mfa';
	sessionId?: string;
	userId?: string;
	deviceChallengeId?: string;
	claves?: ClavesDesbloqueadas;
}

/**
 * F-01/F-02: key-material→abrir→challenge→firma→verify. A diferencia de la
 * CLI (que cachea el blob cifrado en un perfil local tras registrarse), un
 * navegador sin estado local lo pide en cada login vía `/auth/key-material`
 * — mismo patrón anti-enumeración que `/auth/challenge` (forma de
 * respuesta idéntica exista o no la cuenta, ver `auth::service::material_desbloqueo`).
 */
export async function iniciarSesion(email: string, passphrase: string): Promise<ResultadoLogin> {
	const wasm = await cargarCrypto();

	const material = await api.post<{
		encrypted_private_key_blob_b64: string;
		private_key_nonce_b64: string;
		kdf_salt_b64: string;
	}>('/auth/key-material', { email });

	const abierta = wasm.abrir_clave_privada(
		passphrase,
		base64ABytes(material.kdf_salt_b64),
		base64ABytes(material.private_key_nonce_b64),
		base64ABytes(material.encrypted_private_key_blob_b64),
		aadClavePrivada(email)
	);

	const challenge = await api.post<{ nonce_b64: string }>('/auth/challenge', { email });
	const nonce = base64ABytes(challenge.nonce_b64);
	const firma = wasm.firmar(abierta.ed25519_private, nonce);
	const deviceTokenHash = await deviceTokenHashB64();

	const verify = await api.post<{
		estado: string;
		session_id?: string;
		user_id?: string;
		device_challenge_id?: string;
	}>('/auth/verify', {
		email,
		nonce_b64: challenge.nonce_b64,
		signature_b64: bytesABase64(firma),
		device_token_hash_b64: deviceTokenHash
	});

	const claves: ClavesDesbloqueadas = {
		x25519Private: abierta.x25519_private,
		ed25519Private: abierta.ed25519_private,
		x25519Public: wasm.clave_publica_x25519_de(abierta.x25519_private),
		ed25519Public: wasm.clave_publica_ed25519_de(abierta.ed25519_private)
	};

	return {
		estado: verify.estado as ResultadoLogin['estado'],
		sessionId: verify.session_id,
		userId: verify.user_id,
		deviceChallengeId: verify.device_challenge_id,
		claves
	};
}

export async function verificarDispositivo(
	deviceChallengeId: string,
	codigo: string
): Promise<{ estado: string; sessionId?: string; userId?: string }> {
	const resp = await api.post<{ estado: string; session_id?: string; user_id?: string }>(
		'/auth/verify-device',
		{ device_challenge_id: deviceChallengeId, code: codigo }
	);
	return { estado: resp.estado, sessionId: resp.session_id, userId: resp.user_id };
}
